import asyncio
from tcputils import *
from os import urandom
from sys import byteorder
import time

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, ack_no + 1)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            seq_nova = int.from_bytes(urandom(4), byteorder) # Sequencia aleatoria
            ack_no += seq_no + 1
            handshake = make_header(dst_port, src_port, seq_nova, ack_no, FLAGS_SYN + FLAGS_ACK)
            handshake = fix_checksum(handshake, dst_addr, src_addr)
            self.rede.enviar(handshake, src_addr) # Enviando handshake

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_nova, seq_ante):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_nova = seq_nova + 1
        self.seq_ante = seq_ante
        self.sendbase = seq_nova
        self.callback = None
        self.aberta = True # Se a conexao esta aberta
        self.seg_pendente = [] # Segmentos que nao tiveram confirmacao
        self.mss = 1

        #Variaveis para timer
        self.timer = None
        self.sampleRTT = None
        self.correcaoTimeoutInterval = False
        self.estimatedRTT = None
        self.devRTT = None
        self.timeoutInterval = 0.30

    def retransmissao(self):
        self.correcaoTimeoutInterval = False # Ignorando retransmissao
        dados = self.seg_pendente.pop(0)
        self.seg_pendente.insert(0, dados)
        self.servidor.rede.enviar(dados, self.id_conexao[2])
        if self.timer: # Se timer != None, existe um timer ativo, então cancelar
            self.timer.cancel()
            self.timer = None
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmissao)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.aberta:
            if (seq_no == self.seq_nova and payload):
                if (seq_no > self.sendbase) and ((flags & FLAGS_ACK) == FLAGS_ACK):
                    if len(self.seg_pendente) > 0:
                        self.seg_pendente.pop(0)
                        if self.timer: # Se timer != None, existe um timer ativo, então cancelar
                                self.timer.cancel()
                                self.timer = None
                        if len(self.seg_pendente) != 0:
                            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmissao)

                    self.timer = None
                    self.callback(self, payload)
                    self.seq_nova = self.seq_nova + len(payload)
                    self.seq_ante = ack_no

                    #print('recebido payload: %r' % payload)
                    # Enviando confirmação
                    if len(payload) > 0:
                        confirmacao = make_header(self.id_conexao[3], self.id_conexao[1], ack_no, self.seq_nova, FLAGS_ACK)
                        confirmacao = fix_checksum(confirmacao, self.id_conexao[0], self.id_conexao[2])
                        self.servidor.rede.enviar(confirmacao, self.id_conexao[2])

            else:
                if (seq_no > self.sendbase) and ((flags & FLAGS_ACK) == FLAGS_ACK):
                    if len(self.seg_pendente) > 0:
                        self.seg_pendente.pop(0)
                        if len(self.seg_pendente) == 0:
                            if self.timer:
                                self.timer.cancel()
                                self.timer = None
                        else:
                            # Enviando o resto dos segmentos pendentes
                            if self.timer:
                                self.timer.cancel()
                                self.timer = None
                            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmissao)
                self.seq_ante = ack_no

            # Fechando a conexao
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                self.callback(self, b'')
                self.seq_nova = self.seq_nova + 1
                self.seq_ante = ack_no
                fin = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_ante, self.seq_nova, FLAGS_ACK)
                fin = fix_checksum(fin, self.id_conexao[0], self.id_conexao[2])
                self.servidor.rede.enviar(fin, self.id_conexao[2])
                self.aberta = False

            if (flags & FLAGS_ACK) == FLAGS_ACK:
                # Atualizando o timeoutInterval
                alfa = 0.125
                beta = 0.25
                if self.sampleRTT != None:
                    if self.correcaoTimeoutInterval:
                        self.sampleRTT = time.time() - self.sampleRTT
                        if self.estimatedRTT == None: # Caso esteva definindo estimatedRTT e devRTT pela primeira vez
                            self.estimatedRTT = self.sampleRTT
                            self.devRTT = self.sampleRTT/2
                        else:
                            self.estimatedRTT = (1 - alfa)*self.estimatedRTT + alfa*self.sampleRTT
                            self.devRTT = (1- beta)*self.devRTT + beta*abs(self.sampleRTT-self.estimatedRTT)
                        self.timeoutInterval =  self.estimatedRTT + 4*self.devRTT
                        self.correcaoTimeoutInterval = False
                self.mss += 1

    # Os métodos abaixo fazem parte da API
    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        payloadbuff = b''
        enviado = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_ante, self.seq_nova, FLAGS_ACK)
        if len(dados) <= MSS: # Verificando se não ultrapassou o tamanho maximo
            dados = enviado + dados
        else:
            payloadbuff = dados[MSS:] # A ser enviado na proxima
            dados = enviado + dados[:MSS]
 
        
        dados = fix_checksum(dados, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(dados, self.id_conexao[2])
        self.seg_pendente.append(dados)
        self.seq_ante += len(dados) - 20
        
        self.sampleRTT = time.time()
        self.correcaoTimeoutInterval = True

        if self.timer: # Se timer != None, existe um timer ativo, então cancelar
            self.timer.cancel()
            self.timer = None
        self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self.retransmissao)


        if len(payloadbuff) != 0:
            self.enviar(payloadbuff)


    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        finseg = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_ante, self.seq_nova, FLAGS_ACK | FLAGS_FIN)
        finseg = fix_checksum(finseg, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(finseg, self.id_conexao[2])
