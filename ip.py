from iputils import *
from ipaddress import ip_network, ip_address

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela = None
        self.enviar_identificacao = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            ttl -= 1
            ip_ver = 4
            ip_vhl = 5
            ip_ver = (ip_ver << 4 ) + ip_vhl
            if ttl > 0:
                datagrama = struct.pack('!BBHHHBBHII', ip_ver, dscp | ecn, len(datagrama), identification, flags | frag_offset, ttl, proto, 0, int.from_bytes(str2addr(src_addr), 'big'), int.from_bytes(str2addr(dst_addr), 'big'))
                datagrama = struct.pack('!BBHHHBBHII', ip_ver, dscp | ecn, len(datagrama), identification, flags | frag_offset, ttl, proto, calc_checksum(datagrama), int.from_bytes(str2addr(src_addr), 'big'), int.from_bytes(str2addr(dst_addr), 'big'))
                self.enlace.enviar(datagrama, next_hop)
            else:
                next_hop = self._next_hop(src_addr)
                erro = struct.pack('!BBHHHBBHII', ip_ver, dscp | ecn, 48, identification, flags | frag_offset, 64, IPPROTO_ICMP, 0, int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                erro = struct.pack('!BBHHHBBHII', ip_ver, dscp | ecn, 48, identification, flags | frag_offset, 64, IPPROTO_ICMP, calc_checksum(erro), int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(src_addr), 'big'))
                time_exceeded = struct.pack("!BBHHH", 11, 0, 0, 0, 0)
                time_exceeded = struct.pack('!BBHHH', 11, 0, calc_checksum(erro + time_exceeded), 0, 0) + datagrama[:28]
                mensagem_icmp = erro + time_exceeded
                #print(len(mensagem_icmp))
                self.enlace.enviar(mensagem_icmp, next_hop)


    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido
        ip = None
        maior_prefix = -1
        for cdr in self.tabela:
            net = ip_network(cdr[0])
            if (ip_address(dest_addr) in net) and (net.prefixlen > maior_prefix):
                maior_prefix = net.prefixlen
                ip = cdr[1]

        return ip

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela


    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        
        
        ip_ver = 4
        ip_vhl = 5
        ip_ver = (ip_ver << 4 ) + ip_vhl

        datagrama = struct.pack('!BBHHHBBHII',ip_ver, 0, len(segmento)+20, self.enviar_identificacao,0,64,6, 0,int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(dest_addr), 'big'))
        datagrama = struct.pack('!BBHHHBBHII',ip_ver, 0, len(segmento)+20, self.enviar_identificacao,0,64,6, calc_checksum(datagrama),int.from_bytes(str2addr(self.meu_endereco), 'big'), int.from_bytes(str2addr(dest_addr), 'big'))
        datagrama = datagrama + segmento
        self.enviar_identificacao += 1
        self.enlace.enviar(datagrama, next_hop)
