import sys, socket
import pprint
from socket import AF_PACKET, SOCK_RAW
from struct import *
from src.attack_app.host import Host
from src.attack_app.tcpFlags import TCPFlags
from src.constants import *
from src.attack_app.packer import packing_ethernet_header, packing_ip_header, packing_tcp_header

class RawSocket:

    def __init__(self):
        self.s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
        self.s.bind((NETWORK_INTERFACE, 0))
        self.s.settimeout(1.3)

    def send(self, source: Host, dest: Host, flags: TCPFlags, seq = 0, ack_seq = 0):
        # Ethernet header
        eth_header = packing_ethernet_header(dest.mac, source.mac)
        # IP header
        ip_header = packing_ip_header(source, dest)

        # tcp header fields
        tcp_header = packing_tcp_header(source, dest, flags, seq, ack_seq)
            
        # final full packet - syn packets dont have any data
        packet = eth_header + ip_header + tcp_header

        r = self.s.send(packet)

    def receive(self, attackedHost: Host):

        while True:
            try:
                data = self.s.recv(65565)
            except socket.timeout:
                return ACK
            
            if data[12:][:2] != IPV6: #Valida se o tipo do pacote ethernet é IPv6
                continue

            attackedMac = attackedHost.mac
            attackedMac = pack('!6B', attackedMac[0], attackedMac[1], attackedMac[2], attackedMac[3], attackedMac[4], attackedMac[5])
            if data[6:][:6] != attackedMac: #Valida se o MAC de origem do pacote foi o host atacado
                continue
            
            (ver_traff_flow, payload_len, next_header, hop_limit) = unpack_from('!IHBB', data, 14) #offset de 14 bytes

            if next_header != socket.IPPROTO_TCP: #Valida se o corpo do IPv6 é um pacote TCP
                continue

            src_string = socket.inet_ntop(socket.AF_INET6, data[22:][:16])

            if src_string != attackedHost.ip: #Valida se o IP é do host atacado
                continue

            tcp_offset = data[54:]
            (sourcePort, destPort, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr) = unpack('!HHLLBBHHH', tcp_offset[:20])
            
            if attackedHost.port == sourcePort:
                return tcp_flags

