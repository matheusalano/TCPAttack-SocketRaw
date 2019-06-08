import sys, socket
import pprint
from socket import AF_PACKET, SOCK_RAW
from struct import *
from src.host import Host
from src.tcpFlags import TCPFlags
from src.constants import *
from src.packer import packing_ethernet_header, packing_ip_header, packing_tcp_header


def send(source: Host, dest: Host, flags: TCPFlags):
    # Ethernet header
    eth_header = packing_ethernet_header(dest.mac, source.mac)
    # IP header
    ip_header = packing_ip_header(source, dest)

    # tcp header fields
    tcp_header = packing_tcp_header(source, dest, flags)
        
    # final full packet - syn packets dont have any data
    packet = eth_header + ip_header + tcp_header

    s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((NETWORK_INTERFACE, ETH_P_ALL))
    r = s.send(packet)
    print("Sent %d bytes" % r)

def receive(attackedMac, attackedIP, port):
    s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((NETWORK_INTERFACE, ETH_P_ALL))

    while True:
        data = s.recv(1600)
        
        if data[12:][:2] != b'\x86\xdd': #Valida se o tipo do pacote ethernet é IPv6
            continue

        attackedMac = pack('!6B', attackedMac[0], attackedMac[1], attackedMac[2], attackedMac[3], attackedMac[4], attackedMac[5])
        if data[6:][:6] != attackedMac: #Valida se o MAC de origem do pacote foi o host atacado
            continue
        
        (ver_traff_flow, payload_len, next_header, hop_limit) = unpack_from('!IHBB', data, 14) #offset de 14 bytes

        if next_header != socket.IPPROTO_TCP: #Valida se o corpo do IPv6 é um pacote TCP
            continue

        src_offset = data[22:] # data com offset de 22 (14 de ethernet + 8 de coisas do ipv6)
        src_string = socket.inet_ntop(socket.AF_INET6, src_offset[:16]) # pega os 16 bytes e converte pra string

        dst_offset = data[38:] # data com offset de 22 (14 de ethernet + 8 de coisas do ipv6 + 16 de source)
        dst_string = socket.inet_ntop(socket.AF_INET6, dst_offset[:16]) # pega os 16 bytes e converte pra string

        tcp_offset = data[54:]
        (sourcePort, destPort, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr) = unpack('!HHLLBBHHH', tcp_offset[:20])
        print(sourcePort)
        if port == sourcePort:
            return tcp_flags

