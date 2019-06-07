import sys
import pprint
from socket import AF_PACKET, SOCK_RAW, socket
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
    s.bind((NETWORK_INTERFACE, 0))
    r = s.send(packet)
    print("Sent %d bytes" % r)

def receive(port):
    s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((NETWORK_INTERFACE, 0))

    while True:
        (data, src_addr) = s.recvfrom(1600)
        
        (ver_traff_flow, payload_len, next_header, hop_limit) = unpack_from('!IHBB', data, 14) #offset de 14 bytes

        src_offset = data[22:] # data com offset de 22 (14 de ethernet + 8 de coisas do ipv6)
        src_string = socket.inet_ntop(socket.AF_INET6, src_offset[:16]) # pega os 16 bytes e converte pra string

        dst_offset = data[38:] # data com offset de 22 (14 de ethernet + 8 de coisas do ipv6 + 16 de source)
        dst_string = socket.inet_ntop(socket.AF_INET6, dst_offset[:16]) # pega os 16 bytes e converte pra string

        tcp_offset = data[54:]
        (sourcePort, destPort, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr) = unpack('!HHLLBBHHH', tcp_offset)

        if port == sourcePort:
            return tcp_flags

