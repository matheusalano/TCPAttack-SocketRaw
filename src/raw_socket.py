import socket 
import struct
from socket import AF_PACKET, SOCK_RAW
from src.host import Host
from src.tcpFlags import TCPFlags
from src.constants import *
import src.utils.unpacker as Unpacker
from src.utils.packer import packing_ethernet_header, packing_ip_header, packing_tcp_header

class RawSocket:

    def __init__(self):
        self.s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
        self.s.bind((NETWORK_INTERFACE, 0))

    def send(self, source: Host, dest: Host, flags: TCPFlags, seq, ack_seq):
        # Ethernet header
        eth_header = packing_ethernet_header(dest.mac, source.mac)
        # IP header
        ip_header = packing_ip_header(source, dest)

        # tcp header fields
        tcp_header = packing_tcp_header(source, dest, flags, seq, ack_seq)
            
        # final full packet - syn packets dont have any data
        packet = eth_header + ip_header + tcp_header

        r = self.s.send(packet)

    def receive(self):
        while True:
            # Capture packets from network
            packet = self.s.recvfrom(65565)
            # extract packets with the help of Unpacker.unpack class 
            unpack = Unpacker.unpack()

            eth_header = unpack.eth_header(packet[0][0:14])
            if eth_header['protocol'] != IPV6:
                continue

            ip_header = unpack.ip_header(packet[0][14:54])
 
            next_header = ip_header["next_header"]
            if next_header != socket.IPPROTO_TCP: #Valida se o corpo do IPv6 é um pacote TCP
                continue

            tcp_header = unpack.tcp_header(packet[0][54:74])

            return (eth_header, ip_header, tcp_header)