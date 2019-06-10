import socket 
import struct
from socket import AF_PACKET, SOCK_RAW
from src.constants import *
import src.defense_sniffer.unpacker as Unpacker

class RawSocketDefense:

    def __init__(self):
        self.s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
        self.s.bind((NETWORK_INTERFACE, 0))

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