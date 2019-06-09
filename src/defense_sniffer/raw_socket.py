import socket 
import struct
from socket import AF_PACKET, SOCK_RAW
from src.constants import *
import src.defense_sniffer.unpacker as Unpacker

def start_socket():
    s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((NETWORK_INTERFACE, 0))

    while True:

        # Capture packets from network
        packet = s.recvfrom(65565)
        print ("\n[+] ------------ NEW PACKET----- [+]")
        # extract packets with the help of Unpacker.unpack class 
        unpack = Unpacker.unpack()

        print ("\n[+] ------------ Ethernet Header----- [+]")
        # print data on terminal
        for i in unpack.eth_header(packet[0][0:14]).items():
            a,b=i
            print ("{} : {} | ".format(a,b))


        print ("\n[+] ------------ IP Header ------------[+]")
        for i in unpack.ip_header(packet[0][14:54]).items():
            a,b=i
            print ("{} : {} | ".format(a,b))

        print ("\n[+] ------------ Tcp Header ----------- [+]")
        for  i in unpack.tcp_header(packet[0][54:73]).items():
            a,b=i
            print ("{} : {} | ".format(a,b))