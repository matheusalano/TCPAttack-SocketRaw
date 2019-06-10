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

        print ("\n[+] ------------ Ethernet Header OK----- [+]")
        # print data on terminal
        eth_header = unpack.eth_header(packet[0][0:14])
        if eth_header['protocol'] == IPV6:
            print("VALID ETHERNET PACKET IPV6")
        
        # Debug print
        # for i in eth_header.items():
        #     a,b=i
        #     print ("{} : {} | ".format(a,b))
        


        print ("\n[+] ------------ IP Header OK ------------[+]")
        ip_header = unpack.ip_header(packet[0][14:54])
        
        print("attacking ip address:", ip_header["src_ip"])
        # Debug print 
        # for i in ip_header.items():
        #     a,b=i
        #     print ("{} : {} | ".format(a,b))

        next_header = ip_header["next_header"]
        if next_header != socket.IPPROTO_TCP: #Valida se o corpo do IPv6 é um pacote TCP
            continue

        print ("\n[+] ------------ Tcp Header OK ----------- [+]")
        tcp_header = unpack.tcp_header(packet[0][54:74])

        print("tcp_flag: ",tcp_header["tcp_flag"])
        
        # Debug print
        # for  i in tcp_header.items():
        #     a,b=i
        #     print ("{} : {} | ".format(a,b))