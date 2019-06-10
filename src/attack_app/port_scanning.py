from src.attack_app.sockets import RawSocket
from src.attack_app.host import Host
from src.attack_app.tcpFlags import TCPFlags
from threading import Thread
from enum import Enum
from src.constants import *

sourceMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48]
sourceIP = MY_HOST_IP #'fe80::a00:27ff:fe10:5248'
sourcePort = 3000

destMAC = [0x8c, 0x85, 0x90, 0x43, 0xba, 0x9f] # 8c:85:90:43:ba:9f
destIP = '2804:14d:4c84:9530:149f:ba6e:2008:5864'

class Attacks(Enum):
    TCP_CONNECT = 1
    TCP_HALF_OPENING = 2
    STEALTH_SCAN = 3
    TCP_SYN_ACK = 4

def attack(attack: Attacks, range: range):
    for port in range:
        if attack == Attacks.TCP_CONNECT:
            Thread(target=tcp_connect, args=(port,)).start()
        if attack == Attacks.TCP_HALF_OPENING:
            Thread(target=tcp_half_opening, args=(port,)).start()
        if attack == Attacks.STEALTH_SCAN:
            Thread(target=tcp_stealth_scan, args=(port,)).start()
        if attack == Attacks.TCP_SYN_ACK:
            Thread(target=tcp_syn_ack, args=(port,)).start()

def tcp_connect(port):

    socket = RawSocket()
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    syn = TCPFlags(0, 1, 0, 0, 0, 0)

    socket.send(source, dest, syn)

    received_flags = socket.receive(dest)
    if received_flags == SYNACK:
        ack = TCPFlags(0, 0, 0, 0, 1, 0)
        socket.send(source, dest, ack)
        print('PORTA {} ABERTA'.format(port))
    else:
        print('PORTA {} FECHADA'.format(port))

def tcp_half_opening(port):

    socket = RawSocket()
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    syn = TCPFlags(0, 1, 0, 0, 0, 0)

    socket.send(source, dest, syn)

    received_flags = socket.receive(dest)
    if received_flags == SYNACK:
        rst = TCPFlags(0, 0, 1, 0, 0, 0)
        socket.send(source, dest, rst)
        print('PORTA {} ABERTA'.format(port))
    else:
        print('PORTA {} FECHADA'.format(port))

def tcp_stealth_scan(port):

    socket = RawSocket()
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    fin = TCPFlags(1, 0, 0, 0, 0, 0)

    socket.send(source, dest, fin)

    received_flags = socket.receive(dest)
    if received_flags == RSTACK:
        print('PORTA {} FECHADA'.format(port))
    else:
        print('PORTA {} ABERTA'.format(port))

def tcp_syn_ack(port):

    socket = RawSocket()
    print('Ataque SYN/ACK na porta ', port)
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    syn_ack = TCPFlags(0, 1, 0, 0, 1, 0)

    socket.send(source, dest, syn_ack)

    received_flags = socket.receive(dest)
    if received_flags == RST:
        print('PORTA {} ABERTA'.format(port))
    else:
        print('PORTA {} FECHADA'.format(port))

        
