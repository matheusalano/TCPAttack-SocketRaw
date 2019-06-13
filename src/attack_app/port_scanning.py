from src.attack_app.attackSocketManager import AttackSocketManager
from src.host import Host
from src.tcpFlags import TCPFlags
from threading import Thread
from enum import Enum
from src.constants import *

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
    socket = AttackSocketManager()
    source = Host(MY_HOST_MAC, MY_HOST_IP, SOURCE_PORT)
    dest = Host(ATTACKED_MAC, ATTACKED_IP, port)
    syn = TCPFlags(0, 1, 0, 0, 0, 0)

    socket.send(source, dest, syn)

    received_flags = socket.receive(dest)
    if received_flags == SYNACK:
        ack = TCPFlags(0, 0, 0, 0, 1, 0)
        socket.send(source, dest, ack, 1, 1)
        print('PORTA {} ABERTA'.format(port))
    else:
        print('PORTA {} FECHADA'.format(port))

def tcp_half_opening(port):
    socket = AttackSocketManager()
    source = Host(MY_HOST_MAC, MY_HOST_IP, SOURCE_PORT)
    dest = Host(ATTACKED_MAC, ATTACKED_IP, port)
    syn = TCPFlags(0, 1, 0, 0, 0, 0)

    socket.send(source, dest, syn)

    received_flags = socket.receive(dest)
    if received_flags == SYNACK:
        rst = TCPFlags(0, 0, 1, 0, 0, 0)
        socket.send(source, dest, rst, 1)
        print('PORTA {} ABERTA'.format(port))
    else:
        print('PORTA {} FECHADA'.format(port))

def tcp_stealth_scan(port):
    socket = AttackSocketManager()
    source = Host(MY_HOST_MAC, MY_HOST_IP, SOURCE_PORT)
    dest = Host(ATTACKED_MAC, ATTACKED_IP, port)
    fin = TCPFlags(1, 0, 0, 0, 0, 0)

    socket.send(source, dest, fin)

    received_flags = socket.receive(dest)
    if received_flags == RSTACK:
        print('PORTA {} FECHADA'.format(port))
    else:
        print('PORTA {} ABERTA'.format(port))

def tcp_syn_ack(port):
    socket = AttackSocketManager()
    source = Host(MY_HOST_MAC, MY_HOST_IP, SOURCE_PORT)
    dest = Host(ATTACKED_MAC, ATTACKED_IP, port)
    syn_ack = TCPFlags(0, 1, 0, 0, 1, 0)

    socket.send(source, dest, syn_ack)

    received_flags = socket.receive(dest)
    if received_flags == RST:
        print('PORTA {} ABERTA'.format(port))
    else:
        print('PORTA {} FECHADA'.format(port))

        
