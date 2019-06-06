import src.sockets as socket
from src.host import Host
from src.tcpFlags import TCPFlags

SYN = 2
ACK = 16
SYNACK = 18
RST = 4
FIN = 1

sourceMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48]
sourceIP = 'fe80::a00:27ff:fe10:5247'
sourcePort = 1234

destMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48]
destIP = '::1'

def tcp_connect(port):

    print('Ataque TCP Connect na porta ', port)
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    syn = TCPFlags(0, 1, 0, 0, 0, 0)

    socket.send(source, dest, syn)

    received_flags = socket.receive(port)
    if received_flags == SYNACK:
        ack = TCPFlags(0, 0, 0, 0, 1, 0)
        socket.send(source, dest, ack)
    else:
        print('PORTA FECHADA')

def tcp_half_opening(port):

    print('Ataque TCP Half-Opening na porta ', port)
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    syn = TCPFlags(0, 1, 0, 0, 0, 0)

    socket.send(source, dest, syn)

    received_flags = socket.receive(port)
    if received_flags == SYNACK:
        rst = TCPFlags(0, 0, 1, 0, 0, 0)
        socket.send(source, dest, rst)
    else:
        print('PORTA FECHADA')

def tcp_stealth_scan(port):

    print('Ataque Stealth Scan na porta ', port)
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    fin = TCPFlags(1, 0, 0, 0, 0, 0)

    socket.send(source, dest, fin)

    received_flags = socket.receive(port)
    if received_flags == RST:
        print('PORTA FECHADA')
    else:
        print('PORTA ABERTA')

def tcp_syn_ack(port):

    print('Ataque SYN/ACK na porta ', port)
    source = Host(sourceMAC, sourceIP, sourcePort)
    dest = Host(destMAC, destIP, port)
    syn_ack = TCPFlags(0, 1, 0, 0, 1, 0)

    socket.send(source, dest, syn_ack)

    received_flags = socket.receive(port)
    if received_flags == RST:
        print('PORTA ABERTA')
    else:
        print('PORTA FECHADA')

        
