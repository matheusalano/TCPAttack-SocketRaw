import socket
from struct import *
from src.host import Host
from src.tcpFlags import TCPFlags
from src.constants import *
from src.raw_socket import RawSocket

class AttackSocketManager:

    def __init__(self):
        self.raw_socket = RawSocket()
        self.raw_socket.s.settimeout(0.5)

    def send(self, source: Host, dest: Host, flags: TCPFlags, seq = 0, ack_seq = 0):
        
        self.raw_socket.send(source, dest, flags, seq, ack_seq)

    def receive(self, attackedHost: Host):

        while True:
            try:
                packet = self.raw_socket.receive()
            except socket.timeout:
                return ACK

            attackedMac = attackedHost.mac
            attackedMac = pack('!6B', attackedMac[0], attackedMac[1], attackedMac[2], attackedMac[3], attackedMac[4], attackedMac[5])

            if packet[0]['source_mac'] != attackedMac:
                continue

            if packet[1]['src_ip'] != attackedHost.ip:
                continue

            if packet[2]['src_port'] == attackedHost.port:
                return packet[2]['tcp_flag']

