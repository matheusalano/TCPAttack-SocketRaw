import sys
import src.sockets as sockets
from src.host import Host
from src.tcpFlags import TCPFlags

runner_type = int(sys.argv[1])

sourceMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48] #08:00:27:10:52:48
sourceIP = 'fe80::a00:27ff:fe10:5247'
sourcePort = 1234

destMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48]
destIP = '::1'
destPort = 80

fin = 0
syn = 1
rst = 0
psh = 0
ack = 0
urg = 0

source = Host(sourceMAC, sourceIP, sourcePort)
dest = Host(destMAC, destIP, destPort)
flags = TCPFlags(fin, syn, rst, psh, ack, urg)

if runner_type == 0:
    sockets.send(source, dest, flags)
else:
    sockets.receive()