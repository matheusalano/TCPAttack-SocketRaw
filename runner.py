import sys
import src.sockets as sockets
import src.port_scanning as port_scanning

runner_type = int(sys.argv[1])

if runner_type == 0:
    port_scanning.tcp_connect(111)
else:
    sockets.receive(111)