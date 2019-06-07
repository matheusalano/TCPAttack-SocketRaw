import sys
import src.sockets as sockets
import src.port_scanning as port_scanning
import src.defense_sniffer as defense_sniffer

runner_type = int(sys.argv[1])

if runner_type == 0:
    port_scanning.tcp_connect(111)
else:
    defense_sniffer.scan(list(range(25, 80)))
