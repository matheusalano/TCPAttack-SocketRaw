import sys
import src.sockets as sockets

runner_type = int(sys.argv[1])

if runner_type == 0:
    sockets.send()
else:
    sockets.receive()