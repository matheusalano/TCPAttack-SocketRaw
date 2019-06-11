from enum import Enum

# GLOBAL CONFIG
NETWORK_INTERFACE = "enp0s3"
ETH_P_ALL = 3
IPV6 = b'\x86\xdd'

MY_HOST_MAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48]
MY_HOST_IP = '2804:14d:4c84:9530:a00:27ff:fe10:5248'
SOURCE_PORT = 3000

ATTACKED_MAC = [0x8c, 0x85, 0x90, 0x43, 0xba, 0x9f]
ATTACKED_IP = '2804:388:e04a:4bc3:21:f204:c940:4cd6'


# TCP FLAGS
SYN = 2
ACK = 16
SYNACK = 18
RST = 4
RSTACK = 20
FIN = 1

class tcp_flag(Enum):
    SYN = 2
    ACK = 16
    SYNACK = 18
    RST = 4
    RSTACK = 20
    FIN = 1