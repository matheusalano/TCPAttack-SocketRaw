from enum import Enum

# GLOBAL CONFIG
NETWORK_INTERFACE = "enp0s3"
ETH_P_ALL = 3
IPV6 = b'\x86\xdd'

MY_HOST_IP = '2804:389:2027:29a:a00:27ff:fe10:5248'

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