import socket
from struct import *


def packing_ethernet_header(destMAC, sourceMAC):
    eth_header = pack('!6B6BH', destMAC[0], destMAC[1], destMAC[2], destMAC[3], destMAC[4], destMAC[5], sourceMAC[0], sourceMAC[1], sourceMAC[2], sourceMAC[3], sourceMAC[4], sourceMAC[5], 0x86DD)
    return eth_header


def packing_ip_header(source, dest):
    version = 6                           #4 bit
    traffic_class = 0                     #8 bit
    flow_level  = 1                       #20 bit
    payload_len = 20                      #not true lenght, I just selected a random value        #16 bit
    next_header = socket.IPPROTO_TCP      #8 bit
    hop_limit   = 255                     #8 bit
    saddr = socket.inet_pton ( socket.AF_INET6, source.ip )  #128 bit
    daddr = socket.inet_pton ( socket.AF_INET6, dest.ip   )  #128 bit

    ver_traff_flow = (version << 8) + traffic_class
    ver_traff_flow = (ver_traff_flow << 20) + flow_level

    ip_header = pack( '!IHBB', ver_traff_flow, payload_len, next_header, hop_limit)
    ip_header = ip_header + saddr + daddr
    return ip_header



def packing_tcp_header(source, dest, flags, seq, ack_seq):
    sourcePort = source.port   # source port
    destPort = dest.port   # destination port
    seq = seq
    ack_seq = ack_seq
    doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    fin = flags.fin
    syn = flags.syn
    rst = flags.rst
    psh = flags.psh
    ack = flags.ack
    urg = flags.urg
    window = socket.htons(5840)		# maximum allowed window size
    check = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , sourcePort, destPort, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)

    # pseudo header fields
    source_address = socket.inet_pton( socket.AF_INET6, source.ip )
    dest_address = socket.inet_pton( socket.AF_INET6, dest.ip )
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = source_address + dest_address + pack('!BBH' , placeholder , protocol , tcp_length)
    psh = psh + tcp_header

    tcp_checksum = _checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBHHH' , sourcePort, destPort, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
    return tcp_header


def _checksum(data):
    checksum = 0
    data_len = len(data)
    if (data_len%2) == 1:
        data_len += 1
        data += pack('!B', 0)
    
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        checksum += w

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum&0xFFFF
    return checksum