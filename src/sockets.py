import socket, sys
import pprint
from socket import AF_PACKET, SOCK_RAW
from struct import *

interface = "lo"
ETH_P_ALL = 3

sourceMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48] #08:00:27:10:52:48
sourceIP = 'fe80::a00:27ff:fe10:5247'
sourcePort = 1234

destMAC = [0x08, 0x00, 0x27, 0x10, 0x52, 0x48]
destIP = '::1'
destPort = 80

def checksum(data):
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

def send():
    # Ethernet header
    eth_header = pack('!6B6BH', destMAC[0], destMAC[1], destMAC[2], destMAC[3], destMAC[4], destMAC[5], sourceMAC[0], sourceMAC[1], sourceMAC[2], sourceMAC[3], sourceMAC[4], sourceMAC[5], 0x86DD)

    # IP header
    version = 6                           #4 bit
    traffic_class = 0                     #8 bit
    flow_level  = 1                       #20 bit
    payload_len = 20 #not true lenght, I just selected a random value        #16 bit
    next_header = socket.IPPROTO_TCP      #8 bit
    hop_limit   = 255                     #8 bit
    saddr = socket.inet_pton ( socket.AF_INET6, sourceIP )  #128 bit
    daddr = socket.inet_pton ( socket.AF_INET6, destIP   )  #128 bit

    ver_traff_flow = (version << 8) + traffic_class
    ver_traff_flow = (ver_traff_flow << 20) + flow_level

    ip_header = pack( '!IHBB', ver_traff_flow, payload_len, next_header, hop_limit)
    ip_header = ip_header + saddr + daddr

    # tcp header fields
    source = sourcePort   # source port
    dest = destPort   # destination port
    seq = 0
    ack_seq = 0
    doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons(5840)		# maximum allowed window size
    check = 0
    urg_ptr = 0
        
    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
        
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
        
    # pseudo header fields
    source_address = socket.inet_pton( socket.AF_INET6, sourceIP )
    dest_address = socket.inet_pton( socket.AF_INET6, destIP )
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
        
    psh = source_address + dest_address + pack('!BBH' , placeholder , protocol , tcp_length)
    psh = psh + tcp_header
        
    tcp_checksum = checksum(psh)
        
    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
        
    # final full packet - syn packets dont have any data
    packet = eth_header + ip_header + tcp_header

    s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((interface, 0))
    r = s.send(packet)
    print("Sent %d bytes" % r)

def receive():
    s = socket.socket(AF_PACKET, SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((interface, 0))
    print('Entrou receive')

    while True:
        data, src_addr = s.recvfrom(1600)
        print('recebeu data')
        #ip_data = data << 14
        (ver_traff_flow, payload_len, next_header, hop_limit) = unpack_from('!IHBB', data, 14)
        
        src = data[0] << 18
        print(payload_len)
        return
        src_string = socket.inet_ntop(socket.AF_INET6, src[:16])

        dst = data[0] << 34
        dst_string = socket.inet_ntop(socket.AF_INET6, dst[:16])

        print('source: ', src_string)
        print('destination: ', dst_string)


        

