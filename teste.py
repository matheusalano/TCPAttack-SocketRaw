from struct import *

if __name__ == "__main__":
# tcp header fields
	source = 1234   # source port
	dest = 80   # destination port
	seq = 0
	ack_seq = 0
	 
	# the ! in the pack format string means network order
	tcp_header = pack('!HHLL' , source, dest, seq, ack_seq)
    
print(tcp_header)

(src, dst, sq, ack) = unpack('!HHLL', tcp_header)

print("O Source é: %d" % src)