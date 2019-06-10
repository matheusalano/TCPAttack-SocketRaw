from src.defense_sniffer.raw_socket import RawSocketDefense
from src.constants import *



def monitoring():
    sniffer = RawSocketDefense()
    
    while True:
        headers = sniffer.receive()
        eth_header  = headers[0]
        ip_header   = headers[1]
        tcp_header  = headers[2]
        
        other_host = ''
        if ip_header["src_ip"] == MY_HOST_IP == True:
            other_host = ip_header["dst_ip"]
        else:
            other_host = ip_header["src_ip"]

        ## identificar pacotes de resposta
        if ip_header["src_ip"] == MY_HOST_IP:
            print("ENVIANDO RESPOSTAS")
            flag = tcp_flag(int(tcp_header["tcp_flag"]))            
            print("FLAG", flag)


        
        ip_header["dest_ip"]

        




