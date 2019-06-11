from src.defense_sniffer.raw_socket import RawSocketDefense
from src.constants import *
import time

tcpSynAttacks = []
attacks = []
ips = []

def monitoring():
    sniffer = RawSocketDefense()
    
    while True:
        headers = sniffer.receive()
        eth_header  = headers[0]
        ip_header   = headers[1]
        tcp_header  = headers[2]
        flag = int(tcp_header["tcp_flag"])
        if flag != SYN and flag != ACK and flag != SYNACK and flag != RST and flag != RSTACK and flag != FIN:
            continue
        
        if ip_header["src_ip"] == MY_HOST_IP:
            attackerIP = ip_header["dest_ip"]
            port = tcp_header['src_port']
            flag = tcp_flag(flag)
            if flag == tcp_flag.SYNACK or flag == tcp_flag.RSTACK:
                updateIPs(attackerIP)
                tempAttack = {'ip': attackerIP, 'flag': flag, 'port': port, 'time': time.time()}
                tcpSynAttacks.append(tempAttack)
        else:
            attackerIP = ip_header["src_ip"]
            port = tcp_header['dest_port']
            flag = tcp_flag(flag)

            if flag == tcp_flag.FIN:
                updateIPs(attackerIP)
                attack = {'ip': attackerIP, 'attack': 'fin', 'port': port, 'time': time.time()}
                attacks.append(attack)
            if flag == tcp_flag.SYNACK:
                updateIPs(attackerIP)
                attack = {'ip': attackerIP, 'attack': 'synack', 'port': port, 'time': time.time()}
                attacks.append(attack)
            if flag == tcp_flag.ACK or flag == tcp_flag.RST or flag == tcp_flag.SYN:
                updateIPs(attackerIP)
                tempAttack = {'ip': attackerIP, 'flag': flag, 'port': port, 'time': time.time()}
                tcpSynAttacks.append(tempAttack)
        
        cleanOldAttacks()
        identifyTempAttack()
        identifyAttack()

def updateIPs(ip):
    for i, aIP in enumerate(ips):
        if aIP['ip'] == ip:
            ips[i] = {'ip': ip, 'time': time.time()}
            return
    ips.append({'ip': ip, 'time': time.time()})

def identifyTempAttack():
    clean = []
    for ip in ips:
        ipPackets = list(filter(lambda x: x['ip'] == ip['ip'], tcpSynAttacks))
        for i in range(len(ipPackets)):
            if ipPackets[i]['flag'] == tcp_flag.SYN:
                for j in range(i+1, len(ipPackets)):
                    if ipPackets[j]['flag'] == tcp_flag.RSTACK and ipPackets[i]['port'] == ipPackets[j]['port']:
                        attack = {'ip': ip['ip'], 'attack': 'connectOrHalf', 'port': ipPackets[j]['port'], 'time': ipPackets[j]['time']}
                        attacks.append(attack)
                        clean.append(ip['ip'])
                    if ipPackets[j]['flag'] == tcp_flag.SYNACK and ipPackets[i]['port'] == ipPackets[j]['port']:
                        for k in range(j+1, len(ipPackets)):
                            if ipPackets[k]['flag'] == tcp_flag.ACK and ipPackets[j]['port'] == ipPackets[k]['port']:
                                attack = {'ip': ip['ip'], 'attack': 'connect', 'port': ipPackets[k]['port'], 'time': ipPackets[k]['time']}
                                attacks.append(attack)
                                clean.append(ip['ip'])
                            if ipPackets[k]['flag'] == tcp_flag.RST and ipPackets[j]['port'] == ipPackets[k]['port']:
                                attack = {'ip': ip['ip'], 'attack': 'half', 'port': ipPackets[k]['port'], 'time': ipPackets[k]['time']}
                                attacks.append(attack)
                                clean.append(ip['ip'])
    for ip in clean:
        for i, item in enumerate(tcpSynAttacks):
            if item['ip'] == ip:
                tcpSynAttacks.pop(i)

def identifyAttack():
    for ip in ips:
        lambdaConnect = lambda x: x['ip'] == ip['ip'] and x['attack'] == 'connect'
        lambdaHalf = lambda x: x['ip'] == ip['ip'] and x['attack'] == 'half'
        lambdaConnectOrHalf = lambda x: x['ip'] == ip['ip'] and x['attack'] == 'connectOrHalf'
        lambdaFin = lambda x: x['ip'] == ip['ip'] and x['attack'] == 'fin'
        lambdaSynack = lambda x: x['ip'] == ip['ip'] and x['attack'] == 'synack'
        connect = len(list(filter(lambdaConnect, attacks)))
        half = len(list(filter(lambdaHalf, attacks)))
        connectOrHalf = len(list(filter(lambdaConnectOrHalf, attacks)))
        fin = len(list(filter(lambdaFin, attacks)))
        synack = len(list(filter(lambdaSynack, attacks)))
        if connect > 3:
            print('Ataque TCP Connect de {} identificado a partir de {} ataques'.format(ip['ip'], connect))
        if half > 3:
            print('Ataque Half-Opening de {} identificado a partir de {} ataques'.format(ip['ip'], half))
        if connectOrHalf > 3:
            print('Ataque TCPConnect ou Half-Opening de {} identificado a partir de {} ataques'.format(ip['ip'], connectOrHalf))
        if fin > 3:
            print('Ataque Stealth Scan de {} identificado a partir de {} ataques'.format(ip['ip'], fin))
        if synack > 3:
            print('Ataque SYN/ACK de {} identificado a partir de {} ataques'.format(ip['ip'], synack))

def cleanOldAttacks():
    for i, item in enumerate(attacks):
            if (time.time() - item['time']) > 3:
                attacks.pop(i)
    for i, item in enumerate(tcpSynAttacks):
            if (time.time() - item['time']) > 3:
                tcpSynAttacks.pop(i)
    for i, item in enumerate(ips):
            if (time.time() - item['time']) > 3:
                ips.pop(i)
