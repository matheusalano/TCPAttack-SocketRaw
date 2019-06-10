import sys
import src.attack_app.port_scanning as port_scanning
from src.attack_app.port_scanning import Attacks
import src.defense_sniffer.defense_sniffer as defense_sniffer

runner_type = int(sys.argv[1])

if runner_type == 0:
    begin = input("Porta início:\n")
    end = input("Porta fim:\n")
    type = input("Ataque (1 = TCP Connect, 2 = Half-Opening, 3 = Stealth Scan, 4 = SYN/ACK):\n")
    type = Attacks(int(type))
    port_scanning.attack(type, range(int(begin), int(end) + 1))
else:
    defense_sniffer.monitoring()
