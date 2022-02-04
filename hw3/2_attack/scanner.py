from collections import deque
import socket
import sys

from dpkt.arp import ARP
from dpkt.ethernet import Ethernet
from dpkt.ip import IP
from dpkt.pcap import Reader
from dpkt.tcp import TCP, TH_SYN
from dpkt.udp import UDP

if len(sys.argv) != 2:
    print(f'usage: python scanner.py <trace-file>')
    sys.exit(-1)

ip2mac = {
    socket.inet_aton(ip): mac.replace(':', '') for ip, mac in [
        ('192.168.0.100', '7c:d1:c3:94:9e:b8'),
        ('192.168.0.103', 'd8:96:95:01:a5:c9'),
        ('192.168.0.1', 'f8:1a:67:cd:57:6e'),
    ]
}
arpspoofing = []
portscan = {}
synflood = {}

def check_arpspoofing(ip, i):
    if isinstance(ip, ARP):
        spa = ip.spa
        if spa in ip2mac and ip2mac[spa] != ip.sha.hex():
            arpspoofing.append({'src': ip.sha.hex(":"), 'dst': ip.tha.hex(":"), 'i': i})

def is_tcp_syn(ip):
    return isinstance(ip.data, TCP) and ip.data.flags & TH_SYN

def check_portscan(ip, i):
    if isinstance(ip, IP) and (is_tcp_syn(ip) or isinstance(ip.data, UDP)):
        dst = ip.dst
        port = ip.data.dport
        if dst not in portscan:
            portscan[dst] = [], set()
        packets, ports = portscan[dst]
        if port not in ports:
            ports.add(port)
            packets.append(str(i))

def check_synflood(ts, ip, i):
    if isinstance(ip, IP) and is_tcp_syn(ip):
        dst_port = ip.dst, ip.data.dport
        if dst_port not in synflood:
            synflood[dst_port] = deque()
        q = synflood[dst_port]
        if len(q) <= 100:
            while q and (ts - q[0]['ts'] > 1):
                q.popleft()
            q.append({'ts': ts, 'i': i})

f = open(sys.argv[1], 'rb')
reader = Reader(f)

for i, (ts, buf) in enumerate(reader):
    eth = Ethernet(buf)
    ip = eth.data
    check_arpspoofing(ip, i)
    check_portscan(ip, i)
    check_synflood(ts, ip, i)

for record in arpspoofing:
    print('ARP spoofing!')
    print(f'Src MAC: {record["src"]}')
    print(f'Dst MAC: {record["dst"]}')
    print(f'Packet number: {record["i"]}')

for dst, (packets, ports) in portscan.items():
    if len(ports) >= 100:
        print('Port scan!')
        print(f'Dst IP: {socket.inet_ntoa(dst)}')
        print(f'Packet number: {", ".join(packets)}')

for (dst, port), q in synflood.items():
    if len(q) > 100:
        print('SYN floods!')
        print(f'Dst IP: {socket.inet_ntoa(dst)}')
        print(f'Dst Port: {port}')
        print(f'Packet number: {", ".join(str(d["i"]) for d in q)}')

f.close()