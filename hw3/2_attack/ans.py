import sys
from collections import deque

import dpkt
import binascii


def add_colons_to_mac(mac_addr):
    s = list()
    for i in range(6):  # mac_addr should always be 12 chars, we work in groups of 2 chars
        s.append(mac_addr[i * 2:i * 2 + 2])
    r = ":".join(s)
    return r


counter = 0

MAC_ADDRESSES = {
    b'\xC0\xA8\x00\x64': b'\x7C\xD1\xC3\x94\x9E\xB8',  # 192.168.0.100
    b'\xC0\xA8\x00\x67': b'\xD8\x96\x95\x01\xA5\xC9',  # 192.168.0.103
    b'\xC0\xA8\x00\x01': b'\xF8\x1A\x67\xCD\x57\x6E'  # 192.168.0.1
}

ps_list = {}
sf_list = {}
sf_report_list = list()

arp_output = ""
ps_output = ""
sf_output = ""

if len(sys.argv) != 2:
    print("Usage: python scanner.py example.pcap")

for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], 'rb')):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    if type(ip) == dpkt.arp.ARP:
        arp = eth.arp
        if arp.spa in MAC_ADDRESSES.keys() and arp.sha != MAC_ADDRESSES[arp.spa]:
            arp_output += "Arp spoofing!\nSrc MAC: " + add_colons_to_mac(binascii.hexlify(arp.sha).decode('utf-8')) \
                          + "\n" + "Dst MAC: " + add_colons_to_mac(binascii.hexlify(arp.tha).decode('utf-8')) \
                          + "\n" + "Packet number: " + str(counter) + "\n"

    if type(ip) == dpkt.ip.IP and ip.src in MAC_ADDRESSES.keys():
        b = 0
        port = 0
        if (type(ip.data) is dpkt.tcp.TCP and (ip.data.flags & dpkt.tcp.TH_SYN) != 0) or \
                (type(ip.data) == dpkt.udp.UDP):
            b = 1
            port = ip.data.dport
        if b == 0:
            counter += 1
            continue

        dst = dpkt.socket.inet_ntoa(ip.dst)
        if dst in ps_list.keys():
            exist = 0
            for record in ps_list[dst]:
                if port == record['port']:
                    exist = 1
                    break
            if exist == 0:
                ps_list[dst].append({'port': port, 'frame_num': counter})
        else:
            ps_list[dst] = [{'port': port, 'frame_num': counter}]

    # syn flood
    if type(ip) == dpkt.ip.IP and type(ip.data) is dpkt.tcp.TCP and (ip.data.flags & dpkt.tcp.TH_SYN) != 0:
        tcp = ip.data
        port = tcp.dport
        dst = dpkt.socket.inet_ntoa(ip.dst)
        dstAndPort = str(dpkt.socket.inet_ntoa(ip.dst)) + str(port)
        if dstAndPort in sf_report_list:
            counter += 1
            continue
        if dstAndPort in sf_list:
            while len(sf_list[dstAndPort]) > 0:
                first_record = sf_list[dstAndPort][0]
                if ts - first_record['ts'] >= 1:
                    sf_list[dstAndPort].popleft()
                else:
                    break

            sf_list[dstAndPort].append({'dst': dst, 'frame': counter, 'port': port, 'ts': ts})

            if len(sf_list[dstAndPort]) > 100:
                sf_report_list.append(dstAndPort)
                sf_output += "SYN floods!\nDst IP: " + dst + "\nDst Port: " + str(port) + "\nPacket number: " + \
                             str(sf_list[dstAndPort].popleft()['frame'])
                for record in sf_list[dstAndPort]:
                    if record['dst'] == dst and record['port'] == port:
                        sf_output += ", " + str(record['frame'])
                sf_output += "\n"

        else:
            sf_list[dstAndPort] = deque([{'dst': dst, 'frame': counter, 'port': port, 'ts': ts}])

    counter += 1

# print port scan result
for dst in ps_list:
    if len(ps_list[dst]) > 100:
        ps_output += "Port scan!\nDst IP: " + dst + "\n" + "Packet number: " + str(ps_list[dst].pop(0)['frame_num'])
        for p in ps_list[dst]:
            ps_output += ", " + str(p['frame_num'])
        ps_output += "\n"

print(arp_output, end="")
print(ps_output, end="")
print(sf_output, end="")
