# How to run my code

Run `python scanner.py <trace-file>`.

# Detect ARP Spoofing attempts

For ARP packets, if it knows the sender IP address, it checks if the sender MAC address matches the correct MAC address. If not, it reports ARP spoofing.

# Detect Port Scans

It tracks unique port numbers and corresponding TCP SYN or UDP packet numbers for every IP address. Then, it reports any IP addresses that receive packages on at least 100 different ports.

# Detect TCP SYN floods

It uses a queue to store all the TCP SYN packet sent in the last second. If there are more than 100 such packages, then it reports SYN flood.
