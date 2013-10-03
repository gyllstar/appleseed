import sys
from scapy.all import send,ICMP,IP

mcast_address="10.10.10.10"
if len(sys.argv) > 1:
	mcast_address = sys.argv[1]

for i in range(0,20):
	send(IP(dst=mcast_address))
#send(IP(dst=sys.argv[1])/ICMP())
#send(IP(dst="10.0.0.2")/ICMP())
