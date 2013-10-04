import sys
from scapy.all import send,ICMP,IP,sr,sr1

mcast_address="10.10.10.10"
if len(sys.argv) > 1:
	mcast_address = sys.argv[1]

#p = sr1(IP(dst=mcast_address))
#print p

for i in range(0,20):
	send(IP(dst=mcast_address))
