import sys
from scapy.all import send,ICMP,IP,sr,sr1,Ether

host_to_mcast_map = {"10.0.0.1":"10.10.10.10","10.0.0.5":"10.11.11.11","10.0.0.2":"10.12.12.12","10.0.0.3":"10.13.13.13"}
mcast_address=""
fake_ethr_address="99:99:99:99:99:99"
pkt_burst_size = 20
if len(sys.argv) > 2:
	pkt_burst_size= int(sys.argv[2])
host = sys.argv[1]
mcast_address = host_to_mcast_map[host]

#p = sr1(IP(dst=mcast_address))
#print p


for i in range(0,pkt_burst_size):
	#send(Ether(dst=fake_ethr_address)/IP(dst=mcast_address))
	send(IP(dst=mcast_address))
print "\n\n Sent %s packets from %s to multicast address = %s" %(pkt_burst_size,host,mcast_address)
