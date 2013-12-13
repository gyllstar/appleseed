import sys
from scapy.all import send,ICMP,IP,sr,sr1,Ether

src_id = sys.argv[1]
dst_id = sys.argv[2]
rate = sys.argv[3]

dst_ip = "10.0.0.%s" %(dst_id)

wait_time = 1/float(rate)

print src_id,dst_id,rate,dst_ip,wait_time

send(IP(dst=dst_ip),loop=True,inter=wait_time)
