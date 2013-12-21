import sys
from scapy.all import send,ICMP,IP,sr,sr1,Ether
import time

src_id = sys.argv[1]
dst_id = sys.argv[2]
rate = sys.argv[3]

# dst_id can either be a digit (for pcount expt) or an mcast addr for backup_expt)
dst_ip = dst_id
if not "." in dst_id:
	dst_ip = "10.0.0.%s" %(dst_id)

wait_time = 1/float(rate)

print src_id,dst_id,rate,dst_ip,wait_time

#start_time = time.clock()
#print start_time
send(IP(dst=dst_ip),loop=True,inter=wait_time)
#end_time = time.clock()
#print end_time

#print end_time - start_time
#send(IP(dst=dst_ip),inter=wait_time)
