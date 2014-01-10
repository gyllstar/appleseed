"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import CPULimitedHost,RemoteController,OVSSwitch
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from argparse import ArgumentParser
import graph_generator
from graph_generator import IeeeMininetTopo
import os
from itertools import izip
import sys
import signal
import time
import subprocess
from subprocess import Popen
import csv

ieee_graphs_folder = "ieee-buses/"
ieee_base_file_name = "ieee"
ieee_file_type = "txt"
controller_pid=-1


def pairwise(iterable):
	a = iter(iterable)
	return izip(a,a)

def staticArp( net ):
	""" Add all-pairs ARP enries + those for special multicast addresses.  This helps avoid the broadcast ARP requests. """
	for src in net.hosts:
		for dst in net.hosts:
			if src != dst:
#				print "%s adding (%s,%s)" %(src,dst.IP(),dst.MAC)
				src.setARP(ip=dst.IP(), mac = dst.MAC())	

	for switch in net.switches:
		for dst in net.hosts:
			switch.setARP(ip=dst.IP(), mac = dst.MAC())	

def kill_controller():
	kill_cmd = "sudo kill -9 %s" %(controller_pid) 
	os.system(kill_cmd)
	sys.exit(0)	


def compute_mcast_addr(root_id):
	""" Takes node_id and makes IP address - 10.node_id.node_id.node_id.  Example, node_id = 13 yields 10.13.13.13 """
	mcast_addr = "10.%s.%s.%s" %(root_id,root_id,root_id)
	return mcast_addr

def signal_handler(signal,frame):
	print "Ctrl+C pressed.  Killing controller process, then exiting."
	kill_cmd = "sudo kill -9 %s" %(controller_pid) 
	os.system(kill_cmd)
	sys.exit(0)	

signal.signal(signal.SIGINT, signal_handler)


parser = ArgumentParser(description="generates IEEE topology, creates a corresponding mininet network, generates multicast groups, and installs backup trees.") 

parser.add_argument("--topo", dest="topo_num",type=int,help="IEEE topology number (i.e, 14,30,57,118) link",default=14)
parser.add_argument("--num-groups", dest="num_groups",type=int,help="number of multicast groups",default=1)
parser.add_argument("--bak-mode", dest="bak_mode",type=str,help="backup mode (proactive or reactive)",default='reactive')
parser.add_argument("--opt", dest="opt",type=str,help="optimization mode (basic or merger)",default='basic')
parser.add_argument("--log", dest="log",type=bool,help="turn logging on at controller. ",default=False)

args = parser.parse_args()

if args.log:
	print "\n---------------------------------------------------- "
	print "first a quick cleanup: running `mn -c' \n"
	os.system("mn -c")
	print "---------------------------------------------------- \n\n"

	print "parsed command line arguments: %s" %(args)



ieee_file_str = "%s%s%s.%s" %(ieee_graphs_folder,ieee_base_file_name,args.topo_num,ieee_file_type)
#ieee_mn_graph,mcast_groups = graph_generator.gen_graph_and_mcast_groups(ieee_file_str,num_groups=args.num_groups)
ieee_mn_graph = graph_generator.gen_graph(ieee_file_str)


#setLogLevel('debug')


# (2) start the appleseed controller
if args.log: print "\n starting appleseed controller as Remote Controller"
sys.path.append('/home/mininet/appleseed')

start_aseed_cmd = None
if args.log:
	start_aseed_cmd = ['python', '/home/mininet/appleseed/pox.py', '--no-cli', 'appleseed','--is_backup_tree_expt=True', '--bak_mode=%s' %(args.bak_mode), '--opt=%s' %(args.opt),
                     '--num_switches=%s' %(args.topo_num), '--num_groups=%s' %(args.num_groups), 'openflow.discovery','log', '--file=ext/results/backup_tree_expt.log,w'] 
else:
	start_aseed_cmd = ['python', '/home/mininet/appleseed/pox.py', '--no-cli', 'log', '--no-default', 'appleseed', '--is_backup_tree_expt=True', '--bak_mode=%s' %(args.bak_mode),
                      '--opt=%s' %(args.opt), '--num_switches=%s' %(args.topo_num), '--num_groups=%s' %(args.num_groups), 'openflow.discovery'] 


os.chdir('/home/mininet/appleseed')
pid = Popen(start_aseed_cmd,shell=False).pid
controller_pid = pid + 1

# (3) connect to the appleseed controller
c_addr = "127.0.0.1"
c = RemoteController('c',ip=c_addr)

if args.log: print "trying to connect to remote controller at %s ..."%(c_addr)
net = Mininet(topo=ieee_mn_graph,link=TCLink,controller=lambda name: c,listenPort=6634)
if args.log: print "connected to remote controller at %s"%(c_addr)



wait = 5
if args.log: print "\n sleeping for %s seconds before sending any Mininet messages so as to allow all links to be discovered by the Appleseed controller. " %(wait)
time.sleep(wait)



if args.log: print "\n\nrunning 1-hop pings to populate allow for edge switches to discover their adjacent hosts"
hosts = net.hosts

# (2) 1-hop pings: DONE

# if we have an odd number of hosts add the first host to end of the list to
# ensure that a ping is run from each host
if len(hosts)%2==1:
	h1 = hosts[0]
	hosts.append(h1)

for h1,h2 in pairwise(hosts):
	cmd_str1 = 'ping -c1 -W 1 %s ' %(h2.IP())
	if args.log: print "%s %s" %(h1,cmd_str1)
	h1.cmd(cmd_str1)
	cmd_str2 = 'ping -c1 -W 1 %s ' %(h1.IP())
	if args.log: print "%s %s" %(h2,cmd_str2)
	h2.cmd(cmd_str2)

	
# (3) tell appleseed to install the m flow entries: TODO
staticArp(net)

# run a ping command from h1 to special address to trigger primary tree install
h1 = hosts[0]
special_ip = '10.244.244.244'
cmd_str = 'ping -c1 -W 1 %s' %(special_ip)
if args.log: print "h1 %s" %(cmd_str)
h1.cmd(cmd_str)

wait = 5
print "\n sleeping for %s seconds before starting cbr flows " %(wait)
time.sleep(wait)

# (4) start the cbr flows at the mcast root nodes
#rate = 60	# 60 msgs per second
#for group in mcast_groups:
#	root_id = group[0]
#	root_host = hosts[root_id -1]
#	mcast_addr = compute_mcast_addr(root_id)
#	cmd = 'sudo python ~/cbr_flow.py %s %s %s > ~/cbr/h%s_cbr.out &' %(root_id,mcast_addr,rate,root_id)
#	#if args.log: print cmd
#	root_host.cmd(cmd)

#CLI(net)


#raw_input("Press Enter to Exit")

raw_input()

net.stop()
