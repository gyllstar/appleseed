# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
DPG: Utility functions

"""
from pox.core import core
log = core.getLogger("dpg_utils")
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
import multicast,appleseed
import csv,time,os



def get_ofp_rule_str(rule):
  """ Create and return a string with ofp_rule match and actions"""
  prefix = '    '
  out_str = "match: \n"
  out_str += rule.match.show(prefix)
  out_str += "action: \n"
  cnt=0
  for action in rule.actions:
    cnt+=1
    out_str += '  (%s)' %(cnt)
    #prefix = '   (%s) ' %(cnt)
    out_str += action.show(prefix)
  return out_str
def send_msg_to_switch(msg,switch_id):
  
  for con in core.openflow._connections.itervalues():
    #print "msg to s%s" %(switch_id)
    if con.dpid == switch_id:
      con.send(msg.pack())



def find_flow_outports(flowTables,switch_id,nw_src,nw_dst):
  
  if not flowTables.has_key(switch_id):
    log.error("something wrong at dpg_utils.find_flow_outports(): should be a flow entry cached for switch id = %s" %(switch_id))
    return -1
  
  outports = []
  for flow_entry in flowTables[switch_id]:
    
    if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
      for action in flow_entry.actions:
        if isinstance(action, of.ofp_action_output):
          outports.append(action.port)
      
      return outports #DPG: important to return inside the outer for loop because otherwise we append multiple copies of the desired outport
  #print "(switch_id=%s,nw_src=%s,nw_dst=%s) has outport = %s" %(switch_id,nw_src,nw_dst,outport)
  #return outports


def read_mcast_groups_file(controller):
  
  mcast_group_file = "ext/topos/ext/topos/mcast-groups.csv" 
    
  #file structure:. root_id,terminal_host_id1,terminal_host_id2, ...
  for row in csv.reader(open(mcast_group_file),delimiter=','):
    val_list = []
    
    # check if it's a comment line
    if "#" in row[0]:
      continue
    
    root_id = row[0]
    
    val_list.insert(0, IPAddr(line_list[1])) #src ip
    
    i = 2
    while i < len(line_list): #2<4
      val_list.insert(i-1, IPAddr(line_list[i]))
      i+=1
    
    key = IPAddr(line_list[0])
    controller.mcast_groups[key] = val_list

def read_mtree_file(controller):
  """
  reads in a file specifying the nodes in a multicast tree (or trees)
  
  TODO: the location of the file is hard-coded and should be read for the command line, or improved in some way
    """
  mtree_file = "ext/topos/mtree/%s" %(multicast.mtree_file_str)
  
  # check if we need to load the mtree file
  topo1 = multicast.measure_pnts_file_str.split("-")[1]
  topo2 = multicast.mtree_file_str.split("-")[1]
  
  if topo1 != topo2:
    #log.info("did not load mtree file ('%s') because not using a valid matching measurement points file (loaded '%s')" %(multicast.mtree_file_str,multicast.measure_pnts_file_str))
    msg = "The topology ('%s') assumed by the mtree file ('%s') did not match the topology ('%s') assumed by the measurement points file ('%s')" %(topo2,multicast.mtree_file_str,topo1,multicast.measure_pnts_file_str)
    log.error("%s.  Exiting program." %(msg))
    raise appleseed.AppleseedError(msg)
  
  #file structure: multicast address,src,dest1,dest2,...
  for line_list in csv.reader(open(mtree_file)):
    val_list = list()
    
    # check if it's a comment line
    if "#" in line_list[0]:
      continue
    
    val_list.insert(0, IPAddr(line_list[1])) #src ip
    
    i = 2
    while i < len(line_list): #2<4
      val_list.insert(i-1, IPAddr(line_list[i]))
      i+=1
    
    key = IPAddr(line_list[0])
    controller.mcast_groups[key] = val_list
    
    #if controller.mcast_groups.has_key(key):
    #  entry = controller.mcast_groups[key]
    #  entry.append(val_list)
    #else:
    #  entry = list()
    #  entry.append(val_list)
    #  controller.mcast_groups[key] = entry
    
def read_flow_measure_points_file(controller):
  """ Assumes each line has the following format: 'downstream-switch,upstream-switch, ...'.  Creates a tuple (upstream-switch,downstream-switch) and
      adds this to multicast.monitored_links.  All values in the link after the second comma are ignored.
  """
  
  measure_file = "ext/topos/%s" %(multicast.measure_pnts_file_str)
  log.debug("using measure points file: %s" %(measure_file))
  
  for line_list in csv.reader(open(measure_file)):
    val_list = list()
    
    # check if it's a comment line
    if "#" in line_list[0]:
      continue
    
    downstream_node_id = int(line_list[0])
    upstream_node_id = int(line_list[1])
    link = (upstream_node_id,downstream_node_id)

    #link = (12,15)

    src_ip = IPAddr(line_list[-2])
    dst_ip = IPAddr(line_list[-1])
    
    controller.monitored_links[link] = (src_ip,dst_ip)
    
  #print "\n \n MONITORED LINKS = %s." %(controller.monitored_links)
  #os._exit(0)
      

def send_arp_reply(eth_packet,arp_packet,switch_id,inport,mac_addr):
  """ Create an ARP reply packet and send to the requesting switch"""
  r = arp()
  r.hwtype = arp_packet.hwtype
  r.prototype = arp_packet.prototype
  r.hwlen = arp_packet.hwlen
  r.protolen = arp_packet.protolen
  r.opcode = arp.REPLY

  r.protodst = arp_packet.protosrc
  r.protosrc = arp_packet.protodst
  r.hwdst = arp_packet.hwsrc  
  r.hwsrc = mac_addr

  e = ethernet(type=eth_packet.type, src=r.hwsrc, dst=arp_packet.hwsrc)
  e.set_payload(r)
  log.debug("%i %i answering ARP request from src=%s to dst=%s" % (switch_id,inport,str(r.protosrc),str(r.protodst)))
  #print "%i %i answering ARP request from src=%s to dst=%s" % (switch_id,inport,str(r.protosrc),str(r.protodst))

  msg = of.ofp_packet_out()
  msg.data = e.pack()
  msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
  msg.in_port = inport
  
  send_msg_to_switch(msg, switch_id)

def log_pcount_results(controller):
  
  file_base = multicast.measure_pnts_file_str.split(".")[0]
  #w = csv.writer(open("ext/results/current/pcount-output.csv", "w"))
  w = csv.writer(open("ext/results/current/%s-output.csv" %(file_base), "w"))
  for key, val in controller.pcount_results.items():
    w.writerow([key, val])
  



def record_pcount_val_activate_backups(vlan_id,nw_src,nw_dst,switch_id,packet_count,is_upstream,total_tag_count_switches,controller):
  """ Log the Pcount session results and print to console """
  result_list = list()    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
  if controller.pcount_results.has_key(vlan_id):
    result_list = controller.pcount_results[vlan_id]
  else:
    result_list.insert(0,nw_src)
    result_list.insert(1,nw_dst)
    
  # check to make result_list does not already contain an entry for switch_id
  indx = 2
  cnt=0
  #while indx < len(result_list):
  while cnt < total_tag_count_switches:
    
    if indx >= len(result_list):
      cnt+=10000 #some large number so we exit the loop
      continue
    
    if result_list[indx] == switch_id:  #look at 2,4,6,8, ...
      log.debug("received duplicate stat result query for flow (vlan_id=%s,nw_src=%s,nw_dst=%s) at s%s.  Not logging the message." %(vlan_id,nw_src,nw_dst,switch_id))
      return
    
    indx+=2
    cnt+=1  
    
  if is_upstream:
    result_list.insert(2,switch_id)
    packet_count += controller.pkt_dropped_curr_sampling_window  #count the packets dropped by our flow entry at 'u' that drops packets to simulate a lossy link
    controller.pkt_dropped_curr_sampling_window=0
    result_list.insert(3, packet_count)
  else:
    result_list.append(switch_id)
    result_list.append(packet_count)
  
  controller.pcount_results[vlan_id] = result_list
  
  total = 2+ total_tag_count_switches * 2
  if len(result_list) == total: 
    
    updatedTotalDrops = False
    for i in range(0,total_tag_count_switches-1):  
        offset = 3+ (2*i + 2) #5, 7, 9, 11
        diff = result_list[3] - result_list[offset]
        result_list.append(diff)
        
        upstream_id = int(result_list[2])
        d_str = result_list[offset-1]
        downstream_id = int(d_str)
        monitored_link = (upstream_id,downstream_id) 
        if controller.check_install_backup_trees(monitored_link,diff):
          controller.detect_pkt_dropped_gt_threshold_time = time.clock()
          controller.turn_pcount_off = True
          controller.activate_backup_trees(monitored_link)
        
        if not updatedTotalDrops:
          
          controller.detect_total_pkt_dropped += diff
          #pkt_dropped_curr_sampling_window=0
          
          log.debug("detected tatal packets dropped = %s, actual packets dropped=%s" %(controller.detect_total_pkt_dropped,controller.actual_total_pkt_dropped))
          
          if controller.detect_total_pkt_dropped > appleseed.packets_dropped_threshold:
            # controller.detect_pkt_dropped_gt_threshold_time = time.clock()  moved this farther up the function to reduce any lag in recording this timestamp
            detect_time_lag = controller.detect_pkt_dropped_gt_threshold_time - controller.actual_pkt_dropped_gt_threshold_time
            print "\n*************************************************************************************************************************************************************"
            print "Total detected packets dropped = %s, exceeds threshold of %s.  Actual Time=%s, Detect Time = %s, Detection Time Lag = %s" %(controller.detect_total_pkt_dropped,
                                                                                                                                             appleseed.packets_dropped_threshold,
                                                                                                                                             controller.actual_pkt_dropped_gt_threshold_time,
                                                                                                                                             controller.detect_pkt_dropped_gt_threshold_time,
                                                                                                                                             detect_time_lag)
            print "*************************************************************************************************************************************************************\n"
            
            updatedTotalDrops = True
            result_list.append(detect_time_lag)
            
        
    controller.pcount_results[vlan_id] = result_list
    log_pcount_results(controller)
    
    
def hasConverged(array,confPercent,withinMeanPerc):
    """ check if confidence interval for the values in the array (skipping the 1st value) have
    fallen within the 'withinMean' range of the mean for the array.  if so return True """
    
    mean = stats.computeMean(array)
    
    confIntervalVal = stats.computeConfIntervalVal(array,confPercent)
    
    
    withinMean = withinMeanPerc * mean
    
    if confIntervalVal <= withinMean:
        return True,mean,confIntervalVal
    
    return False,mean,confIntervalVal