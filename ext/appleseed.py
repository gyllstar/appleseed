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

""" This module is our controller for running PCount sessions.

Some of this module code was copied from "pox/forwarding/l3_learning.py", which had the following comments:

    A stupid L3 switch
    
    For each switch:
    1) Keep a table that maps IP addresses to MAC addresses and switch ports.
       Stock this table using information from ARP and IP packets.
    2) When you see an ARP query, try to answer it using information in the table
       from step 1.  If the info in the table is old, just flood the query.
    3) Flood all other ARPs.
    4) When you see an IP packet, if you know the destination port (because it's
       in the table from step 1), install a flow for it.

I find this description somewhat misleading because it does not make it clear that there is no explicit data structure for switches, 
rather we identify switches by their switch_id and use the flow tables to determine and alter their state.          
  
"""

from pox.core import core
import pcount_all
import multicast
log = core.getLogger("fault_tolerant_controller")
#log = core.getLogger()
from collections import defaultdict
import utils

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import EventMixin

import time



BACKUP_TREE_EXPT_FLAG = False
INSTALL_PRIMARY_TREES_DELAY = 20  #delay of 10 seconds (from the time the first link is discovered) to install the primary trees
INSTALL_PRIMARY_TREE_TRIGGER_IP = IPAddr("10.244.244.244")
LINK_TIMEOUT = 1000 # time the discovery module waits before considering a link removed

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  """
  def __init__ (self, port, mac):
    self.port = port    #DPG: this could be a list of ports because we support Layer 3 multicast
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    return False #DPG: modified this because for our application (power grid) the IP addresses will not change and therefore will not expire


class AppleseedError(Exception):

  def __init__(self, *args, **kwargs):
    Exception.__init__(self, *args, **kwargs)


class fault_tolerant_controller (EventMixin):
  """ This is the controller application.  Each network switch is implemented as an L3 learning switch supporting ARP and PCount. 
  
  The flow tables are populated by implementing the behavior of an L3 learning switch.  Supporting ARP is a necessary to do so.  
  The PCount sessions are triggered, using a timer, after the first flow entries are installed (as part of the L3 learning phase).
  Currently flows are specified using the source IP address and destination address tuple.
  Note that there is no explicit data structure for switches, rather we identify them by switch_id and use the flow tables to 
  determine and alter their state.  
  
  TODO: Flows should be refactored to match packets using only the destination address, rather than (src_ip,dst_up) pair.  
  
  """
  
  def __init__ (self):

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    self.ip_to_mac_map = {}   # maps IP address to Mac address.  9/23 PROBABLY CAN DELETE

    self.listenTo(core)
    self.listenTo(core.openflow_discovery)
    
    # Adjacency map.  [(upstream_switch,downstream_switch)] -> port from upstream_switch to downstream_switch
    self.adjacency = defaultdict(lambda:None)
    
    # for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod). 
    self.flowTables = {} 
    
    # dict.  d_switch_id1 --> list w/ entries (d_switch_id2, d_switch_id3, .... , u_switch_id,nw_src,nw_dst)
    self.flow_measure_points={}  # note this really ought to be (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id)
    
    #multicast address -> [src,dest1,dest2,...]
    self.mcast_groups = {}
    
    # (src-ip,dst-ip) -> [switch_id1, switch_id2, ...].  list of the most downstream switch_ids in the PCount session
    self.flow_strip_vlan_switch_ids = {}
    
    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
    self.pcount_results = dict()
    
    self.primary_trees = [] 
    
    # dict: (u,d) --> (src_up,dst_ip). element of the set is a tuple of 2 integers: (u,d) where u is the upstream switch id and d the downstream switch id
    self.monitored_links  = {}
    
    # dict: (u,d) --> set[PCountResults], initiated when unicast flows are installed
    self.pcount_link_results = {}  

    
    self.num_monitor_flows = pcount_all.PCOUNT_NUM_MONITOR_FLOWS
    
    #self.backup_tree_mode = multicast.BackupMode.REACTIVE
    self.backup_tree_mode = multicast.BackupMode.PROACTIVE
    
    #self.algorithm_mode = multicast.Mode.MERGER
    self.algorithm_mode = multicast.Mode.BASELINE

    if pcount_all.IS_PCOUNT_EXP:
      self.algorithm_mode = multicast.Mode.BASELINE
    
    
    # TODO: this should be refactored to be statistics between 2 measurement points.  currently this lumps together all loss counts, which is problematic when we have
    #       more than a single pair of measurement points
    self.actual_total_pkt_dropped = 0
    self.detect_total_pkt_dropped = 0
    self.actual_pkt_dropped_gt_threshold_time=-1
    self.detect_pkt_dropped_gt_threshold_time=-1
    self.pkt_dropped_curr_sampling_window = 0
    self.turn_pcount_off = False
    
    if not pcount_all.IS_PCOUNT_EXP:
      utils.read_flow_measure_points_file(self)
      utils.read_mtree_file(self)
    
   
    
    
  def cache_flow_table_entry(self,dpid,flow_entry):
    """ For the given switch, adds the flow entry. This flow table mirrors the table stored at the switch
    
    Keyword arguments:
    dpid -- the switch id
    flow_entry -- a modify state message (i.e., libopenflow_01.ofp_flow_mod object)
    
    """
    if not self.flowTables.has_key(dpid):
      flow_table = list()
      flow_table.append(flow_entry)
      self.flowTables[dpid] = flow_table
    else:
      self.flowTables[dpid].append(flow_entry)


  def activate_backup_trees(self,failed_link):
    
    if self.algorithm_mode == multicast.Mode.MERGER:
      affected_trees = multicast.find_affected_primary_trees(self.primary_trees,failed_link)
      multicast.activate_merger_backups(self,affected_trees,failed_link)
      return
        
    for tree in multicast.find_affected_primary_trees(self.primary_trees,failed_link):
      msg = "installing backup tree for mcast_addr = %s for failed link %s" %(tree.mcast_address,failed_link)
      log.info(msg)
      backup = tree.backup_trees[failed_link]
      backup.activate()
    
   
  
  def _handle_ipv4_PacketIn(self,event,packet,dpid,inport):
    """ All IP packets from switches are processed here.  This is the meat of the controller, or at least where all processing is started.
    
    This function:
      (1) populates an ARP table w/ MAC address to IP Address mappings
      (2) starts a PCount session if the basic flow entries for forwarding are installed at all switches a part of the PCount session
    
    Keyword Arguments:
    event -- object with connection state between controller and the switch that sent us the IP packet
    packet -- IP packet
    dpid -- the switch id that sent us the packets
    inport -- the port the packet arrived 
    
    """
    log.debug("s%i inport=%i IP %s => %s", dpid,inport,str(packet.next.srcip),str(packet.next.dstip))
    
    # Learn or update port/MAC info for the SRC-IP (not dest!!)
    if packet.next.srcip in self.arpTable[dpid]:
      if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
        log.info("%i %i RE-learned %s", dpid,inport,str(packet.next.srcip))
    else:
      log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
    self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

    # Try to forward
    dstaddr = packet.next.dstip
    srcaddr = packet.next.srcip

    #if pcount_all.IS_PCOUNT_EXP:
    #  return
    
    if dstaddr in self.arpTable[dpid]:
      # We have info about what port to send it out on...

      prt = self.arpTable[dpid][dstaddr].port
      if prt == inport:
        log.warning("%i %i not sending packet for %s back out of the input port" % (
          dpid, inport, str(dstaddr)))
      else:
        log.debug("%i %i installing flow for %s => %s out port %i" % (dpid,
            inport, str(packet.next.srcip), str(dstaddr), prt))


        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                buffer_id=event.ofp.buffer_id,
                                action=of.ofp_action_output(port = prt)) 
        
        match = of.ofp_match.from_packet(packet,inport) 
        
        msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=match._nw_src, nw_dst = match._nw_dst) #DPG: match using L3 address
        
        self.cache_flow_table_entry(dpid, msg)
        
        event.connection.send(msg.pack())
        
    else:
      log.error("no ARP entry at switch s%s for dst=%s" %(dpid,dstaddr))
       
       
  def _handle_LinkEvent (self, event):
    """ Handles events thrown by pox.openflow.discovery to populate an adjacency matrix.  Starts timer for installing primary trees.
    
    pox.openflow.discovery uses LLDP packets to determine the network links and the port each link is connected to at the link's endpoints. 
    The first call to this function starts a timer to install the primary trees after a 10 second delay.
    """
    l = event.link
    s1 = l.dpid1
    s2 = l.dpid2
    
    link_event = "discovered"
    if not event.added: 
      link_event = "removed"
    msg = "%s (s%s,s%s)" %(link_event,s1,s2)
    log.info(msg)
    
    # Mininet links are bidirectional
    self.adjacency[(s1,s2)] = l.port1
    self.adjacency[(s2,s1)] = l.port2
    
    
  def add_switch_to_host_edges(self,switch_id,host_ip_addr,port):
    """ Add edges to adjacency list from switch_id to its directly connected host(s).
    
    Written such that each host can only be connected to a single switch.  
    """
    host_id = multicast.find_node_id(host_ip_addr)
    
    for key in self.adjacency.keys():
      if key[1] == host_id:
        return
    
    log.info("discovered (s%s,h%s)=%s" %(switch_id,host_id,port))
    
    self.adjacency[(switch_id,host_id)] = port
    
    
  def _handle_arp_PacketIn(self,event,packet,dpid,inport):
    """ Learns the inport the switch receive packets from the given IP address.  Once the primary trees are installed, all ARP packets are ignored.
    
    Keyword Arguments:
    event -- the event that triggered this function call
    packet -- IP packet
    dpid -- the switch id
    inport -- 
    """
    a = packet.next  # 'a' seems to be an IP packet (or actually it's an ARP packet)
    
    log.debug("%i %i ARP %s %s => %s", dpid, inport,{arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
    
    if a.prototype == arp.PROTO_TYPE_IP:
      if a.hwtype == arp.HW_TYPE_ETHERNET:
        if a.protosrc != 0:
          if a.protodst == INSTALL_PRIMARY_TREE_TRIGGER_IP:

            if len(self.primary_trees) > 0:
              return
            
            msg = "received special packet destined to %s so starting to install primary trees and any backup trees (if using Proactive recovery approach)" %(a.protodst)
            log.info(msg)
            
            if pcount_all.IS_PCOUNT_EXP:
              log.debug( "\n INSTALLING UNICAST FLOWS")
              multicast.install_pcount_unicast_flows(self)
              pcount_all.start_pcount(self,self.monitored_links,self.primary_trees,pcount_all.PCOUNT_NUM_MONITOR_FLOWS)
            elif BACKUP_TREE_EXPT_FLAG:
              multicast.install_all_trees(self,True) 
            else:
              multicast.install_all_trees(self)  # NICK: here is where I make the call to compute and install all primary trees (and potentially backup trees)
              pcount_all.start_pcount(self,self.monitored_links,self.primary_trees)
            return
           
          if multicast.is_mcast_address(a.protodst,self):
            log.debug("hack, because ARP request ARP request is for multicast address (%s), we send a fake mac address is the ARP reply "%(str(a.protodst)))
            outport = utils.find_flow_outports(self.flowTables,dpid, a.protosrc, a.protodst)
            self.arpTable[dpid][a.protodst] = Entry(outport,multicast.mcast_mac_addr)
            utils.send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac)
            
            return 
          
          # Learn or update port/MAC info for the SOURCE address 
          if a.protosrc in self.arpTable[dpid]:
            if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
              log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
          else:
            log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
          log.debug("adding %s to s%s ARP table" %(str(a.protosrc),dpid)) 
          self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)
         

          if a.opcode == arp.REQUEST:
            log.debug("Adding switch to hsot edges for s%s protosrc=%s, protodst=%s" %(dpid,a.protosrc,a.protodst))
            self.add_switch_to_host_edges(dpid,a.protosrc,inport)
            
            if a.protodst in self.arpTable[dpid]:
	      log.debug("sending ARP reply")
              utils.send_arp_reply(packet,a,dpid,inport,self.arpTable[dpid][a.protodst].mac)
              #self.add_switch_to_host_edges(dpid,a.protosrc,inport)
              return

    if len(self.primary_trees) == 0 and pcount_all.IS_PCOUNT_EXP:
      return
    
    # Didn't know how to answer or otherwise handle this ARP request, so just flood it
    log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
     {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
     'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))
    
    msg = of.ofp_packet_out(in_port = inport, action=of.ofp_action_output(port=of.OFPP_FLOOD))
    if event.ofp.buffer_id is of.NO_BUFFER:
      msg.data = event.data
    else:
      msg.buffer_id = event.ofp.buffer_id
    event.connection.send(msg.pack())
    



  def _handle_FlowRemoved (self, event):
    """ Handles the removal of our special flow entry to drop packets during a PCount session.
    
    Updates and logs the count of the true number of packets dropped, and prints this value to the console 
    
    TODO: move to PCount ?
    
    """
    num_dropped_pkts = event.ofp.packet_count
    
    self.actual_total_pkt_dropped += num_dropped_pkts
    self.pkt_dropped_curr_sampling_window = num_dropped_pkts
    
    outStr = "Flow removed on s%s, packets dropped = %s, total packets droppped=%s" %(event.dpid,num_dropped_pkts,self.actual_total_pkt_dropped)
    
    if self.actual_total_pkt_dropped > packets_dropped_threshold:
      self.actual_pkt_dropped_gt_threshold_time = time.clock()
      print "\n-------------------------------------------------------------------------------------------------------------------------------------------------------------"
      print "Total packets ACTUALLY dropped = %s, exceeds threshold of %s.  Timestamp = %s" %(self.actual_total_pkt_dropped,packets_dropped_threshold,self.actual_pkt_dropped_gt_threshold_time)
      print "-------------------------------------------------------------------------------------------------------------------------------------------------------------"
    log.debug(outStr) 

  def _handle_PacketIn (self, event):
    """ This is where all packets arriving at the controller received.  This function delegates the processing to sub-functions."""
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    
    if isinstance(packet.next,ipv4) and packet.next.srcip == IPAddr("0.0.0.0"):
      #print "DPG 0 :::::::: s%i inport=%i IP %s => %s" %(dpid,inport,str(packet.next.srcip),str(packet.next.dstip))
      return
    
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      self._handle_ipv4_PacketIn(event,packet,dpid,inport)

    elif isinstance(packet.next, arp):
      self._handle_arp_PacketIn(event,packet,dpid,inport)
      
    elif False:
      # this is where i am putting my code to parse the ofp_flow_removed message from the temporary flow entry to drop packets to simulate link loss
      self._handle_flow_removed_msg(event,packet,dpid)
      
    return
  
  
  def handle_d_node_aggregate_flow_stats(self,event):
    pcount_all.handle_d_node_aggregate_flow_stats(event,self)

  def handle_flow_removed (self,event):
    switch_id = event.connection.dpid
    print "AT S%s FLOW REMOVED " %(switch_id)
    print "S%s PACKET COUNT=%s " %(switch_id,event.ofp.packet_count)
    
  def handle_flow_stats (self,event):
    """ Process a flow statistics query result from a given switch"""
    pcount_all.handle_u_node_query_result(event, self)
    
  def _handle_GoingUpEvent (self, event):
    """ When the connection to the controller is established, this function is called to register our components and listeners """
    self.listenTo(core.openflow)
    log.debug("Up...")
    
    
    core.openflow.addListenerByName("AggregateFlowStatsReceived", self.handle_d_node_aggregate_flow_stats)
    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
    core.openflow.addListenerByName("FlowRemoved", self.handle_flow_removed)
    log.debug("Listening to flow stats ...")
    
    log.debug("configuration files -- measurement points file = %s, mtree file=%s" %(multicast.measure_pnts_file_str,multicast.mtree_file_str))



def launch (is_backup_tree_expt = False,num_monitor_flows=-1,num_unicast_flows=-1,true_loss_percentage=-1,dtime=False):
  if 'openflow_discovery' not in core.components:
    import pox.openflow.discovery as discovery
    discovery.LINK_TIMEOUT = LINK_TIMEOUT
    core.registerNew(discovery.Discovery)
    
  if num_monitor_flows != -1:
    #log.debug("before created ft_controller")
    #controller = fault_tolerant_controller()
    #controller.algorithm_mode = multicast.Mode.BASELINE
    pcount_all.PCOUNT_DTIME_EXPT = bool(dtime)
    if bool(dtime):
      num_monitor_flows = 1
    pcount_all.set_pcount_expt_params(num_monitor_flows,num_unicast_flows,true_loss_percentage)
    core.registerNew(fault_tolerant_controller)
  else:
    if bool(is_backup_tree_expt):
      BACKUP_TREE_EXPT_FLAG = True
    core.registerNew(fault_tolerant_controller)
  
  

