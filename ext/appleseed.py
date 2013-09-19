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
from pox.openflow.discovery import Discovery
import pcount
import multicast
import pox
log = core.getLogger("fault_tolerant_controller")
#log = core.getLogger()
from pox.lib.recoco import Timer
import csv
import os,sys
import utils
from pox.lib.util import dpidToStr

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.dhcp import dhcp
from pox.lib.addresses import IPAddr,EthAddr

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time




# Timeout for ARP entries
ARP_TIMEOUT = 6000 * 2



packets_dropped_threshold = 5

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
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
    #return time.time() > self.timeout





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

    self.listenTo(core)
    self.listenTo(core.openflow_discovery)
    
    # for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod). 
    self.flowTables = {} 
    
    # dict.  d_switch_id1 --> list w/ entries (d_switch_id2, d_switch_id3, .... , u_switch_id,nw_src,nw_dst)
    self.flow_measure_points={}  # note this really ought to be (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id)
    
    #multicast address -> [src,dest1,dest2,...]
    self.mcast_groups = {}
    
    # (src-ip,dst-ip) -> [switch_id1, switch_id2, ...]
    self.flow_strip_vlan_switch_ids = {}
    
    # (src-ip,dst-ip,switch_id) -> [dstream_host1,dstream_host2, ...] 
    self.mtree_dstream_hosts = {}
    
    # vlan_id -> [nw_src,nw_dst, u_switch_id,u_count,d_switch_id,d_count,u_count-dcount]
    self.pcount_results = dict()
    
    # multicast_dst_address -> list of tuples (u,d), representing a directed edge from u to d, that constitute all edges in the primary tree
    self.primary_trees = {}
    
    utils.read_flow_measure_points_file(self)
    utils.read_mtree_file(self)
    
    # TODO: this should be refactored to be statistics between 2 measurement points.  currently this lumps together all loss counts, which is problematic when we have
    #       more than a single pair of measurement points
    self.actual_total_pkt_dropped = 0
    self.detect_total_pkt_dropped = 0
    self.actual_pkt_dropped_gt_threshold_time=-1
    self.detect_pkt_dropped_gt_threshold_time=-1
    
    self.pkt_dropped_curr_sampling_window = 0
    
    
    
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


  def check_install_backup_trees(self,pkt_loss_cnt):
    """ Checks if the pkt_loss_cnt exceeds a threshold""" 
    
    return pkt_loss_cnt > packets_dropped_threshold
         
  def install_backup_trees(self):
    
    print "placeholder for installing backup trees"
   
  
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
    
    #for link in Discovery.adjacency:
    print core.openflow_discovery.adjacency
    for link in core.openflow_discovery.adjacency:
      print link
      print "(n%s,n%s) = outport %s ||| (n%s,n%s) = outport %s " %(link.dpid1,link.dpid2,link.port1,link.dpid2,link.dpid1,link.port2) 

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
    
    
    if multicast.is_mcast_address(dstaddr,self):
      if dstaddr in multicast.installed_mtrees:
        # should never reach here because mcast tree is setup when switch closest to root receives a msg destined for a multicast address 
        print "already setup mcast tree for s%s, inport=%s,dest=%s." %(dpid,inport,dstaddr)
        return
      
      log.info("special handling IP Packet in for multicast address %s" %(str(dstaddr)))
      u_switch_id, d_switch_ids = multicast.setup_mtree(srcaddr,dstaddr,inport,self)
      
      pcount.start_pcount_thread(u_switch_id, d_switch_ids, srcaddr, dstaddr,self)

      
    elif dstaddr in self.arpTable[dpid]:
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
        
        start_pcount,u_switch_id,d_switch_ids = pcount.check_start_pcount(dpid,match.nw_src,match.nw_dst,self)
        
        if start_pcount:
          pcount.start_pcount_thread(u_switch_id, d_switch_ids, match.nw_src, match.nw_dst,self)
    else:
      log.error("no ARP entry at switch s%s for dst=%s" %(dpid,dstaddr))
        
  
  def blah_blah_handle_LinkEvent (self, event):

    l = event.link
    #print l[0],l[1],l[2],l[3]

            
    ##### 9/17/13 DPG self-note for link discovery
    for link in core.openflow_discovery.adjacency:
      print link
      print "(n%s,n%s) = outport %s ||| (n%s,n%s) = outport %s " %(link.dpid1,link.dpid2,link.port1,link.dpid2,link.dpid1,link.port2) 
  
  def _handle_arp_PacketIn(self,event,packet,dpid,inport):
    """ Learns the inport the switch receive packets from the given IP address
    
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
          
          if multicast.is_mcast_address(a.protodst,self):
            log.debug("skipping normal ARP Request code because ARP request is for multicast address %s" %(str(a.protodst)))
            
            if a.protodst in multicast.installed_mtrees:
              print "already setup mcast tree for s%s, inport=%s,dest=%s, just resending the ARP reply and skipping mcast setup." %(dpid,inport,a.protodst)
              utils.send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac, self.arpTable[dpid][a.protodst].port)
            else:
              #getting the outport requires that we have run a "pingall" to setup the flow tables for the non-multicast addreses
              outport = utils.find_nonvlan_flow_outport(self.flowTables,dpid, a.protosrc, multicast.h1)
              self.arpTable[dpid][a.protodst] = Entry(outport,multicast.mcast_mac_addr)
              utils.send_arp_reply(packet, a, dpid, inport, self.arpTable[dpid][a.protodst].mac, self.arpTable[dpid][a.protodst].port)
            
            return

          # Learn or update port/MAC info for the SOURCE address 
          if a.protosrc in self.arpTable[dpid]:
            if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
              log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
          else:
            log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
            
          self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

          if a.opcode == arp.REQUEST:
            # Maybe we can answer

            if a.protodst in self.arpTable[dpid]:
              # We have an answer...

              if not self.arpTable[dpid][a.protodst].isExpired():
                # .. and it's relatively current, so we'll reply ourselves
                
                r = arp()
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                r.opcode = arp.REPLY
                r.hwdst = a.hwsrc
                r.protodst = a.protosrc #IP address
                r.protosrc = a.protodst #IP address
                r.hwsrc = self.arpTable[dpid][a.protodst].mac
                e = ethernet(type=packet.type, src=r.hwsrc, dst=a.hwsrc)
                e.set_payload(r)   # r is the ARP REPLY
                log.debug("%i %i answering ARP for %s" % (dpid, inport,
                 str(r.protosrc)))
                msg = of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
                msg.in_port = inport
                event.connection.send(msg)
                return

    # Didn't know how to answer or otherwise handle this ARP request, so just flood it
    log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
     {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
     'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

    msg = of.ofp_packet_out(in_port = inport, action = of.ofp_action_output(port = of.OFPP_FLOOD))
    if event.ofp.buffer_id is of.NO_BUFFER:
      # Try sending the (probably incomplete) raw data
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



  def handle_flow_stats (self,event):
    """ Process a flow statistics query result from a given switch"""
    pcount.handle_switch_query_result(event, self)
    
  def _handle_GoingUpEvent (self, event):
    """ When the connection to the controller is established, this function is called to register our components and listeners """
    self.listenTo(core.openflow)
    log.debug("Up...")
    
    
    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)
    log.debug("Listening to flow stats ...")
    
    log.debug("configuration files -- measurement points file = %s, mtree file=%s" %(multicast.measure_pnts_file_str,multicast.mtree_file_str))



def launch ():
  if 'openflow_discovery' not in core.components:
    import pox.openflow.discovery as discovery
    core.registerNew(discovery.Discovery)
    
  core.registerNew(fault_tolerant_controller)
  
  

