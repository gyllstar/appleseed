# @author: dpg/gyllstar/Dan Gyllstrom


""" Implements PCount algorithm.

This module contains helper functions called by the controller to initiate PCount sessions,
along with a PCountSession class that does the actual PCount implmentation.
"""


from pox.core import core
from pox.lib.recoco import Timer
import pox
log = core.getLogger("pcount_all")

from pox.lib.addresses import IPAddr,EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import utils, appleseed, multicast

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time, random, os, csv

global_vlan_id=0

# in seconds
PCOUNT_WINDOW_SIZE=1  
PCOUNT_CALL_FREQUENCY=PCOUNT_WINDOW_SIZE*2
PROPOGATION_DELAY=1 #seconds


  
def start_pcount(controller,monitored_links,primary_trees,num_monitor_flows=1000):
  """ Find all primary trees using the monitored links and, for each monitored link (u,d), create PCount sessions for the set of flow entry used to forward packets along (u,d)"""
  
  if controller.algorithm_mode == multicast.Mode.MERGER: 
    msg = "Error.  Trying to initiate pcount_all session with MERGER optimization. Currently not supported"
    raise appleseed.AppleseedError(msg)
  
  relevant_trees = set()
  for monitored_link in monitored_links:
    # (1) find the primary trees using each monitored link
    relevant_trees = set()
    curr_num_flows = 0
    for tree in primary_trees:
      if tree.uses_link(monitored_link) and curr_num_flows < num_monitor_flows:
        relevant_trees.add(tree)
        curr_num_flows+=1
    
    if len(relevant_trees) == 0:
      msg = "No primary trees found using monitored link %s, therefore no pcount sessions initiated." %(monitored_link)
      log.error(msg)

    results = PCountResults(controller)
    results.actual_pkt_dropped_gt_threshold_time
    results.monitored_link = monitored_link
    results.num_monitored_flows = len(relevant_trees)
    controller.pcount_link_results[monitored_link] = results
  
  start_pcount_thread(controller,monitored_link[0], monitored_link[1],relevant_trees)
  #os._exit(0)

    # (3) create synchronous Pcount sessions for each flow entry from (2)

def start_pcount_thread(controller,u_switch_id,d_switch_id,relevant_trees):
  """ Sets a timer to start a PCount session
  
  Keyword Arguments:
  u_switch_id -- upstream switch id
  d_switch_id -- downstream switch id
  relevant_trees -- trees using (u,d)
  """
  pcounter = PCountSession()
  
  # likely can make this more dynamic by finding the most downstream nodes along the measurement path to determine the strip_vlan_switch_ids
  strip_vlan_switch_ids = d_switch_id
  
  
  #pcounter.pcount_session(controller,u_switch_id,d_switch_id,relevant_trees,strip_vlan_switch_ids,PCOUNT_WINDOW_SIZE)
  Timer(PCOUNT_CALL_FREQUENCY,pcounter.pcount_session, args = [controller,u_switch_id,d_switch_id,relevant_trees,strip_vlan_switch_ids,PCOUNT_WINDOW_SIZE],recurring=True,selfStoppable=True)



# TODO: refactor this mess by changing the structure of flow_measure_points to (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id) b/c no longer will need to search
#       the entire dict for a match
def is_counting_switch(switch_id,nw_src,nw_dst,controller):
  """ Checks if this switch is a downstream counting node for the (nw_src,nw_dst) flow
   
   TODO: refactor this mess by changing the structure of flow_measure_points to (nw_src,nw_dst) -> (d_switch_id2, d_switch_id3, .... , u_switch_id) b/c no longer will need to search
        the entire dict for a match 
  """
  # could be the key
  if controller.flow_measure_points.has_key(switch_id):
    for measure_pnt in controller.flow_measure_points[switch_id]:
      last_indx = len(measure_pnt) -1
      if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
        return True
   
  # could also be one of the first few values in the value list
  for measure_pnts in controller.flow_measure_points.values():
    for measure_pnt in measure_pnts:
      last_indx = len(measure_pnt) -1
      if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
        if switch_id in measure_pnt[0:last_indx-2]:  # the list "subset" or slice is not inclusive on the upper index
          return True
  
  return False
   


# tagging takes place at the upstream node
def is_tagging_switch(switch_id,nw_src,nw_dst,controller):
  """ is this an upstream tagging switch for flow (nw_src,nw_dst) """
  
  for measure_pnts in controller.flow_measure_points.values():
    for measure_pnt in measure_pnts:
      last_indx = len(measure_pnt) -1
      if measure_pnt[last_indx-2] == switch_id and measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
        return True
  
  
  return False


def total_tag_and_cnt_switches(nw_src, nw_dst,controller):
  """ returns the total number of measurement nodes (taggers and counters) for flow (nw_src,nw_dst)"""
  for measure_pnts in controller.flow_measure_points.values():
    for measure_pnt in measure_pnts:
      last_indx = len(measure_pnt) -1
      if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == nw_dst:
        return len(measure_pnt) -2 + 1  # minus two because don't want to count the nw_src, nw_dst, and plus one because one counting switch is not in teh measure_pnt list (it is the hash key)
  
  return -1
   
 
    
      





class PCountSession (EventMixin):
  """ Single PCount session: measure the packet loss for flow, f, between an upstream switch and downstream switches, for a specified window of time
  
  """
  
  def __init__ (self):

    #  Copy of the version maintained at fault_tolerant_controller.   
    #self.depracated_flowTables = {} #for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod).
    #self.depracated_arpTable = {}
    
    self.current_highest_priority_flow_num = of.OFP_DEFAULT_PRIORITY

    self.arpTable = {}
    self.flowTables = {}
    
    self.controller = None
 
 
  def pcount_session(self,controller,u_switch_id,d_switch_id,relevant_trees,strip_vlan_switch_id,window_size):
    """
    Entry point to running a PCount session. Measure the packet loss for flow, f, between the upstream switch and  and downstream switches, for a specified window of time
    
    Keyword arguments
    u_switch_id --  the id of the upstream switch, 
    d_switch_id -- list of ids of the downstream switches
    relevant_trees
    window_size -- window is the length (in seconds) of the sampling window
    
    """
    if controller.turn_pcount_off: 
      return False
    
    self.arpTable = controller.arpTable
    self.flowTables = controller.flowTables
    
    global global_vlan_id
    global_vlan_id+=1
    self.controller = controller
    

    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("(%s) started pcount session along (s%s,s%s) for VLAN=%s lasting %s seconds" %(current_time,u_switch_id,d_switch_id,global_vlan_id,window_size)) 
    self._start_pcount_session(u_switch_id,d_switch_id,strip_vlan_switch_id,relevant_trees,global_vlan_id)
    #self._stop_pcount_session_and_query(u_switch_id,d_switch_id,strip_vlan_switch_id,relevant_trees,global_vlan_id)
    
    Timer(window_size, self._stop_pcount_session_and_query, args = [u_switch_id,d_switch_id,strip_vlan_switch_id,relevant_trees,global_vlan_id]) 
    

  def _query_tagging_switch(self,switch_id,vlan_id,nw_src,nw_dst):
    """ Issue a query to the tagging switch, using (vlan_id,nw_src,nw_dst) to identify the flow """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match,priority= self._find_tagging_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          #print "sent tagging stats request to s%s with params=(nw_src=%s, nw_dst=%s, vlan_id=%s)" %(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))
          #con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))  #DPG: temp for debugging so we can see all flow table values

  def _query_counting_switch_all_flows(self,switch_id,vlan_id):
    """ Issue a query to the tagging switch, using (vlan_id,nw_src,nw_dst) to identify the flow """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match = of.ofp_match(dl_type = ethernet.IP_TYPE,dl_vlan=vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_aggregate_stats_request(match=match)))
    
  def _query_counting_switch(self,switch_id,vlan_id,nw_src,nw_dst):
    """ Send a query request to the counting switch """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match = self._find_counting_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))

  def _start_pcount_session(self,u_switch_id,d_switch_id,strip_vlan_switch_id,relevant_trees,vlan_id):
    """ Install flow entries for PCount session and install rule to drop packets (to simulate packet loss)
    
    Install a flow entry downstream to count tagged packets, then install tag and count rule upstream, and last install a rule to randomly drop packets so as to simulate packet loss
    
    """
    self.current_highest_priority_flow_num+=1
    
    # (1): count and tag all packets at d that match the VLAN tag
    for primary_tree in relevant_trees:
      self._start_pcount_downstream(d_switch_id,strip_vlan_switch_id,primary_tree,vlan_id)
    
    # (2): tag and count all packets at upstream switch, u
    for primary_tree in relevant_trees:
      self._start_pcount_upstream(u_switch_id,vlan_id, primary_tree)  
    
    # (3): start a thread to install a rule which drops packets at u for a short period (this is used to measure time to detect packet loss)
    #Timer(1, self._install_drop_pkt_flow, args = [u_switch_id,nw_src,nw_dst])
    
  def _find_orig_flow_and_clean_cache(self,switch_id,nw_src,nw_dst,primary_tree):
    """ Find a flow matching (nw_src,nw_dst,old_flow_priority), remove it from the cache, and return this value """
    node = None
    flow_entry = None
    ofp_match_pattern = None
    #old_flow_priority = self.current_highest_priority_flow_num - 2
    
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.priority < self.current_highest_priority_flow_num:
        old_flow_priority = flow_entry.priority
        match = flow_entry.match
        self.flowTables[switch_id].remove(flow_entry)
        return match,old_flow_priority
  
    log.error("should have found a matching flow (%s,%s) at s%s" %(nw_src,nw_dst,switch_id))    

  def _find_tagging_flow_match(self,u_switch_id,nw_src,nw_dst,vlan_id):
    """ Find a tagging flow matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return this value """    
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s" %(u_switch_id,vlan_id)) 
    
    
  def _install_drop_pkt_flow(self,u_switch_id,nw_src,nw_dst):
    """ Install a rule to drop packets at the given switch.  Between a random integer between 0 and w/2, where w is window size of the PCount session, are dropped."""
    # highest possible value for flow table entry is 2^(16) -1
    flow_priority= 2**16 - 1
    
    timeout = random.randint(0,PCOUNT_WINDOW_SIZE/2) # amount of time packets will be dropped
                                                          
    send_flow_rem_flag = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
    
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,priority=flow_priority,hard_timeout = timeout)
    msg.flags = send_flow_rem_flag
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug( "\t * (%s) installed drop packet flow at s%s (src=%s,dst=%s)" %(current_time,u_switch_id,nw_src,nw_dst))
    
    #  To drop packet leave actions empty.  From OpenFlow 1.1 specification "There is no explicit action to represent drops. Instead packets whose action sets have 
    #  no output actions should be dropped"
    
    utils.send_msg_to_switch(msg, u_switch_id)
    
    

  def _find_counting_flow_match(self,switch_id,nw_src,nw_dst,vlan_id): 
    """ Find a counting flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id) and return it. """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
        return flow_entry.match
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") %(d_switch_id,vlan_id)  

  def _find_tagging_flow_and_clean_cache(self,u_switch_id,nw_src,nw_dst,vlan_id):
    """ Find a tagging flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return it. """
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            self.flowTables[u_switch_id].remove(flow_entry)
            return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") %(u_switch_id,vlan_id)  
    
    
  def _find_vlan_counting_flow_and_clean_cache(self,switch_id,nw_src,nw_dst,vlan_id):
    """ Find a counting flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return it. """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan==vlan_id:
        self.flowTables[switch_id].remove(flow_entry)
        return flow_entry.match,flow_entry.priority
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") %(d_switch_id,vlan_id)  


  def _stop_pcount_session_and_query(self,u_switch_id,d_switch_id,strip_vlan_switch_id,relevant_trees,vlan_id):
    """ Stop the PCount session by removing the tagging and counting flows and issuing a query for their corresponding packet counts.
    
    The operations to stop PCount takes place in the following order
      (1)  turn tagging off at the upstream switch by installing a copy of the original flow entry, that matches (nw_src,nw_dst), with higher priority than e' (the tagging flow)
      (2)  wait for time proportional to transit time between u and d to turn counting off at d (to account for in-transit packets after tagging is shut off)
      (3)  query upstream and downstream switches for packet counts
      (4)  delete the upstream tagging flow
      (5)  delete the original upstream flow used upstream to match packets for our flow (nw_src,nw_dst)
      (6)  delete the downstream VLAN counting flow

    """
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("(%s) stopped pcount session between switches (s%s,%s) forvlan_id=%s)" %(current_time,u_switch_id,d_switch_id,vlan_id))
    
    self.current_highest_priority_flow_num+=1
    new_flow_priority = self.current_highest_priority_flow_num   
    
    # (1): turn tagging off at u (reinstall e with higher priority than e'), 
    for primary_tree in relevant_trees:   # could optimize to just delete here and return the result
      self._reinstall_basic_flow_entry(u_switch_id, primary_tree.root_ip_address, primary_tree.mcast_address, new_flow_priority)

    # (2): wait for time proportional to transit time between u and d to turn counting off at d
    time.sleep(PROPOGATION_DELAY)
    
    # (3) query u and d for packet counts
    for primary_tree in relevant_trees:
      self._query_tagging_switch(u_switch_id, vlan_id,primary_tree.root_ip_address, primary_tree.mcast_address)
    
    self._query_counting_switch_all_flows(d_switch_id, vlan_id)
    
    # (4) delete the original flow entries at u (e and e') and d (e and e'')
    
    # delete the upstream VLAN tagging flow
    for primary_tree in relevant_trees:
      u_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      u_switch_msg.match,u_switch_msg.priority = self._find_tagging_flow_and_clean_cache(u_switch_id,primary_tree.root_ip_address, primary_tree.mcast_address,vlan_id)
      utils.send_msg_to_switch(u_switch_msg , u_switch_id)
   
      #delete the original upstream flow
      old_flow_priority = self.current_highest_priority_flow_num - 2
      u_switch_msg2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      u_switch_msg2.match,old_flow_priority = self._find_orig_flow_and_clean_cache(u_switch_id,primary_tree.root_ip_address, primary_tree.mcast_address,primary_tree)
      u_switch_msg2.priority = old_flow_priority
      utils.send_msg_to_switch(u_switch_msg2 , u_switch_id)
 
    # delete the downstream VLAN counting flow
    for primary_tree in relevant_trees:
      d_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      d_switch_msg.match,d_switch_msg.priority = self._find_vlan_counting_flow_and_clean_cache(d_switch_id,primary_tree.root_ip_address, primary_tree.mcast_address,vlan_id)
      utils.send_msg_to_switch(d_switch_msg , d_switch_id)
      
  
  def _reinstall_basic_flow_entry(self,switch_id,nw_src,nw_dst,flow_priority):
    """ Install a flow entry that only cares about (nw_src,nw_dst), i.e., nothing with vlan_id """
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_dst)
    
    prts = utils.find_flow_outports(self.flowTables, switch_id, nw_src, nw_dst)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))
    
    utils.send_msg_to_switch(msg, switch_id)
    
    self._cache_flow_table_entry(switch_id, msg)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("\t * (%s) reinstalled basic flow (src=%s,dest=%s,priority=%s) at s%s" % (current_time,nw_src,nw_dst,flow_priority,switch_id))
  

  def _add_rewrite_single_mcast_dst_action(self,switch_id,msg,nw_mcast_dst,new_ip_dst):
    """ Append to the action list of flow, to rewrite a multicast address to a regular IP address"""
    action = of.ofp_action_nw_addr.set_dst(IPAddr(new_ip_dst))
    msg.actions.append(action)
  
    new_mac_addr = self.arpTable[switch_id][new_ip_dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    msg.actions.append(l2_action)



  def _start_pcount_downstream(self,d_switch_id,strip_vlan_switch_id,primary_tree,vlan_id):
    """ Install a flow entry at each downstream measurement node to count tagged packets. """
    
    # (1): create a copy of the flow entry, e, at switch d.  call this copy e''.  e''  counts packets using the VLAN field
    flow_priority = self.current_highest_priority_flow_num

    # Just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,priority=flow_priority)
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE,nw_src = primary_tree.root_ip_address, nw_dst = primary_tree.mcast_address,dl_vlan=vlan_id)
    
    self._append_downstream_actions(primary_tree, d_switch_id, msg, strip_vlan_switch_id, primary_tree.mcast_address)
    
    # (2): install e'' at d with a higher priority than e
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug("\t * (%s) installed counting flow (dest=%s,priority=%s,vlan_id=%s) at s%s" % (current_time,primary_tree.mcast_address,flow_priority,vlan_id,d_switch_id))
    utils.send_msg_to_switch(msg, d_switch_id)
    
    self._cache_flow_table_entry(d_switch_id, msg)

  def _append_downstream_actions(self,primary_tree,d_switch_id,msg,strip_vlan_switch_id,nw_dst):
    
    # this is where the action list should be sequential (one destination at-a-time) so the correct version of each modified packet is output 
    # when for leaf switches with > 1 adjacent downstream switch
    
    if d_switch_id == strip_vlan_switch_id:
      msg.actions.append(of.ofp_action_header(type=of.OFPAT_STRIP_VLAN))  
    
    if self.controller.algorithm_mode == multicast.Mode.MERGER:
      d_node = multicast.nodes[d_switch_id]
      original_flow_entry = d_node.treeid_rule_map[primary_tree.id]
      original_flow_entry.generate_ofp_actions(msg,self.controller,d_switch_id)
      return
    
    if primary_tree.is_leaf_node(d_switch_id):
      host_to_port_map, switch_ports, dst_addresses = primary_tree.compute_host_port_maps(d_switch_id)
      self.append_rewrite_dst_mcast_flow(msg,d_switch_id, host_to_port_map, nw_dst, dst_addresses, switch_ports)
    else:  # non-leaf node:  for BASELINE: add the correct outports, 
      prts = primary_tree.find_outports(d_switch_id)
      for p in prts:
        msg.actions.append(of.ofp_action_output(port = p))
        
  def append_rewrite_dst_mcast_flow(self,ofp_msg,switch_id,ports,nw_mcast_dst,new_dst,switch_ports):
    """ Creates actions to rewrite the multicast address in the packet to the IP address of a downstream host.  
    
    Keyword Arguments
    switch_id -- 
    nw_src -- IP address of source 
    ports -- dictionary of host to outport mapping
    nw_mcast_dst -- Multicast IP destination address
    new_dst -- the IP address(es) to overwrite the destination IP address.  Either a single IP address or list of IP addresses
    switch_ports -- the outports for any connected downstream switch in the tree
    """
    # add actions for the downstream switches 1st
    for prt in switch_ports:
      ofp_msg.actions.append(of.ofp_action_output(port = prt))
    
    if isinstance(new_dst,list):    # if multiple downstream hosts
      
      # this part is only executed if multiple addresses need to be rewriteen (works because OF switches execute actions in order, meaning that each copy of the packet
      # is output before the next destination address rewrite takes place)
      for dst in new_dst:
        action = of.ofp_action_nw_addr.set_dst(IPAddr(dst))
        ofp_msg.actions.append(action)
        
        new_mac_addr = self.controller.arpTable[switch_id][dst].mac
        l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
        ofp_msg.actions.append(l2_action)
        
        prt = ports[dst]  
        ofp_msg.actions.append(of.ofp_action_output(port = prt))
        
    else:     # for single downstream host
      action = of.ofp_action_nw_addr.set_dst(IPAddr(new_dst))
      ofp_msg.actions.append(action)
      
      new_mac_addr = self.controller.arpTable[switch_id][new_dst].mac
      l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
      ofp_msg.actions.append(l2_action)
          
      for prt in ports:
        ofp_msg.actions.append(of.ofp_action_output(port = prt)) 

  def _start_pcount_upstream(self,u_switch_id,vlan_id, primary_tree):
    """ Start tagging and counting packets at the upstream switch.  Creates a new flow table entry to do so and is set with a higher priority than its non-tagging counterpart
    """
  # (1): create a copy of the flow entry, e, at switch u.  call this copy e'. 

    flow_priority = self.current_highest_priority_flow_num
    
    prts = primary_tree.find_outports(u_switch_id)
      
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src = primary_tree.root_ip_address,nw_dst = primary_tree.mcast_address) 
  
  # (2):  e' tags packets using the VLAN field
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    log.debug( "\t * (%s) installed tagging flow at s%s (dst=%s,set vid = %s)" %(current_time,u_switch_id,primary_tree.mcast_address,vlan_id))
    vlan_action = of.ofp_action_vlan_vid()
    vlan_action.vlan_vid = vlan_id
    msg.actions.append(vlan_action)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port = p))
    
    
  # (3): install e' at u with a higher priority than e
    utils.send_msg_to_switch(msg, u_switch_id)
    
    self._cache_flow_table_entry(u_switch_id, msg)
    

  
    

  
  def _cache_flow_table_entry(self,dpid,flow_entry):
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
    


def handle_u_node_query_result (event,controller):
  """ Process a flow statistics query result from a given switch"""
  u_switch_id = event.connection.dpid
  
  curr_results = None
  for pcount_result in controller.pcount_link_results.values():
    if pcount_result.monitored_link[0] == u_switch_id:
      curr_results = pcount_result
  
  packet_count = -1
  vlan_id = -1
  for flow_stat in event.stats: #note that event stats is a list of flow table entries

    for flow_action in flow_stat.actions:
      if isinstance(flow_action, of.ofp_action_vlan_vid): 
        packet_count = flow_stat.packet_count
        vlan_id = flow_action.vlan_vid
  
  curr_results.update_u_node_results(packet_count,vlan_id)
    


def handle_d_node_aggregate_flow_stats (event,controller):
  d_switch_id = event.connection.dpid
  
  curr_results = None
  for pcount_result in controller.pcount_link_results.values():
    if pcount_result.monitored_link[1] == d_switch_id:
      curr_results = pcount_result
  
  pkt_cnt = event.stats.packet_count
  curr_results.update_d_node_results(pkt_cnt)


def find_vlan(event):
  vlan = -1
  
  return vlan


class PCountResults():
  
  def __init__(self,controller):
    self.d_node_count = {}  # vlan_id --> value
    self.u_node_count = {}  # vlan_id --> value
    
    self.actual_total_pkt_dropped = {}  # vlan_id --> value
    self.detect_total_pkt_dropped = {}  # vlan_id --> value
    
    self.actual_pkt_dropped_gt_threshold_time = {}  # vlan_id --> value
    self.detect_pkt_dropped_gt_threshold_time= {}  # vlan_id --> value
    self.num_monitored_flows = -1
    self.monitored_link = -1
    
    self.curr_num_u_node_results = 0
    self.curr_vlan_id = 1 
    self.controller = controller
    
    #self.pkt_dropped_curr_sampling_window = 0
   
  def update_u_node_results(self,pkt_cnt,vlan_id):
    
    if self.curr_num_u_node_results >= self.num_monitored_flows:
      msg = "ERROR. PCountResults instance must be getting duplicate u_node query results at vlan=%s" %(vlan_id)
      raise appleseed.AppleseedError(msg)
    
    if self.u_node_count.has_key(vlan_id):
      curr_result = self.u_node_count[vlan_id]
      self.u_node_count[vlan_id] = curr_result + pkt_cnt
    else:
      self.u_node_count[vlan_id] = pkt_cnt
    
    self.curr_num_u_node_results +=1

    self.record_window_results(vlan_id)   
  
   
  def update_d_node_results(self,pkt_cnt):
    
    if self.d_node_count.has_key(self.curr_vlan_id):
      msg = "ERROR. PCountResults instance should not have a d_node_count value for vlan_id=%s.  Must be getting duplicate query results " %(self.curr_vlan_id)
      raise appleseed.AppleseedError(msg)
  
    self.d_node_count[self.curr_vlan_id] = pkt_cnt
    
    self.record_window_results(self.curr_vlan_id)
  
  def record_window_results(self,vlan_id):
    
    if not self.d_node_count.has_key(vlan_id) or not self.u_node_count.has_key(vlan_id):
      return
    
    if self.curr_num_u_node_results != self.num_monitored_flows:
      return
    
    detected_drops = self.u_node_count[vlan_id] - self.d_node_count[vlan_id]
    
    if self.controller.check_install_backup_trees(self.monitored_link,detected_drops):
      self.controller.turn_pcount_off = True
        self.controller.activate_backup_trees(self.monitored_link)
      
    self.detect_total_pkt_dropped[vlan_id] = detected_drops
    self.log_pcount_results()
    
    self.curr_num_u_node_results = 0
    self.curr_vlan_id +=1   # this means that the result for prev vlan must reach the controller before the next session is started
    
   # print "COMPLETED VLAN SESSION %s with DETECTED DROPPED PKTS: u_cnt - d_cnt = %s - %s = %s" %(self.curr_vlan_id-1,self.u_node_count[vlan_id],self.d_node_count[vlan_id],detected_drops)
    
    
  def log_pcount_results(self):
  
    file_base = multicast.measure_pnts_file_str.split(".")[0]
    w = csv.writer(open("ext/results/current/%s-output.csv" %(file_base), "w"))
    for session_num in range(1,self.curr_vlan_id+1): 
      detected_drops = self.detect_total_pkt_dropped[session_num]
      w.writerow([session_num, self.num_monitored_flows,detected_drops])
    