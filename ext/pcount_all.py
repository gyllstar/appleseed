# @author: dpg/gyllstar/Dan Gyllstrom


""" Implements PCount algorithm.

This module contains helper functions called by the controller to initiate PCount sessions,
along with a PCountSession class that does the actual PCount implmentation.
"""


from pox.core import core
from pox.lib.recoco import Timer
import pox
log = core.getLogger("pcount_all")

from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
import utils, appleseed, multicast, stats

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time, random, os, csv

global_vlan_id = 0
global_current_high_priority = of.OFP_DEFAULT_PRIORITY 

# variables for loss rate
PCOUNT_SAMPLE_QUOTA = 50
#  PCOUNT_SAMPLE_QUOTA = 2

IS_PCOUNT_EXP = False
PCOUNT_WINDOW_SIZE = 5  
PCOUNT_CALL_FREQUENCY = PCOUNT_WINDOW_SIZE * 2
PCOUNT_PROP_DELAY = 1 #seconds  
PCOUNT_NUM_MONITOR_FLOWS = -1
PCOUNT_NUM_UNICAST_FLOWS = -1
PCOUNT_TRUE_LOSS_PERCENTAGE = -1
PCOUNT_LOSS_THRESHOLD = -1
#pcount_window_sizes = [4,4.5, 5,5.5,6,6.5,7]
pcount_window_sizes = [0.5, 1, 1.5, 2, 2.5, 3, 3.5, 4, 4.5, 5,5.5,6,6.5,7]

pcount_window_detect_time_results = []  #list of lists, where each sublist is of form [num_monitored_flows,window_size,mean_detection_time, confidence_interval_lower, confidence_interval_upper]

# variables for detection time
PCOUNT_DTIME_EXPT = False
PCOUNT_MAX_NUM_MONITORS = 240
PCOUNT_DTIME_NUM_MONITORS_INCREMENT = int(PCOUNT_MAX_NUM_MONITORS / 8)
PCOUNT_MAX_NUM_JUNKFLOWS = 3600
PCOUNT_JUNKFLOWS_INCREMENT = int(PCOUNT_MAX_NUM_JUNKFLOWS / 6)
PCOUNT_MAX_NUM_JUNKFLOWS = 3600
PCOUNT_CURR_NUM_JUNKFLOWS = 0
pcount_dtime_window = 2
curr_pcount_session=None #PCountSession object

#pcount_window_sizes = [0.2,0.4,0.6,0.8,1,1.2,1.4,1.6,1.8,2,3,4,5]

#num_monitor_flows=-1,num_unicast_flows=-1,loss_threshold=-1

def set_pcount_expt_params(num_monitor_flows, num_unicast_flows, true_loss_percentage, move_to_next_sim=True):
  log.debug("setting up Pcount Expt parameters")
  global PCOUNT_WINDOW_SIZE
  if len(pcount_window_sizes) == 0 and move_to_next_sim:
    return True,num_monitor_flows # end the experiment
   
  global IS_PCOUNT_EXP
  IS_PCOUNT_EXP = True
  
  if not PCOUNT_DTIME_EXPT and move_to_next_sim:
   PCOUNT_WINDOW_SIZE = pcount_window_sizes.pop(0)
  
  global PCOUNT_NUM_MONITOR_FLOWS
  global PCOUNT_NUM_UNICAST_FLOWS
  PCOUNT_NUM_MONITOR_FLOWS = int(num_monitor_flows)
  PCOUNT_NUM_UNICAST_FLOWS = int(num_unicast_flows)
  
  global PCOUNT_TRUE_LOSS_PERCENTAGE
  PCOUNT_TRUE_LOSS_PERCENTAGE = float(true_loss_percentage)
  
  global PCOUNT_LOSS_THRESHOLD
  send_rate = 60 # 60 pkts per second
  PCOUNT_LOSS_THRESHOLD = int(float(num_unicast_flows) * float(send_rate) * float(PCOUNT_WINDOW_SIZE) * float(true_loss_percentage) / 100)
  PCOUNT_LOSS_THRESHOLD = -1  # because we want to record the detection time and loss estimate over every window
  
  msg = ""
  if PCOUNT_DTIME_EXPT:
    global PCOUNT_NUM_UNICAST_FLOWS
    PCOUNT_NUM_UNICAST_FLOWS = 1
    if PCOUNT_CURR_NUM_JUNKFLOWS > PCOUNT_MAX_NUM_JUNKFLOWS:
      return True,num_monitor_flows # exit the experiment

    if num_monitor_flows > PCOUNT_MAX_NUM_MONITORS:
      # advance to next num JUNK flows and reset90 num_monitor_flows
   
      global PCOUNT_CURR_NUM_JUNKFLOWS
      PCOUNT_CURR_NUM_JUNKFLOWS = PCOUNT_CURR_NUM_JUNKFLOWS + PCOUNT_JUNKFLOWS_INCREMENT
      num_monitor_flows = 1
      
    global PCOUNT_NUM_MONITOR_FLOWS
    PCOUNT_NUM_MONITOR_FLOWS = num_monitor_flows
    PCOUNT_WINDOW_SIZE = pcount_dtime_window
    msg = "PCount Exp Parameters: w=%s, true loss=%s, threshold=%s, num_monitored_flows=%s, dtime_expt=%s" % (pcount_dtime_window, PCOUNT_TRUE_LOSS_PERCENTAGE, PCOUNT_LOSS_THRESHOLD, PCOUNT_NUM_MONITOR_FLOWS,PCOUNT_DTIME_EXPT)
  else:
    msg = "PCount Exp Parameters: w=%s, true loss=%s, threshold=%s, num_monitored_flows=%s" % (PCOUNT_WINDOW_SIZE, PCOUNT_TRUE_LOSS_PERCENTAGE, PCOUNT_LOSS_THRESHOLD, PCOUNT_NUM_MONITOR_FLOWS)
  log.info(msg)

  global PCOUNT_CALL_FREQUENCY
  PCOUNT_CALL_FREQUENCY = PCOUNT_WINDOW_SIZE * 2
  return False,PCOUNT_NUM_MONITOR_FLOWS
  
def get_next_dummy_src_ipaddr(id):

  r3 = id/254
  d3 = id%254

  r2 = r3/254
  d2 = r3%254

  r1 = r2/254
  d1 = r2%254

  ip_str = '10.%s.%s.1' %(d3,d2)
  return IPAddr(ip_str)  

def gen_dummy_primary_trees(controller, num_dummy_trees, relevant_trees):
  """ Used by  PCOUNT_DTIME_EXPT only """ 
  
  num_hosts_half = int(PCOUNT_NUM_UNICAST_FLOWS)
  u_id = int(num_hosts_half * 2) + 1
  d_id = u_id + 1
  
  for id in range(0, num_dummy_trees):
    dummy_src_host = get_next_dummy_src_ipaddr(id)
    dst_id = u_id - 1
    dst_host = multicast.find_host_ip_addr(dst_id)
    edges = [(1, u_id), (u_id, d_id), (d_id, dst_id)]
    data = {"edges":edges, "mcast_address":dst_host, "root":dummy_src_host, "terminals":[dst_host], "adjacency":controller.adjacency, "controller":controller}
    tree = multicast.PrimaryTree(**data)
    controller.primary_trees.append(tree)
    relevant_trees.add(tree)
    #log.debug("installing primary tree for unicast flow (%s,%s)" %(src_id,dst_id))
    tree.install()
  
def sample_random_primary_tree_set(primary_trees, monitored_link, sample_size):
  
  all_relevant_trees = []
  for tree in primary_trees:
    if tree.uses_link(monitored_link):
      all_relevant_trees.append(tree)
  sample_list = random.sample(all_relevant_trees, sample_size)
  return set(sample_list)

def start_pcount(controller, monitored_links, primary_trees, num_monitor_flows=PCOUNT_NUM_MONITOR_FLOWS,add_junk_flows_flag=False):
  """ Find all primary trees using the monitored links and, for each monitored link (u,d), create PCount sessions for the set of flow entry used to forward packets along (u,d)"""
 
  if controller.algorithm_mode == multicast.Mode.MERGER: 
    msg = "Error.  Trying to initiate pcount_all session with MERGER optimization. Currently not supported"
    raise appleseed.AppleseedError(msg)
  
  relevant_trees = set()
  for monitored_link in monitored_links:
    # (1) find the primary trees using each monitored link
    #relevant_trees = set()
    #curr_num_flows = 0
    sample_size = num_monitor_flows
    if len(primary_trees) < num_monitor_flows:
      sample_size = len(primary_trees)
    relevant_trees = sample_random_primary_tree_set(primary_trees, monitored_link, sample_size)
    
    if PCOUNT_DTIME_EXPT and len(relevant_trees) < PCOUNT_NUM_MONITOR_FLOWS:
      diff = PCOUNT_NUM_MONITOR_FLOWS - len(relevant_trees) 
      gen_dummy_primary_trees(controller, diff, relevant_trees)
      log.debug("generating dummy primary trees for fake monitoring of flows.")
    
    if len(relevant_trees) == 0:
      msg = "No primary trees found using monitored link %s, therefore no pcount sessions initiated." % (monitored_link)
      log.error(msg)
    
    results = PCountResults(controller, global_vlan_id + 1, PCOUNT_WINDOW_SIZE, PCOUNT_LOSS_THRESHOLD,PCOUNT_CURR_NUM_JUNKFLOWS)
    results.monitored_link = monitored_link
    results.num_monitored_flows = len(relevant_trees)
    controller.pcount_link_results[monitored_link].add(results)  
  
  #controller.turn_pcount_off = False
  start_pcount_thread(controller, monitored_link[0], monitored_link[1], relevant_trees,add_junk_flows_flag)

    # (3) create synchronous Pcount sessions for each flow entry from (2)


def install_junk_flow_entries(controller, u_switch_id, d_switch_id):
  """ Install junk flow entries at u_id and d_id using PCOUNT_CURR_NUM_JUNKFLOWS value """
  if PCOUNT_CURR_NUM_JUNKFLOWS == 0: return
  num_installed_junkflows = PCOUNT_CURR_NUM_JUNKFLOWS - PCOUNT_JUNKFLOWS_INCREMENT
  #for junk_num in range(num_installed_junkflows, PCOUNT_CURR_NUM_JUNKFLOWS):
  for junk_num in range(0, PCOUNT_CURR_NUM_JUNKFLOWS):  #start at 0 because now we clear the flow tables after each session
    junk_dst_ipaddr = IPAddr("10.77.77.77")
    junk_msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
    junk_msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_dst=junk_dst_ipaddr)
    junk_msg.priority = junk_num
    utils.send_msg_to_switch(junk_msg, u_switch_id)
    utils.send_msg_to_switch(junk_msg, d_switch_id)
    controller.cache_flow_table_entry(u_switch_id, junk_msg)  #probably don't need this
    controller.cache_flow_table_entry(d_switch_id, junk_msg)
     
def start_pcount_thread(controller, u_switch_id, d_switch_id, relevant_trees,add_junk_flows_flag=False):
  """ Sets a timer to start a PCount session
  
  Keyword Arguments:
  u_switch_id -- upstream switch id
  d_switch_id -- downstream switch id
  relevant_trees -- trees using (u,d)
  """
  
  
  # likely can make this more dynamic by finding the most downstream nodes along the measurement path to determine the strip_vlan_switch_ids
  strip_vlan_switch_ids = d_switch_id
  pcounter = PCountSession(u_switch_id, d_switch_id, relevant_trees, strip_vlan_switch_ids, PCOUNT_WINDOW_SIZE)
  
  global curr_pcount_session
  curr_pcount_session = pcounter
  
  msg = "\nAPPLESEED CONTROLLER MSG: Starting PCount Experiment Run where PCOUNT_DTIME_EXPT=%s, (%s window sizes left) with Parameters:\n\t\t w=%s,num_monitored_flows=%s, true loss=%s, threshold=%s, junk_flows=%s \n" % (PCOUNT_DTIME_EXPT,len(pcount_window_sizes), PCOUNT_WINDOW_SIZE, len(relevant_trees), PCOUNT_TRUE_LOSS_PERCENTAGE, PCOUNT_LOSS_THRESHOLD, PCOUNT_CURR_NUM_JUNKFLOWS)
  print msg #want to print so we know our progress when running our experiments
  log.info(msg)
  
  if PCOUNT_DTIME_EXPT and add_junk_flows_flag:
    install_junk_flow_entries(controller, u_switch_id, d_switch_id)
  
  #pcounter.pcount_session(controller,u_switch_id,d_switch_id,relevant_trees,strip_vlan_switch_ids,PCOUNT_WINDOW_SIZE)
  pcounter.pcount_session(controller, u_switch_id, d_switch_id, relevant_trees, strip_vlan_switch_ids, PCOUNT_WINDOW_SIZE)
  #Timer(PCOUNT_CALL_FREQUENCY, pcounter.pcount_session, args=[controller, u_switch_id, d_switch_id, relevant_trees, strip_vlan_switch_ids, PCOUNT_WINDOW_SIZE], recurring=True, selfStoppable=True)


def setup_and_start_next_expt(controller, prev_num_monitored_flows, current_highest_priority_flow_num):
  
  move_to_next_sim = False
  #num_monitor_flows = prev_num_monitored_flows-1
  subtract_val = float(float(PCOUNT_NUM_UNICAST_FLOWS) / float(4))
  subtract_val = int(subtract_val) + 1
  num_monitor_flows = prev_num_monitored_flows - subtract_val
  
  

  if num_monitor_flows < 1:
    num_monitor_flows = 1
  if prev_num_monitored_flows == 1:
    move_to_next_sim = True
    num_monitor_flows = PCOUNT_NUM_UNICAST_FLOWS
  if PCOUNT_DTIME_EXPT:
    if prev_num_monitored_flows == 1: num_monitor_flows = prev_num_monitored_flows + PCOUNT_DTIME_NUM_MONITORS_INCREMENT - 1
    else: num_monitor_flows = prev_num_monitored_flows + PCOUNT_DTIME_NUM_MONITORS_INCREMENT
    move_to_next_sim = True
    
  end_experiment_flag,num_monitor_flows = set_pcount_expt_params(num_monitor_flows, PCOUNT_NUM_UNICAST_FLOWS, PCOUNT_TRUE_LOSS_PERCENTAGE, move_to_next_sim)

  if end_experiment_flag:
    print "Appleseed Controller program terminated.  Press Enter to Exit Mininet script."
    os._exit(0)

  global global_current_high_priority
  global_current_high_priority = current_highest_priority_flow_num
  
  add_junk_flows_flag=False
  if PCOUNT_DTIME_EXPT and num_monitor_flows == 1:
    add_junk_flows_flag=True
    clear_flow_tables(controller)
    time.sleep(1)
  
  start_pcount(controller, controller.monitored_links, controller.primary_trees, num_monitor_flows,add_junk_flows_flag)
  
def clear_flow_tables(controller):
  """ Clear flow tables at switches, clear controller cache, clear primary tree list"""
  monitored_link = controller.monitored_links.keys()[0]
  u_id = monitored_link[0]
  d_id = monitored_link[1]
  msg = of.ofp_flow_mod(match=of.ofp_match(dl_type=ethernet.IP_TYPE),command=of.OFPFC_DELETE)
  utils.send_msg_to_switch(msg, u_id)
  utils.send_msg_to_switch(msg, d_id)   
  
  del controller.primary_trees[:]
  
  del controller.flowTables[u_id][:]
  del controller.flowTables[d_id][:]
  
class PCountSession (EventMixin):
  """ Single PCount session: measure the packet loss for flow, f, between an upstream switch and downstream switches, for a specified window of time
  
  """
  
  def __init__ (self,u_switch_id, d_switch_id, relevant_trees, strip_vlan_switch_id, window_size):

    #  Copy of the version maintained at fault_tolerant_controller.   
    #self.depracated_flowTables = {} #for each switch keep track of flow tables (switchId --> flow-table-entry), specifically (dpid --> ofp_flow_mod).
    #self.depracated_arpTable = {}
    
    self.current_highest_priority_flow_num = global_current_high_priority
                                              #of.OFP_DEFAULT_PRIORITY + global_vlan_id
    #log.debug("Current Highest Priority Flow Initalized to %s and global_vlan_id=%s" % (self.current_highest_priority_flow_num, global_vlan_id))

    self.arpTable = {}
    self.flowTables = {}
    
    self.controller = None
    
    self.u_switch_id = u_switch_id
    self.d_switch_id = d_switch_id
    self.relevant_trees = relevant_trees
    self.strip_vlan_switch_id = strip_vlan_switch_id
    self.window_size = window_size
 
 
  def pcount_session(self, controller, u_switch_id, d_switch_id, relevant_trees, strip_vlan_switch_id, window_size):
    """
    Entry point to running a PCount session. Measure the packet loss for flow, f, between the upstream switch and  and downstream switches, for a specified window of time
    
    Keyword arguments
    u_switch_id --  the id of the upstream switch, 
    d_switch_id -- list of ids of the downstream switches
    relevant_trees
    window_size -- window is the length (in seconds) of the sampling window
    
    """
#    if controller.turn_pcount_off:
#      setup_and_start_next_expt(controller, len(relevant_trees), self.current_highest_priority_flow_num)
#      return False
    
    self.arpTable = controller.arpTable
    self.flowTables = controller.flowTables
    
    global global_vlan_id
    global_vlan_id += 1
    self.controller = controller
    

    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    #log.debug("(%s) started pcount session along (s%s,s%s) for VLAN=%s lasting %s seconds" % (current_time, u_switch_id, d_switch_id, global_vlan_id, window_size)) 
    self._start_pcount_session(u_switch_id, d_switch_id, strip_vlan_switch_id, relevant_trees, global_vlan_id)
    #self._stop_pcount_session_and_query(u_switch_id,d_switch_id,strip_vlan_switch_id,relevant_trees,global_vlan_id)
    
    Timer(window_size, self._stop_pcount_session_and_query, args=[u_switch_id, d_switch_id, strip_vlan_switch_id, relevant_trees, global_vlan_id]) 
    

  def _query_tagging_switch(self, switch_id, vlan_id, nw_src, nw_dst):
    """ Issue a query to the tagging switch, using (vlan_id,nw_src,nw_dst) to identify the flow """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match, priority = self._find_tagging_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          #print "sent tagging stats request to s%s with params=(nw_src=%s, nw_dst=%s, vlan_id=%s)" %(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))
          #con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))  #DPG: temp for debugging so we can see all flow table values

  def _query_counting_switch_all_flows(self, switch_id, vlan_id):
    """ Issue a query to the tagging switch, using (vlan_id,nw_src,nw_dst) to identify the flow """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match = of.ofp_match(dl_type=ethernet.IP_TYPE, dl_vlan=vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_aggregate_stats_request(match=match)))
    
  def _query_counting_switch(self, switch_id, vlan_id, nw_src, nw_dst):
    """ Send a query request to the counting switch """
    for con in core.openflow._connections.itervalues():
        if con.dpid == switch_id:
          match = self._find_counting_flow_match(switch_id, nw_src, nw_dst, vlan_id)
          con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request(match=match)))

  def _start_pcount_session(self, u_switch_id, d_switch_id, strip_vlan_switch_id, relevant_trees, vlan_id):
    """ Install flow entries for PCount session and install rule to drop packets (to simulate packet loss)
    
    Install a flow entry downstream to count tagged packets, then install tag and count rule upstream, and last install a rule to randomly drop packets so as to simulate packet loss
    
    """
    self.current_highest_priority_flow_num += 1
    
    # (1): count and tag all packets at d that match the VLAN tag
    for primary_tree in relevant_trees:
      self._start_pcount_downstream(d_switch_id, strip_vlan_switch_id, primary_tree, vlan_id)
    
    pcount_results = get_pcount_results_obj(self.controller, (u_switch_id, d_switch_id), PCOUNT_WINDOW_SIZE, len(relevant_trees))
    #pcount_results = self.controller.pcount_link_results[(u_switch_id,d_switch_id)]
    pcount_results.record_start_time(vlan_id)
    
    # (2): tag and count all packets at upstream switch, u
    for primary_tree in relevant_trees:
      self._start_pcount_upstream(u_switch_id, vlan_id, primary_tree)  
    
    # (3): start a thread to install a rule which drops packets at u for a short period (this is used to measure time to detect packet loss)
    #Timer(1, self._install_drop_pkt_flow, args = [u_switch_id,nw_src,nw_dst])
    
  def _find_orig_flow_and_clean_cache(self, switch_id, nw_src, nw_dst, primary_tree):
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
        return match, old_flow_priority
  
    log.error("should have found a matching flow (%s,%s) at s%s" % (nw_src, nw_dst, switch_id))    

  def _find_tagging_flow_match(self, u_switch_id, nw_src, nw_dst, vlan_id):
    """ Find a tagging flow matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return this value """    
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            return flow_entry.match, flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s" % (u_switch_id, vlan_id)) 
    
    
  def _install_drop_pkt_flow(self, u_switch_id, nw_src, nw_dst):
    """ Install a rule to drop packets at the given switch.  Between a random integer between 0 and w/2, where w is window size of the PCount session, are dropped."""
    # highest possible value for flow table entry is 2^(16) -1
    flow_priority = 2 ** 16 - 1
    
    timeout = random.randint(0, PCOUNT_WINDOW_SIZE / 2) # amount of time packets will be dropped
                                                          
    send_flow_rem_flag = of.ofp_flow_mod_flags_rev_map['OFPFF_SEND_FLOW_REM']
    
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD, priority=flow_priority, hard_timeout=timeout)
    msg.flags = send_flow_rem_flag
    msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=nw_src, nw_dst=nw_dst)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    #log.debug("\t * (%s) installed drop packet flow at s%s (src=%s,dst=%s)" % (current_time, u_switch_id, nw_src, nw_dst))
    
    #  To drop packet leave actions empty.  From OpenFlow 1.1 specification "There is no explicit action to represent drops. Instead packets whose action sets have 
    #  no output actions should be dropped"
    
    utils.send_msg_to_switch(msg, u_switch_id)
    
    

  def _find_counting_flow_match(self, switch_id, nw_src, nw_dst, vlan_id): 
    """ Find a counting flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id) and return it. """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan == vlan_id:
        return flow_entry.match
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") % (d_switch_id, vlan_id)  

  def _find_tagging_flow_and_clean_cache(self, u_switch_id, nw_src, nw_dst, vlan_id):
    """ Find a tagging flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return it. """
    for flow_entry in self.flowTables[u_switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst:
        for flow_action in flow_entry.actions:
          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
            self.flowTables[u_switch_id].remove(flow_entry)
            return flow_entry.match, flow_entry.priority
  
    log.error("should have found a matching flow for s%s that tags packets with vlan_id=%s") % (u_switch_id, vlan_id)  
    
    
  def _find_vlan_counting_flow_and_clean_cache(self, switch_id, nw_src, nw_dst, vlan_id):
    """ Find a counting flow entry (by looking at our cache) matching (nw_src,nw_dst,vlan_id), remove it from the cache, and return it. """
    for flow_entry in self.flowTables[switch_id]:
      if flow_entry.match.nw_src == nw_src and flow_entry.match.nw_dst == nw_dst and flow_entry.match.dl_vlan == vlan_id:
        self.flowTables[switch_id].remove(flow_entry)
        return flow_entry.match, flow_entry.priority
  
    log.error("should have found a matching flow for s%s that counts packets with vlan_id=%s") % (d_switch_id, vlan_id)  


  def _stop_pcount_session_and_query(self, u_switch_id, d_switch_id, strip_vlan_switch_id, relevant_trees, vlan_id):
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
    #log.debug("(%s) stopped pcount session between switches (s%s,%s) forvlan_id=%s)" % (current_time, u_switch_id, d_switch_id, vlan_id))
    
    self.current_highest_priority_flow_num += 1
    new_flow_priority = self.current_highest_priority_flow_num   
    
    # (1): turn tagging off at u (reinstall e with higher priority than e'), 
    for primary_tree in relevant_trees:   # could optimize to just delete here and return the result
      self._reinstall_basic_flow_entry(u_switch_id, primary_tree.root_ip_address, primary_tree.mcast_address, new_flow_priority)

    # (2): wait for time proportional to transit time between u and d to turn counting off at d
    time.sleep(PCOUNT_PROP_DELAY)
    
    # (3) query u and d for packet counts
    for primary_tree in relevant_trees:
      self._query_tagging_switch(u_switch_id, vlan_id, primary_tree.root_ip_address, primary_tree.mcast_address)
    
    self._query_counting_switch_all_flows(d_switch_id, vlan_id)
    
    # (4) delete the original flow entries at u (e and e') and d (e and e'')
    
    # delete the upstream VLAN tagging flow
    for primary_tree in relevant_trees:
      u_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      u_switch_msg.match, u_switch_msg.priority = self._find_tagging_flow_and_clean_cache(u_switch_id, primary_tree.root_ip_address, primary_tree.mcast_address, vlan_id)
      utils.send_msg_to_switch(u_switch_msg , u_switch_id)
   
      #delete the original upstream flow
      if vlan_id > 1:
        old_flow_priority = self.current_highest_priority_flow_num - 2
        u_switch_msg2 = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
        u_switch_msg2.match, old_flow_priority = self._find_orig_flow_and_clean_cache(u_switch_id, primary_tree.root_ip_address, primary_tree.mcast_address, primary_tree)
        u_switch_msg2.priority = old_flow_priority
        utils.send_msg_to_switch(u_switch_msg2 , u_switch_id)
 
    # delete the downstream VLAN counting flow
    for primary_tree in relevant_trees:
      d_switch_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
      d_switch_msg.match, d_switch_msg.priority = self._find_vlan_counting_flow_and_clean_cache(d_switch_id, primary_tree.root_ip_address, primary_tree.mcast_address, vlan_id)
      utils.send_msg_to_switch(d_switch_msg , d_switch_id)
      
  
  def _reinstall_basic_flow_entry(self, switch_id, nw_src, nw_dst, flow_priority):
    """ Install a flow entry that only cares about (nw_src,nw_dst), i.e., nothing with vlan_id """
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=nw_src, nw_dst=nw_dst)
    
    prts = utils.find_flow_outports(self.flowTables, switch_id, nw_src, nw_dst)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port=p))
    
    utils.send_msg_to_switch(msg, switch_id)
    
    self._cache_flow_table_entry(switch_id, msg)
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    #log.debug("\t * (%s) reinstalled basic flow (src=%s,dest=%s,priority=%s) at s%s" % (current_time, nw_src, nw_dst, flow_priority, switch_id))
  

  def _add_rewrite_single_mcast_dst_action(self, switch_id, msg, nw_mcast_dst, new_ip_dst):
    """ Append to the action list of flow, to rewrite a multicast address to a regular IP address"""
    action = of.ofp_action_nw_addr.set_dst(IPAddr(new_ip_dst))
    msg.actions.append(action)
  
    new_mac_addr = self.arpTable[switch_id][new_ip_dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    msg.actions.append(l2_action)



  def _start_pcount_downstream(self, d_switch_id, strip_vlan_switch_id, primary_tree, vlan_id):
    """ Install a flow entry at each downstream measurement node to count tagged packets. """
    
    # (1): create a copy of the flow entry, e, at switch d.  call this copy e''.  e''  counts packets using the VLAN field
    flow_priority = self.current_highest_priority_flow_num

    # Just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD, priority=flow_priority)
    msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=primary_tree.root_ip_address, nw_dst=primary_tree.mcast_address, dl_vlan=vlan_id)
    
    if not PCOUNT_DTIME_EXPT:
      self._append_downstream_actions(primary_tree, d_switch_id, msg, strip_vlan_switch_id, primary_tree.mcast_address)
    
    # (2): install e'' at d with a higher priority than e
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    #log.debug("\t * (%s) installed counting flow (dest=%s,priority=%s,vlan_id=%s) at s%s" % (current_time, primary_tree.mcast_address, flow_priority, vlan_id, d_switch_id))
    utils.send_msg_to_switch(msg, d_switch_id)
    
    self._cache_flow_table_entry(d_switch_id, msg)

  def _append_downstream_actions(self, primary_tree, d_switch_id, msg, strip_vlan_switch_id, nw_dst):
    
    # this is where the action list should be sequential (one destination at-a-time) so the correct version of each modified packet is output 
    # when for leaf switches with > 1 adjacent downstream switch
    
    if d_switch_id == strip_vlan_switch_id:
      msg.actions.append(of.ofp_action_header(type=of.OFPAT_STRIP_VLAN))  
    
    if self.controller.algorithm_mode == multicast.Mode.MERGER:
      d_node = multicast.nodes[d_switch_id]
      original_flow_entry = d_node.treeid_rule_map[primary_tree.id]
      original_flow_entry.generate_ofp_actions(msg, self.controller, d_switch_id)
      return
    
    if primary_tree.is_leaf_node(d_switch_id):
      host_to_port_map, switch_ports, dst_addresses = primary_tree.compute_host_port_maps(d_switch_id)
      self.append_rewrite_dst_mcast_flow(msg, d_switch_id, host_to_port_map, nw_dst, dst_addresses, switch_ports)
    else:  # non-leaf node:  for BASELINE: add the correct outports, 
      prts = primary_tree.find_outports(d_switch_id)
      for p in prts:
        msg.actions.append(of.ofp_action_output(port=p))
        
  def append_rewrite_dst_mcast_flow(self, ofp_msg, switch_id, ports, nw_mcast_dst, new_dst, switch_ports):
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
      ofp_msg.actions.append(of.ofp_action_output(port=prt))
    
    if isinstance(new_dst, list):    # if multiple downstream hosts
      
      # this part is only executed if multiple addresses need to be rewriteen (works because OF switches execute actions in order, meaning that each copy of the packet
      # is output before the next destination address rewrite takes place)
      for dst in new_dst:
        action = of.ofp_action_nw_addr.set_dst(IPAddr(dst))
        ofp_msg.actions.append(action)
        
        new_mac_addr = self.controller.arpTable[switch_id][dst].mac
        l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
        ofp_msg.actions.append(l2_action)
        
        prt = ports[dst]  
        ofp_msg.actions.append(of.ofp_action_output(port=prt))
        
    else:     # for single downstream host
      action = of.ofp_action_nw_addr.set_dst(IPAddr(new_dst))
      ofp_msg.actions.append(action)
      
      new_mac_addr = self.controller.arpTable[switch_id][new_dst].mac
      l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
      ofp_msg.actions.append(l2_action)
          
      for prt in ports:
        ofp_msg.actions.append(of.ofp_action_output(port=prt)) 

  def _start_pcount_upstream(self, u_switch_id, vlan_id, primary_tree):
    """ Start tagging and counting packets at the upstream switch.  Creates a new flow table entry to do so and is set with a higher priority than its non-tagging counterpart
    """
  # (1): create a copy of the flow entry, e, at switch u.  call this copy e'. 

    flow_priority = self.current_highest_priority_flow_num
    
    prts = primary_tree.find_outports(u_switch_id)
      
    # Hack: just use the network source and destination to create a new flow, rather than make a copy
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD, priority=flow_priority)
        
    msg.match = of.ofp_match(dl_type=ethernet.IP_TYPE, nw_src=primary_tree.root_ip_address, nw_dst=primary_tree.mcast_address) 
  
  # (2):  e' tags packets using the VLAN field
  
    current_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    #log.debug("\t * (%s) installed tagging flow at s%s (dst=%s,set vid = %s)" % (current_time, u_switch_id, primary_tree.mcast_address, vlan_id))
    vlan_action = of.ofp_action_vlan_vid()
    vlan_action.vlan_vid = vlan_id
    msg.actions.append(vlan_action)
    
    for p in prts:
      msg.actions.append(of.ofp_action_output(port=p))
    
    
  # (3): install e' at u with a higher priority than e
    utils.send_msg_to_switch(msg, u_switch_id)
    
    self._cache_flow_table_entry(u_switch_id, msg)
    

  
    

  
  def _cache_flow_table_entry(self, dpid, flow_entry):
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
    


def handle_u_node_query_result (event, controller):
  """ Process a flow statistics query result from a given switch"""
  start_proc_time = time.time()
  
  u_switch_id = event.connection.dpid
  #log.debug("pcount query result from s%s" % (u_switch_id))  
  
  # pcount_results = get_pcount_results_obj(self.controller, (u_switch_id,d_switch_id), PCOUNT_WINDOW_SIZE, len(relevant_trees))
  monitored_link = None
  for link in controller.monitored_links.keys():
    if link[0] == u_switch_id:
      monitored_link = link 
      
  curr_results = get_pcount_results_obj(controller, monitored_link, PCOUNT_WINDOW_SIZE, PCOUNT_NUM_MONITOR_FLOWS)
#  for pcount_result in controller.pcount_link_results.values():
#    if pcount_result.monitored_link[0] == u_switch_id:
#      curr_results = pcount_result
  
  packet_count = -1
  vlan_id = -1
  for flow_stat in event.stats: #note that event stats is a list of flow table entries

    for flow_action in flow_stat.actions:
      if isinstance(flow_action, of.ofp_action_vlan_vid): 
        packet_count = flow_stat.packet_count
        #log.debug("u_node packet count = %s" % (packet_count))
        vlan_id = flow_action.vlan_vid
  
  curr_results.update_u_node_results(packet_count, vlan_id,start_proc_time)
  
  start_next_pcount_session(curr_results.move_nxt_window_session,curr_results.move_nxt_expt_setting)
  curr_results.move_nxt_window_session = False
  curr_results.move_nxt_expt_setting = False

def handle_d_node_aggregate_flow_stats (event, controller):
  start_proc_time = time.time()
  d_switch_id = event.connection.dpid
  #log.debug("pcount aggregate query result from s%s" % (d_switch_id))  
  
  monitored_link = None
  for link in controller.monitored_links.keys():
    if link[1] == d_switch_id:
      monitored_link = link
  
  curr_results = get_pcount_results_obj(controller, monitored_link, PCOUNT_WINDOW_SIZE, PCOUNT_NUM_MONITOR_FLOWS)
  
  pkt_cnt = event.stats.packet_count
  #log.debug("d_node aggregate query result at s%s = %s" % (d_switch_id, pkt_cnt))  
  curr_results.update_d_node_results(pkt_cnt,start_proc_time)
  
  start_next_pcount_session(curr_results.move_nxt_window_session,curr_results.move_nxt_expt_setting)
  curr_results.move_nxt_window_session = False
  curr_results.move_nxt_expt_setting = False

  #TODO check if should start next pcount session
  
def start_next_pcount_session(move_nxt_window_session,move_nxt_expt_setting):
  """  """
  if move_nxt_window_session == False and move_nxt_expt_setting == False:
    return
  
  if move_nxt_window_session:
    Timer(1, curr_pcount_session.pcount_session, args=[curr_pcount_session.controller, curr_pcount_session.u_switch_id, curr_pcount_session.d_switch_id, curr_pcount_session.relevant_trees,
                                         curr_pcount_session.strip_vlan_switch_id, curr_pcount_session.window_size])
    #log.debug("starting next pcount_session for same window (w=%s) and same settings as previous pcount session" %(curr_pcount_session.window_size))
  elif move_nxt_expt_setting:
    Timer(1,setup_and_start_next_expt, args=[curr_pcount_session.controller, len(curr_pcount_session.relevant_trees), curr_pcount_session.current_highest_priority_flow_num ])
    #log.debug("making call to setup_and_start_next_expt() ")
  
def find_vlan(event):
  vlan = -1
  
  return vlan
 
def get_pcount_results_obj(controller, link, window_size, num_monitored_flows):
  for result in controller.pcount_link_results[link]:
    if PCOUNT_DTIME_EXPT:
      if float(result.window_size) == float(window_size) and int(result.num_monitored_flows) == int(num_monitored_flows) and int(PCOUNT_CURR_NUM_JUNKFLOWS) == int(result.num_junk_flows):
        return result
    else:
      if float(result.window_size) == float(window_size) and int(result.num_monitored_flows) == int(num_monitored_flows):
        return result
    
  msg = "no matching PCountResults object found for l=%s with w=%s and num_monitored_flows=%s." % (link, window_size, num_monitored_flows)
  raise appleseed.AppleseedError(msg)
    


class PCountResults():
  
  def __init__(self, controller, start_vlan_id,window_size= -1, loss_threshold= -1,num_junk_flows=0):
    self.d_node_count = {}  # vlan_id --> value
    self.u_node_count = {}  # vlan_id --> value
    
    self.actual_total_pkt_dropped = {}  # vlan_id --> value
    self.detect_total_pkt_dropped = {}  # vlan_id --> value
    self.estimated_loss_ratio = {}  # vlan_id --> value
    #self.estimated_loss_ratio = {}  # vlan_id --> value
    self.num_junk_flows=num_junk_flows #only used for PCOUNT_DTIME_EXPT
    
    self.loss_threshold = loss_threshold
    self.window_size = window_size
    self.window_start_time = {}# vlan_id --> value
    self.detect_time = {} # vlan_id --> value
    self.total_detection_time_results = {} #vlan_id --> value
    
    self.actual_pkt_dropped_gt_threshold_time = {}  # vlan_id --> value
    self.detect_pkt_dropped_gt_threshold_time = {}  # vlan_id --> value
    self.num_monitored_flows = -1
    self.monitored_link = -1
    
    self.move_nxt_window_session = False
    self.move_nxt_expt_setting = False
    
    self.curr_num_u_node_results = 0
    self.curr_vlan_id = start_vlan_id 
    self.controller = controller
    
    self.first_pkt_time = 0
    self.total_time_btw_first_last_pkts=0
    self.single_run_proc_time = 0
    self.total_controller_proc_time = 0
    
    self.send_rate = 60 # 60 pkts per second
    #self.expected_num_lost_pkts = int( float(num_unicast_flows) * float(send_rate) * float(PCOUNT_WINDOW_SIZE) * float(true_loss_percentage)/100 )
    #self.true_loss_rate = float(float(expected_num_lost_pkts)/float(self.window_size))
    
    #self.pkt_dropped_curr_sampling_window = 0
  
  def record_start_time(self, vlan_id):
    self.window_start_time[vlan_id] = time.time()
    
  def get_num_flows_installed(self):
    monitored_link = self.controller.monitored_links.keys()[0]
    u_id = monitored_link[0]
    d_id = monitored_link[1]
    
    u_cnt = len(self.controller.flowTables[u_id])
    d_cnt = len(self.controller.flowTables[d_id])
    
    return u_cnt,d_cnt
    
   
  def update_u_node_results(self, pkt_cnt, vlan_id,start_proc_time):
    
    if self.curr_num_u_node_results >= self.num_monitored_flows:
      msg = "ERROR. PCountResults instance must be getting duplicate u_node query results at vlan=%s. Already have %s u_node results but only monitoring %s flows" % (vlan_id,self.curr_num_u_node_results,self.num_monitored_flows)
      raise appleseed.AppleseedError(msg)
    
    if self.u_node_count.has_key(vlan_id):
      curr_result = self.u_node_count[vlan_id]
      self.u_node_count[vlan_id] = curr_result + pkt_cnt
    else:
      self.u_node_count[vlan_id] = pkt_cnt
      self.first_pkt_time = time.time()
    
    self.curr_num_u_node_results += 1

    self.record_window_results(vlan_id,start_proc_time)   
    
  def update_d_node_results(self, pkt_cnt,start_proc_time):
    
    if self.d_node_count.has_key(self.curr_vlan_id):
      msg = "ERROR. PCountResults instance should not have a d_node_count value for vlan_id=%s.  Must be getting duplicate query results " % (self.curr_vlan_id)
      raise appleseed.AppleseedError(msg)
  
    self.d_node_count[self.curr_vlan_id] = pkt_cnt
    
    self.record_window_results(self.curr_vlan_id,start_proc_time)
    
  def record_window_results(self, vlan_id,start_proc_time):
    
    end_time = time.time()
    single_qresult_proc_time = end_time - start_proc_time
    self.single_run_proc_time+=single_qresult_proc_time
    
    if not self.d_node_count.has_key(vlan_id) or not self.u_node_count.has_key(vlan_id):
      return
    
    if self.curr_num_u_node_results != self.num_monitored_flows:
      return
    
    detected_drops = self.u_node_count[vlan_id] - self.d_node_count[vlan_id]
    
    if self.check_threshold(vlan_id, detected_drops):
      if IS_PCOUNT_EXP:
        
        self.total_controller_proc_time+=self.single_run_proc_time
        self.single_run_proc_time=0
        
        self.detect_total_pkt_dropped[vlan_id] = detected_drops
        total_packets = self.u_node_count[vlan_id]
        estimated_loss_ratio = 0
        if total_packets > 0:
          estimated_loss_ratio = float(float(detected_drops) / float(total_packets))
        self.estimated_loss_ratio[vlan_id] = estimated_loss_ratio
        time_btw_first_last_pkts = self.detect_time[vlan_id] - self.first_pkt_time
        self.total_time_btw_first_last_pkts+=time_btw_first_last_pkts
        print "\t result output for session %s" % (vlan_id)
        self.log_pcount_detect_time_results()
        self.log_pcount_results()
      else:
        #self.controller.turn_pcount_off = True
        self.controller.activate_backup_trees(self.monitored_link)
      
        self.detect_total_pkt_dropped[vlan_id] = detected_drops
        self.log_pcount_results()
    
    self.curr_num_u_node_results = 0
    self.curr_vlan_id += 1   # this means that the result for prev vlan must reach the controller before the next session is started
    
    self.check_window_sample_quota(vlan_id)
    
  def check_threshold(self, vlan_id, pkt_loss_cnt):
    """ Checks if the pkt_loss_cnt exceeds a threshold""" 
    if pkt_loss_cnt > PCOUNT_LOSS_THRESHOLD:
      self.detect_time[vlan_id] = time.time()
      self.total_detection_time_results[vlan_id] = self.detect_time[vlan_id] - self.window_start_time[vlan_id]
      return True
    return False
  
  def log_pcount_detect_time_results(self):
    """  record the time detected, and output the total detection time """
    w = csv.writer(open("ext/results/current/pcount-detections-f%s.csv" % (self.num_monitored_flows), "w"))
    w.writerow("#,window,num_monitor,loss_thresh,detected_drops,detect_time,est_loss_ratio")
    for session_num in range(1, self.curr_vlan_id + 1): 
      if self.detect_time.has_key(session_num):
        #detect_time = self.detect_time[session_num] - self.window_start_time[session_num]
        detect_time = self.total_detection_time_results[session_num]
        detected_drops = self.detect_total_pkt_dropped[session_num]
        estimated_loss_ratio = self.estimated_loss_ratio[session_num]
        w.writerow([self.window_size, self.num_monitored_flows, self.loss_threshold, detected_drops, detect_time, estimated_loss_ratio])
    
  def log_pcount_results(self):
  
    file_base = multicast.measure_pnts_file_str.split(".")[0]
    w = csv.writer(open("ext/results/current/%s-output.csv" % (file_base), "w"))
    if IS_PCOUNT_EXP:
      w = csv.writer(open("ext/results/current/pcount-sessions-w%s-j%s.csv" % (self.window_size,self.num_junk_flows), "a"))
      #w.writerow("#,session_num,window,num_monitor,u_count,d_count,detected_drops,est_loss_ratio")
    for session_num in range(1, self.curr_vlan_id + 1): 
      if self.detect_total_pkt_dropped.has_key(session_num):
        detected_drops = self.detect_total_pkt_dropped[session_num]
        u_count = self.u_node_count[session_num]
        d_count = self.d_node_count[session_num]
        estimated_loss_ratio = self.estimated_loss_ratio[session_num]
        u_cnt,d_cnt = self.get_num_flows_installed()
        expected_cnt = self.num_monitored_flows + self.num_junk_flows
        w.writerow([session_num, self.window_size, self.num_monitored_flows, u_count, d_count, detected_drops, estimated_loss_ratio,expected_cnt,u_cnt,d_cnt])

  def check_window_sample_quota(self,vlan_id):
    """ (1) check if enough samples taken, If yes: (2) stop pcount session, (3) compute the detect_time_mean and confidence interval + output to file (4) setup constructs for expts on next window size """
    if len(self.detect_time) < PCOUNT_SAMPLE_QUOTA:
      self.move_nxt_window_session = True
      return 
    
    # stop pcount session
    #self.controller.turn_pcount_off = True
  
    loss_ratio_mean = stats.computeMean(self.estimated_loss_ratio.values())
    loss_ratio_conf_interval = stats.computeConfInterval(self.estimated_loss_ratio.values(), 95)    
    
    detect_time_mean = stats.computeMean(self.total_detection_time_results.values())
    detect_time_conf_interval = stats.computeConfInterval(self.total_detection_time_results.values(), 95)
    
    # log the results
    num_runs = len(self.detect_time)
    total_packets = self.u_node_count[vlan_id]
    avg_time_btw_first_last_pkts = self.total_time_btw_first_last_pkts/(float(len(self.detect_time)))
    avg_proc_time = self.total_controller_proc_time/(float(len(self.detect_time)))
    
    window_results = [self.window_size, self.num_monitored_flows, num_runs, total_packets,detect_time_mean, detect_time_conf_interval[0], detect_time_conf_interval[1], loss_ratio_mean, loss_ratio_conf_interval[0], loss_ratio_conf_interval[1],avg_time_btw_first_last_pkts,avg_proc_time]
    
    if PCOUNT_DTIME_EXPT:
      window_results.append(PCOUNT_CURR_NUM_JUNKFLOWS)
    
    global pcount_window_detect_time_results
    pcount_window_detect_time_results.append(window_results)
    log_all_window_detect_time_results(self.window_size)
    
    #setup constructs for expts on next window size
    #log.debug("At time = %s, logging complete of w=%s results and controller.turn_pcount_off = %s" % (time.time(), self.window_size, self.controller.turn_pcount_off))
    
    self.move_nxt_expt_setting = True

def log_all_window_detect_time_results(window_size):
  loss_percent = int(PCOUNT_TRUE_LOSS_PERCENTAGE * 1)
  w = csv.writer(open("ext/results/current/pcount-loss-l%s-u%s.csv" % (loss_percent, PCOUNT_NUM_UNICAST_FLOWS), "w"))
  
  if PCOUNT_DTIME_EXPT:
    w = csv.writer(open("ext/results/current/pcount-dtimes-w%s-j%s.csv" % (window_size, PCOUNT_MAX_NUM_JUNKFLOWS), "w"))
  
  for row in pcount_window_detect_time_results:
    w.writerow(row)
    
  
  
    
