# @author: dpg/gyllstar/Dan Gyllstrom


""" Implements multicast.

This module contains helper functions called by the controller to implement multicast,
along with some data structures to create and manage multicast trees (Tree and PrimaryTree).

"""


import utils, appleseed,pcount
from Queue import Queue
from pox.lib.addresses import IPAddr,EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.core import core
from types import NoneType
from compiler.ast import nodes
log = core.getLogger("multicast")
import os


#################### Start of Hard-coded IP addresses and config files ####################
h1 = IPAddr("10.0.0.1")
h2 = IPAddr("10.0.0.2")
h3 = IPAddr("10.0.0.3")
h4 = IPAddr("10.0.0.4")
h5 = IPAddr("10.0.0.5")
h6 = IPAddr("10.0.0.6")
h7 = IPAddr("10.0.0.7")
h8 = IPAddr("10.0.0.8")
h9 = IPAddr("10.0.0.9")

mcast_ip_addr1 = IPAddr("10.10.10.10")
mcast_mac_addr = EthAddr("10:10:10:10:10:10") 
mcast_ip_addr2 = IPAddr("10.11.11.11")
mcast_mac_addr2 = EthAddr("11:11:11:11:11:11")
mcast_ip_addr3 = IPAddr("10.12.12.12")
mcast_mac_addr3 = EthAddr("12:12:12:12:12:12")

measure_pnts_file_str="measure-h6s10-1d-1p.csv"
#measure_pnts_file_str="measure-h9s6-2d-2p.csv"
#measure_pnts_file_str="measure-h6s9-1d-1p.csv"
#measure_pnts_file_str ="measure-h4s8-1d-1p.csv"
#measure_pnts_file_str="measure-h3s4-3d-1p.csv"
#measure_pnts_file_str="measure-h3s4-2d-1p.csv"
#measure_pnts_file_str="measure-h3s4-1p.csv"
#measure_pnts_file_str="measure-h3s3-2p.csv"
#measure_pnts_file_str="measure-h3s3-1p.csv"
#measure_pnts_file_str="measure-h3s3-2d-1p.csv"
#measure_pnts_file_str="measure-h3s2-2p.csv"
#measure_pnts_file_str="measure-h3s2-1p.csv"

mtree_file_str="mtree-h6s10-3t.csv"
#mtree_file_str="mtree-h6s9-2t.csv"
#mtree_file_str="mtree-h4s8-1t.csv"
#mtree_file_str="mtree-h3s4-1t.csv"
#mtree_file_str="mtree-h9s6-2t.csv"
#################### End of Hard-coded IP addresses and config files ####################


depracted_installed_mtrees=[] #list of multicast addresses with an mtree already installed

nodes = {} # node_id --> Node
edges = {} #(u,d) --> Edge

def enum(**enums):
    return type('Enum', (), enums)
  
Backup_Mode = enum(REACTIVE=1,PROACTIVE=2,MERGER=3)


def is_mcast_address(dst_ip_address,controller):
  return controller.mcast_groups.has_key(dst_ip_address)

def depracted_install_rewrite_dst_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,new_dst,controller):
  """ Creates a flow table rule that rewrites the multicast address in the packet to the IP address of a downstream host.  
  
  Keyword Arguments
  switch_id -- 
  nw_src -- IP address of source 
  ports -- dictionary of host to outport mapping
  nw_mcast_dst -- Multicast IP destination address
  new_dst -- the IP address(es) to overwrite the destination IP address.  Either a single IP address or list of IP addresses
  controller -- appleseed controller instance
  """
  msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
  msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
  
  if isinstance(new_dst,list):    # if multiple downstream hosts
    
    # this part is only executed if multiple addresses need to be rewriteen (works because OF switches execute actions in order, meaning that each copy of the packet
    # is output before the next destination address rewrite takes place)
    for dst in new_dst:
      action = of.ofp_action_nw_addr.set_dst(IPAddr(dst))
      msg.actions.append(action)
      
      new_mac_addr = controller.arpTable[switch_id][dst].mac
      l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
      msg.actions.append(l2_action)
      
      for prt in ports[dst]:  # probably don't need this loop
        msg.actions.append(of.ofp_action_output(port = prt))
      
  else:     # for single downstream host
    action = of.ofp_action_nw_addr.set_dst(IPAddr(new_dst))
    msg.actions.append(action)
    
    new_mac_addr = controller.arpTable[switch_id][new_dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    msg.actions.append(l2_action)
        
    for prt in ports:
      msg.actions.append(of.ofp_action_output(port = prt))
    
  utils.send_msg_to_switch(msg, switch_id)
  controller.cache_flow_table_entry(switch_id, msg)

def install_rewrite_dst_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,new_dst,switch_ports,controller):
  """ Creates a flow table rule that rewrites the multicast address in the packet to the IP address of a downstream host.  
  
  Keyword Arguments
  switch_id -- 
  nw_src -- IP address of source 
  ports -- dictionary of host to outport mapping
  nw_mcast_dst -- Multicast IP destination address
  new_dst -- the IP address(es) to overwrite the destination IP address.  Either a single IP address or list of IP addresses
  switch_ports -- the outports for any connected downstream switch in the tree
  controller -- appleseed controller instance
  """
  msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
  msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
  
  # add actions for the downstream switches 1st
  for prt in switch_ports:
    msg.actions.append(of.ofp_action_output(port = prt))
  
  if isinstance(new_dst,list):    # if multiple downstream hosts
    
    # this part is only executed if multiple addresses need to be rewriteen (works because OF switches execute actions in order, meaning that each copy of the packet
    # is output before the next destination address rewrite takes place)
    for dst in new_dst:
      action = of.ofp_action_nw_addr.set_dst(IPAddr(dst))
      msg.actions.append(action)
      
      new_mac_addr = controller.arpTable[switch_id][dst].mac
      l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
      msg.actions.append(l2_action)
      
      prt = ports[dst]  
      msg.actions.append(of.ofp_action_output(port = prt))
      
  else:     # for single downstream host
    action = of.ofp_action_nw_addr.set_dst(IPAddr(new_dst))
    msg.actions.append(action)
    
    new_mac_addr = controller.arpTable[switch_id][new_dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    msg.actions.append(l2_action)
        
    for prt in ports:
      msg.actions.append(of.ofp_action_output(port = prt))
    
  utils.send_msg_to_switch(msg, switch_id)
  controller.cache_flow_table_entry(switch_id, msg)
  
def install_basic_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,priority,controller):
  """ Install a flow table rule using the multicast destination address and list of outports  """
  msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
  msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
  
  for prt in ports:
    msg.actions.append(of.ofp_action_output(port = prt))
  
  if priority > 0:  # if the priority is negative we just take the default value
    msg.priority = priority
    
  utils.send_msg_to_switch(msg, switch_id)
  controller.cache_flow_table_entry(switch_id, msg)
  
def depracated_setup_mtree(nw_src,nw_mcast_dst,inport,controller):
  """ Hard-coded setup of mutlicast trees using the switch_id numbers. """
  
  msg = "depracted_setup_mtree() should not be called to install the primary trees.  Should be using mutlicast.compute_primary_trees()"
  raise appleseed.AppleseedError(msg)
  
  if nw_mcast_dst == mcast_ip_addr1:
    mtree1_switches = []
    primary_tree = []
    if len(controller.mcast_groups.keys()) == 2:
      mtree1_switches = [10,11,13,12]
      primary_tree = [(13,12),(12,11),(12,10)]
    else:
      mtree1_switches = [7,6,5,4]
      primary_tree = [(7,6),(6,4),(6,5)]
    
    controller.depracted_primary_trees[nw_mcast_dst] = primary_tree
    return depracated_setup_mtree1_flow_tables(nw_src, nw_mcast_dst, inport,mtree1_switches,controller)
  elif nw_mcast_dst == mcast_ip_addr2:
    mtree2_switches = []
    primary_tree = []
    if len(controller.mcast_groups.keys()) == 2:
      mtree2_switches = [10,14,15]
      primary_tree = [(15,14),(15,10)]
    
    controller.depracted_primary_trees[nw_mcast_dst] = primary_tree  #TODO REFACTOR !!!!!!!!!!!!!!!!!!!
    return depracated_setup_mtree2_flow_tables(nw_src, nw_mcast_dst, inport,mtree2_switches,controller)
  

# should really use self.mcast_groups to determine which hosts are a part of the multicast group and tree
# should have some way to determine which hosts are downstream from a given switch, rather than hard coding this  
def depracated_setup_mtree1_flow_tables(nw_src,nw_mcast_dst,inport,mtree_switches,controller):
  """ More hard-coding of the multicast trees.  Here we install the flow entries at each switch node """
  # mcast address = 10.10.10.10, src = 10.0.0.3, dst1=10.0.0.1, dst2 = 10.0.0.2
  # tree: 
  #       h1 -- s4
  #                \ s6 --- s7 --- h3              
  #       h2 -- s5 /
  
  
  # s7: install (src=10.0.0.3, dst = 10.10.10.10, outport)
  switch_id = mtree_switches[0]
  s7_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h1)
  install_basic_mcast_flow(switch_id, nw_src,s7_ports,nw_mcast_dst,controller)
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s7_ports,mcast_mac_addr)
  
  
  # s6: install (src=10.0.0.3, dst = 10.10.10.10, outport_list) or
  # s6: install (src=10.0.0.3, dst = 10.0.0.1, outport),  (src=10.0.0.3, dst = 10.0.0.6, outport) 
  switch_id = mtree_switches[1]
  h1_prts = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h1)
  h2_prts = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h2)
  s6_ports = h1_prts + h2_prts
  install_basic_mcast_flow(switch_id, nw_src, s6_ports, nw_mcast_dst,controller)
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s6_ports,mcast_mac_addr)
  
  
  
  # s5: rewrite destination address from 10.10.10.10 to h2 (10.0.0.2)
  switch_id = mtree_switches[2]
  s5_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h2)
  depracted_install_rewrite_dst_mcast_flow(switch_id, nw_src, s5_ports, nw_mcast_dst, h2,controller)
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s5_ports,mcast_mac_addr)
  controller.depracated_mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h2]
  
  # s4: rewrite destination address from 10.10.10.10 to h1 (10.0.0.1)
  switch_id = mtree_switches[3]
  s4_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h1)
  depracted_install_rewrite_dst_mcast_flow(switch_id, nw_src, s4_ports, nw_mcast_dst, h1,controller)  
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s4_ports,mcast_mac_addr) 
  controller.depracated_mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h1]
  
  global depracted_installed_mtrees
  depracted_installed_mtrees.append(nw_mcast_dst)
  
  u_switch_id,d_switch_ids = find_mcast_measure_points(nw_src,mcast_ip_addr1,controller)
  
  return u_switch_id, d_switch_ids

def depracated_setup_mtree2_flow_tables(nw_src,nw_mcast_dst,inport,mtree_switches,controller):
  """ More hard-coding of the multicast trees.  Here we install the flow entries at each switch node """
      
  # mcast address = 11.11.11.11, src = 10.0.0.4, dst1=10.0.0.2, dst2 = 10.0.0.7, dst3 = 10.0.0.8, dst4 = 10.0.0.5, dst5 = 10.0.0.6
  # tree: 
  #       h9
  #       h7 - \
  #       h8 -- s15
  #                \ s10 --- h4               
  #       h5 -- s14 /
  #       h6 /
  
  
  # s10: install (src=10.0.0.9, dst = 11.11.11.11, outport_list) 
  switch_id = mtree_switches[0]
  h8_prts = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h8)
  h6_prts = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h6)
  s10_ports = h8_prts + h6_prts
  install_basic_mcast_flow(switch_id, nw_src, s10_ports, nw_mcast_dst,controller)
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s10_ports,mcast_mac_addr)
  
  # s14: rewrite destination address from 11.11.11.11 to h5 and h6 
  switch_id = mtree_switches[1]
  #s14_ports = utils.find_nonvlan_flow_outport(self.flowTables,switch_id, nw_src, h5)
  #self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s14_ports, nw_mcast_dst, h5)
  #self.depracated_mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h5]
  h5_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h5)
  h6_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h6)
  s14_ports = {h5:h5_ports, h6:h6_ports}
  depracted_install_rewrite_dst_mcast_flow(switch_id, nw_src, s14_ports, nw_mcast_dst, [h5,h6],controller)
  controller.depracated_mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h5,h6]
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s14_ports,mcast_mac_addr)

  
  # s15: rewrite destination address from 11.11.11.11 to h2,h7, and h8 
  switch_id = mtree_switches[2]
  h7_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h7)
  h8_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h8)
  h9_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h9)
  #s15_ports = h7_ports + h8_ports + h9_ports
  s15_ports = {}
  s15_ports[h7] = h7_ports
  s15_ports[h8] = h8_ports
  s15_ports[h9] = h9_ports
  depracted_install_rewrite_dst_mcast_flow(switch_id, nw_src, s15_ports, nw_mcast_dst, [h7,h8,h9],controller)  
  #self._install_rewrite_dst_mcast_flow(switch_id, nw_src, s15_ports, nw_mcast_dst, [h7])  
  #self.depracated_mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h7]
  controller.depracated_mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h7,h8,h9]
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s15_ports,mcast_mac_addr) 
  
  global depracted_installed_mtrees
  depracted_installed_mtrees.append(nw_mcast_dst)
  
  u_switch_id,d_switch_ids = find_mcast_measure_points(nw_src,mcast_ip_addr2,controller)
  
  return u_switch_id, d_switch_ids


def find_mcast_measure_points(nw_src,mcast_ip_addr1,controller):
  
  for d_switch_id in controller.flow_measure_points.keys():
  
    for measure_pnt in controller.flow_measure_points[d_switch_id]:
      last_indx = len(measure_pnt) -1
    
      if measure_pnt[last_indx-1] == nw_src and measure_pnt[last_indx] == mcast_ip_addr1:
        dstream_switches = list()
        dstream_switches.append(d_switch_id)
        dstream_switches = dstream_switches + measure_pnt[0:last_indx-2]
        
        return measure_pnt[last_indx-2],dstream_switches  #returns the upstream switch id 
    
  return -1,-1

def generate_multicast_groups(controller):
  """ Temporary solution is just use the multicast groups read from a text file (see utils.read_mtree_file).  Would like to generate multicast groups w/ a random process.
      
      Currently this a no-op as the multicast groups are already read from a text file.
  """
  
  # considering all end_hosts, generate some random multicast groups
  
  # add each multicast group to controller.mcast_groups
  
def compute_primary_trees(controller):
  """ In the short-term the primary trees are hard-coded.  This is where the code for computing the Steiner Arboresence approxiation goes. """
  num_switches = len(core.openflow_discovery._dps)
  
  for mcast_addr in controller.mcast_groups.keys():
    
    end_hosts = controller.mcast_groups[mcast_addr]   # this is the root and all terminal nodes
    root = end_hosts[0]
    terminal_hosts = end_hosts[1:]
    
    #some check here for # of switches
    edges = []

    # some temporary hard-coding going on here 
    if mcast_addr == mcast_ip_addr1:
      if num_switches == 4 and len(end_hosts) == 3: #H3S4
        edges = [(3,7),(7,6),(6,4),(6,5),(4,1),(5,2)]
      elif num_switches == 6 and len(end_hosts) == 3: #H9S6
        edges = [(3,10),(10,11),(11,12),(11,13),(12,1),(13,2)]
      elif num_switches == 8 and len(end_hosts) == 4: #H4S8
        edges = [(1,5),(5,6),(6,7),(6,8),(8,9),(8,10),(7,2),(9,3),(10,4)]
      elif num_switches == 9 and len(end_hosts) == 4: #H6S9
        edges = [(1,7),(7,8),(8,9),(8,10),(10,11),(10,12),(9,2),(11,3),(12,4)]
      elif num_switches == 10 and len(end_hosts) == 4: #H6S10
        edges = [(1,7),(7,8),(8,9),(8,10),(10,11),(10,12),(9,2),(11,3),(12,4)]
      else:
        msg = "should be 4,6,8, or 9 switches in topology when using the hard-coded multicast address %s, but %s switches are present." %(mcast_ip_addr2,num_switches)
        log.error(msg)
        raise appleseed.AppleseedError(msg)
    elif mcast_addr == mcast_ip_addr2:
      if num_switches == 6 and len(end_hosts) == 6:  #H9S6
        edges = [(4,10),(10,14),(10,15),(14,5),(14,6),(15,7),(15,8),(15,9)]
      elif num_switches == 9 and len(end_hosts) == 5: #H6S9
        edges = [(5,7),(7,8),(8,9),(8,10),(10,11),(10,12),(12,15),(9,2),(11,3),(12,4),(15,6)]
      elif num_switches == 10 and len(end_hosts) == 5: #H6S10
        edges = [(5,7),(7,8),(8,9),(8,10),(10,11),(10,12),(12,15),(9,2),(11,3),(12,4),(15,6)]
      else:
        msg = "should be 6 or 9 switches in topology when using the hard-coded multicast address %s, but %s switches are present." %(mcast_ip_addr2,num_switches)
        log.error(msg)
        raise appleseed.AppleseedError(msg)
    elif mcast_addr == mcast_ip_addr3:
      if num_switches == 10 and len(end_hosts) == 4: #H6S10
        edges = [(2,9),(9,16),(16,10),(10,11),(10,12),(12,15),(11,3),(12,4),(15,6)]
    data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
    tree = PrimaryTree(**data)
    
    controller.primary_trees.append(tree)

def get_node(node_id):
  """ Either create a new Node object or retrieve one if it already exists in nodes """
  if nodes.has_key(node_id):
    return nodes[node_id]
  
  switch_ids = core.openflow_discovery._dps
  min_switch_id = min(switch_ids)
  is_host = False  
  if node_id < min_switch_id:  # with Mininet hosts have the smallest id numbers
    is_host = True
  
  return Node(node_id,is_host)
  
def mark_tree_edges(controller):
  """ Traverse the links of each tree and mark that the tree uses that edge. """
  for tree in controller.primary_trees:
    for edge_id in tree.edges:
      edge = edges[edge_id]
      edge.trees.add(tree.id)
   
def full_overlap(tree_id,in_tag,in_set,d_node,d_link,outport):
  """ Check if full overlap downstream and if so apply keep_tag """   
  if in_tag == None or len(in_set) < 2: return False
  if in_set == d_link.trees and d_link.tag == None:  # only need to process for one of the trees using d_link
    print "\t\t Full overlap at n%s: handling T%s at %s:  %s" %(d_node.id,tree_id,d_link,in_set)
    d_link.tag = in_tag
    d_node.update_keep_tags(d_link.trees_hash_key,in_tag,outport)
    return True
  elif in_set == d_link.trees:
    print "\t\t Full overlap at n%s for T%s link %s: %s, but skipping because already updated indices when processing previous trees." %(d_node.id,tree_id,d_link,in_set)
    return True
  return False
 
 
def tag_upstream(tree_id,u_node,u_link,in_tag,in_set,d_node,d_link,outport):
  """ Try to see if we can apply the tag at 'u'.  This is messy!!  """
  if not u_node.is_host and len(in_set) == 1 and len(d_link.trees) > 1:
    # check that all other d_link trees are not using in a tag for an incoming link to 'd'.  if this is the case, then we don't tag_upstream
    for tid in d_link.trees:
      if tid == tree_id: continue
      match = False
      for in_link in d_node.in_links:
        if in_link == u_link: continue
        if len(in_link.trees) == 1 and tid in in_links.trees:
          match = True
          break
      if match == False:
        return False
    
    if in_tag == None:
      print "\t\twrite tag upstream, keep downstream"
      tag = -1
      if d_link.tag != None:
        tag = d_link.tag
      else: 
        new_tag = 11
        tag = new_tag
      
      u_port = controller.adjacency[(u_node.id,d_node.id)]
      u_node.update_new_tags(u_link.trees_hash_key,tag,u_port)
      u_link.tag = tag
      d_link.tag = tag
      d_node.update_keep_tags(u_link.trees_hash_key,tag,outport)
      return True
    elif d_node.keep_tags.has_key(u_link.trees_hash_key):
      print "keep tags"
      d_link.tag = in_tag
      d_node.update_keep_tags(u_link.trees_hash_key,in_tag,outport)
      return True
    else:
      msg = "error when trying to apply tag at the upstream node"
      raise appleseed.AppleseedError(msg)
  return False

def new_merge_set(tree_id,u_node,u_link,in_tag,in_set,d_node,d_link,outport):
  """ Check a new merge set is formed.  If yes, process and return True.  Otherwise return False """  
  if len(d_link.trees) == 1: return False
  if d_link.tag != None:    # because a tree processed earlier has already handled the tagging
    print "\t\t New merge set at n%s: %s already has a tag (%s) for the new merge set (%s) so reusing this tag. " %(d_node.id,d_link,d_link.tag,d_link.trees) 
    return True  
  
  #if tag_upstream(tree_id, u_node, u_link, in_tag, in_set, d_node, d_link, outport):    # may want to skip this because it's ugly
  #  return True
  
  # (2) since we can't apply tag upstream, we have to add a new tag at 'd'
  if d_node.new_tags.has_key(d_link.trees_hash_key): # already processed a link with merge set S so just reusing this tag
    print "\t\t New merge set at n%s: another out-link at n%s has the same set of trees (%s) using this tag %s for %s" %(d_node.id,d_node.id,d_link.trees_hash_key,d_node.new_tags[d_link.trees_hash_key][0],d_link)
    d_link.tag = d_node.new_tags[d_link.trees_hash_key][0]
    d_node.update_new_tags(d_link.trees_hash_key,d_link.tag,outport)
  else:
    print "\t\t New merge set at n%s: generate new tag T%s,%s" %(d_node.id,tree_id,d_link) 
    new_tag = 00
    d_node.update_new_tags(d_link.trees_hash_key,new_tag,outport)
    d_link.tag = new_tag
    
  return True
  
def no_merge(tree_id,d_node,d_link,outport):
  """ Process a single flow """ 
  print "\t\t no merge: T%s at %s" %(tree_id,d_link) 
  d_node.update_no_tags(tree_id,outport)
  
def create_node_tags(controller,tree_id,u_link,d_node):
  """ u --> {d1,d2, ...}.  We are at 'u' and looking at the outlink of each d1, d2, ... """
  for d_link in d_node.out_links:
    if not tree_id in d_link.trees: continue
    print "\t (%s,%s) vs. (%s,%s)" %(u_link.upstream_node.id,u_link.downstream_node.id,d_link.upstream_node.id,d_link.downstream_node.id)
    
    outport = controller.adjacency[(d_link.upstream_node.id,d_link.downstream_node.id)]
    if full_overlap(tree_id,u_link.tag,u_link.trees,d_node,d_link,outport): 
      continue
    
    # if we've made it here then we do not have a full_overlap case so need to add an existing tag the remove list
    if u_link.tag != None:
      d_node.update_remove_tags(tree_id,u_link.tag,outport)
      print "\t\t Remove tag at n%s for %s and old-set=%s" %(d_node.id,d_link,u_link.trees)
      
    if new_merge_set(tree_id,u_link.upstream_node,u_link,u_link.tag,u_link.trees,d_node,d_link,outport): 
      continue
    else:
      no_merge(tree_id,d_node,d_link,outport)
    
    #print "process (u,d_j, (u,d_j), (d_j,e_i)"  
      
def create_single_tree_tagging_indices(controller,tree_id,root_node):
  """  Do a BFS search of tree and determine the new_tag, keep_tag, and remove_tag indices we use to later to create the flow entry rules. """
  print "\nTREE %s-----------------------------------------------------------------" %(tree_id)
  q = Queue()
  q.put(root_node)
  visited = set()
  while not q.empty():
    node = q.get()
    visited.add(node)
    print "At n%s" %(node.id)
    
    for u_link in node.out_links:
      if not tree_id in u_link.trees: continue
      d_node = u_link.downstream_node
      if d_node.is_host or d_node in visited: continue
      
      q.put(d_node)
      create_node_tags(controller,tree_id, u_link, d_node)
  print "----------------------------------------------------------------------------\n"
  
def create_tagging_rules(controller):
  """ For each tree do a BFS. """  
  for tree in controller.primary_trees:
    root_id = find_node_id(tree.root_ip_address)
    root_node = nodes[root_id]
    create_single_tree_tagging_indices(controller,tree.id,root_node)
  
def create_merged_primary_tree_flows(controller):
  """ Merger Algorithm for primary trees """
  
  create_node_edge_objects(controller)
  
  mark_tree_edges(controller)
  
  create_tagging_rules(controller)      
      
  print "\n -------------------------------------------------------------------------------------------------------" 
  print nodes
  print " -------------------------------------------------------------------------------------------------------"
  os._exit(0)
  
def create_node_edge_objects(controller):
  """ Merger Algorithm for primary trees """
  
  # Switches: create new or retrieve existing, Edges: create new .  
  
  # create nodes and edges
  for edge in controller.adjacency.keys():
    u_id = edge[0]
    d_id = edge[1]
    
    if edges.has_key((u_id,d_id)):    # already processed edge
      continue

    u = get_node(u_id) # create new or return existing
    d = get_node(d_id)
    
    ud = Edge() 
    ud.upstream_node = u
    ud.downstream_node = d
    du = Edge()
    du.upstream_node = d
    du.downstream_node = u
    
    u.out_links.add(ud)
    u.in_links.add(du)
    d.in_links.add(ud)
    d.out_links.add(du)
    
    global nodes, edges
    nodes[u_id] = u
    nodes[d_id] = d
    edges[(u_id,d_id)]= ud
    edges[(d_id,u_id)] = du
  
  # need to do this because Node.trees is a set and sets are not hashable.
  for edge in edges.values():
    edge.generate_trees_hash_key()
    
def install_all_trees(controller):
  """  (1) Compute and install the primary trees. 
       (2) Triggers a pcount session after a 5 second delay (using a timer)
       (3) Precompute backup trees
  
   """
  generate_multicast_groups(controller)
  
  compute_primary_trees(controller)
  
  if controller.merger_optimization:
    create_merged_primary_tree_flows(controller)
  
  for tree in controller.primary_trees:
    tree.install()
    print "============== installed tree = %s" %(tree.mcast_address)
    try:
      u_switch_id, d_switch_ids = pcount.get_tree_measure_points(tree.root_ip_address,tree.mcast_address,controller)
      core.callDelayed(pcount.PCOUNT_CALL_FREQUENCY,pcount.start_pcount_thread,u_switch_id, d_switch_ids,tree.root_ip_address,tree.mcast_address,controller)
    except appleseed.AppleseedError:
      log.info("found no flow measurement points for flow = (%s,%s) but continuing operation becasue it assumed that no PCount session is wanted for this flow." %(tree.root_ip_address,tree.mcast_address))
    
  msg = " ================= Primary Trees Installed ================="
  log.info(msg)
  print "\t\t %s" %(msg)
  
  compute_backup_trees(controller)
  

def compute_backup_trees(controller):
  """ Short-term: hard-coded backup tree + assume only one primary tree"""
  num_switches = len(core.openflow_discovery._dps)
  
  for primary_tree in controller.primary_trees:  # self-note: would require another loop to precompute backups for ALL links
    end_hosts = controller.mcast_groups[primary_tree.mcast_address]   # this is the root and all terminal nodes
    backup_tree_edges = []
    backup_edge = ()
  
    if primary_tree.mcast_address == mcast_ip_addr1:
      if num_switches == 8 and len(end_hosts) == 4: #H4S8
        backup_tree_edges = [(1,5),(5,11),(11,7),(11,12),(12,10),(12,9),(7,2),(9,3),(10,4)]
        backup_edge = (5,6)
      if num_switches == 9 and len(end_hosts) == 4: #H6S9
        backup_tree_edges = [(1,7),(7,13),(13,9),(13,14),(14,12),(14,11),(9,2),(11,3),(12,4)]
        backup_edge = (7,8)
    if primary_tree.mcast_address == mcast_ip_addr2:
      if num_switches == 9 and len(end_hosts) == 5: #H6S9
        backup_tree_edges = [(5,7),(7,13),(13,9),(13,14),(14,12),(14,11),(12,15),(9,2),(11,3),(12,4),(15,6)]
        backup_edge = (7,8)
    
    if len(backup_tree_edges) == 0:
      msg = "no backup trees edges are specified for T%s" %(primary_tree.id)
      log.info(msg)
      continue
    
    data = {"edges":backup_tree_edges, "mcast_address":primary_tree.mcast_address, "root":primary_tree.root_ip_address, "terminals":primary_tree.terminal_ip_addresses, 
            "adjacency":controller.adjacency, "controller":controller,"primary_tree":primary_tree,"backup_edge":backup_edge}
    backup_tree = BackupTree(**data)
    primary_tree.backup_trees.append(backup_tree) 
    
    if controller.backup_tree_mode == Backup_Mode.PROACTIVE:
      backup_tree.preinstall()
  
def find_node_id(ip_address):
  """ Takes the IP Address of a node and returns its node id number. 
  
  We asssume that the last value in IP address corresponds to the node id. For example, IP address of
  10.0.0.8 has node id of 8"
  """
  ip_str = str(ip_address)
  parse = ip_str.split(".")
  id = parse[-1]
  return int(id) 
     

def find_affected_primary_trees(primary_trees,failed_link):
  """ Find all primary trees using the given failed_link and return as a list"""
  affected_trees = []
  
  for tree in primary_trees:
    if failed_link in tree.edges:
      affected_trees.append(tree)
      
  return affected_trees
      

#####################################################################################################

class MulticastTree ():
  """ Multicast Tree Abstraction """
  
  def __init__(self,**kwargs):
    self.edges = kwargs["edges"]
    self.mcast_address = kwargs["mcast_address"]
    self.root_ip_address = kwargs["root"]
    self.terminal_ip_addresses = kwargs["terminals"]
    self.adjacency = kwargs["adjacency"]
    self.controller = kwargs["controller"]
    self.id = find_node_id(self.root_ip_address)
    
  def find_ip_address(self,id):
    
    for ip in self.terminal_ip_addresses:
      if find_node_id(ip) == id:
        return ip
    
  
  def find_downstream_neighbors(self,node_id):
    
    neighbors = []
    for edge in self.edges:
      if edge[0] == node_id:
        neighbors.append(edge[1])
    
    return neighbors
  
  def install_leaf_flow(self,node_id):
    """ The node_id must have at least one connected host.  It is possible that a neighbor is a switch (rather than a host)."""
    neighbors = self.find_downstream_neighbors(node_id)
    
    host_to_port_map= {}
    switch_ports = []
    dst_addresses = []
    for neighbor in neighbors:
      
      if self.is_host(neighbor):
        ip_addr = self.find_ip_address(neighbor)
        dst_addresses.append(ip_addr)
        outport = self.adjacency[(node_id,neighbor)]
        
        if isinstance(outport, NoneType):
          msg = ("Tree %s want to add install flow for link (%s,%s) which does is not the adjacency list.  It likely that the (%s,%s) was not\n" 
            "discovered during intialization or the the tree computation algorithm added a non-existent link." %(self,node_id,neighbor,node_id,neighbor))
          log.error("%s. Exiting Program." %(msg))
          raise appleseed.AppleseedError(msg)  
        
        host_to_port_map[ip_addr] = outport
      
      else:
        outport = self.adjacency[(node_id,neighbor)]
        switch_ports.append(outport)
    
    install_rewrite_dst_mcast_flow(node_id, self.root_ip_address, host_to_port_map, self.mcast_address, dst_addresses, switch_ports,self.controller)
    
  def determine_flow_priority(self,node_id):
    """ Determine the priority of other entries corresponding to this flow  and set the priority to be 1 greater than the existing max priority"""
    highest_priority = -1
    for flow_entry in self.controller.flowTables[node_id]:
      if flow_entry.match.nw_src == self.root_ip_address and flow_entry.match.nw_dst == self.mcast_address:
        if flow_entry.priority > highest_priority:
          highest_priority = flow_entry.priority

    return highest_priority + 1
  
  def install_nonleaf_flow(self,node_id,set_priority_flag=False):
    neighbors = self.find_downstream_neighbors(node_id)
    
    outports = []
    for d_switch in neighbors:
      outport = self.adjacency[(node_id,d_switch)]
      
      if isinstance(outport, NoneType):
        msg = ("Tree %s want to add install flow for link (%s,%s) which does is not the adjacency list.  It likely that the (%s,%s) was not\n" 
          "discovered during intialization or the the tree computation algorithm added a non-existent link." %(self,node_id,d_switch,node_id,d_switch))
        log.error("%s. Exiting Program." %(msg))
        raise appleseed.AppleseedError(msg)
      
      outports.append(outport)
      
    # get the priority of other entries corresponding to this flow  
    priority = -1
    if set_priority_flag:
      priority = self.determine_flow_priority(node_id)
      
    #print "called install_basic_mcast_flow(s%s,root=%s,outport=%s,mcast_addr=%s,priority=%s)" %(node_id,self.root_ip_address,outports,self.mcast_address,priority)
    install_basic_mcast_flow(node_id,self.root_ip_address,outports,self.mcast_address,priority,self.controller)
    
  def compute_node_levels(self):
    """ Finds the level in the tree each node occupies and returns a list of lists contain this info"""
    level = 0
    id = find_node_id(self.root_ip_address)
    upstream_ids = [id]
    node_levels = [] 
    while len(upstream_ids)>0:
      node_levels.append(upstream_ids)
      downstream_ids = []
      for id in upstream_ids:
        downstream = self.find_downstream_neighbors(id)
        downstream_ids = downstream_ids + downstream
      level+=1
      upstream_ids = downstream_ids
    return node_levels
  
  def is_leaf_node(self,node_id):
    """ Return True if the node_id is a leaf node.  We consider a leaf node one directly connected with a end-host. """
    neighbors = self.find_downstream_neighbors(node_id)
    
    for id in neighbors:
      if self.find_ip_address(id) in self.terminal_ip_addresses:
        return True
    return False 
  
  def is_host(self,node_id):
    if self.find_ip_address(node_id) in self.terminal_ip_addresses:
      return True   
    return False
    
class PrimaryTree (MulticastTree):
  
  def __init__(self, **kwargs):
    MulticastTree.__init__(self, **kwargs)
    self.backup_trees = []  
    
    
  def install(self):
    
    if len(self.edges) == 0:
      msg = "Error.  Trying to install a primary tree with no edges.  Exiting program."
      log.error(msg)
      raise appleseed.AppleseedError(msg)
    
    # (1) order nodes from top to bottom
    node_levels = self.compute_node_levels()
    
    # (2) install each flow entry (bottom-up) -- skip the root and leaf nodes because these are hosts and no flow entry is needed
    leaf_level = len(node_levels)-2
    
    for level in range(leaf_level,0,-1):
      for id in node_levels[level]:
        if self.is_host(id): 
          continue
        if self.is_leaf_node(id):
          self.install_leaf_flow(id)
        else:
          self.install_nonleaf_flow(id)
    
  def cleanup_stale_flows(self):
    """ Remove primary tree flows made obsolete because the backup tree was activated."""
    msg = "Primary.cleanup_stale_flows() is not yet implemented"
    log.info(msg)
    
  def __str__(self):
    return "Tree %s, %s-->%s" %(self.id,self.mcast_address,self.edges)
  
  def __repr__(self):
    return self.__str__()


class BackupTree (MulticastTree):

  def __init__(self, **kwargs):
    MulticastTree.__init__(self, **kwargs)
    self.primary_tree = kwargs["primary_tree"]    # pointer to it's primary tree
    self.backup_edge = kwargs["backup_edge"]      # the edge the tree is backup for
    self.nodes_to_signal = []  # sorted bottom up (i.e., most downstream node is entry 0)
    self.compute_nodes_to_signal()
    
  def compute_nodes_to_signal(self):
    """ Precompute the set of nodes we need to signal after a link failure. 
    
    Find the set of edges in the backup tree but not in the primary tree, and save the upstream node id of each edge
    """
    if len(self.edges) == 0:
      msg = "Error.  Backup tree has no edges.  Exiting program."
      log.error(msg)
      raise appleseed.AppleseedError(msg)
    
    unique_edges =  [link for link in self.edges if link not in self.primary_tree.edges]
    upstream_nodes = set([link[0] for link in unique_edges])
    self.nodes_to_signal = self.sort_nodes_bottom_up(upstream_nodes)
  
  def sort_nodes_bottom_up(self,unsort_node_list):  
    """ Sort the list of nodes bottom up and return a new list """
    node_levels = self.compute_node_levels()
    bottom_up = []
    
    leaf_level = len(node_levels)-2
    for level in range(leaf_level,-1,-1):
      for id in node_levels[level]:
        if id in unsort_node_list:
          bottom_up.append(id)
    
    return bottom_up
  
  def preinstall(self):
    """ Used by the Proactive Algorithm to preinstall flow entries.  Signal all nodes in 'self.nodes_to_signal' except the most upstream node"""
    for node_id in self.nodes_to_signal:
      if self.is_leaf_node(node_id):
        self.install_leaf_flow(node_id)
      else:
        is_most_upstream = (node_id == self.nodes_to_signal[-1])
        if is_most_upstream:
          continue
        self.install_nonleaf_flow(node_id)
        
  def reactive_install(self):
    """ Reactive Algorithm.  Signal switches bottom up to activate backup tree."""
    for node_id in self.nodes_to_signal:
      if self.is_leaf_node(node_id):
        self.install_leaf_flow(node_id)
      else:
        is_most_upstream = (node_id == self.nodes_to_signal[-1])
        self.install_nonleaf_flow(node_id,is_most_upstream)
  
  
  def activate(self):
    """ Activate the backup tree.  For Proactive, signal the most upstream node.  For reactive signal all relevant nodes bottom up. """
   
    if self.controller.backup_tree_mode == Backup_Mode.REACTIVE:
      self.reactive_install()
    elif self.controller.backup_tree_mode == Backup_Mode.PROACIVE:    # only need signal the most upstream node
      most_upstream_node = self.nodes_to_signal[-1]
      is_most_upstream = True
      self.install_nonleaf_flow(node_id,is_most_upstream)
    
    msg = "============== Backup Tree Activated =============="
    log.info(msg)
    print msg
    
    self.primary_tree.cleanup_stale_flows()
    # TODO: clean up == delete old flows
    
    
    
  def __str__(self):
    unique_edges =  [link for link in self.edges if link not in self.primary_tree.edges]
    return "(%s,%s) --> unique-edges: %s" %(self.mcast_address,self.backup_edge,unique_edges)
  
  def __repr__(self):
    return self.__str__()

class Edge ():
  
  def __init__(self):
    self.trees = set()
    self.tag = None
    self.upstream_node = None
    self.downstream_node = None
    self.trees_hash_key = None
    
  def generate_trees_hash_key(self):
    """ Workaround because set() is not a hashable type"""
    str = ""
    for id in self.trees:
      str += "T%s," %(id)
    
    self.trees_hash_key = str
    
  def __str__(self):
    tree_strs = []
    for id in self.trees:
      str = "T%s" %(id)
      tree_strs.append(str)
    return "(%s,%s), %s " %(self.upstream_node.id,self.downstream_node.id,tree_strs)
  
  def __repr__(self):
    return self.__str__()    
    
class Node ():
  
  def __init__(self,id,is_host):
    self.id = id
    self.is_host = is_host
    self.in_links = set()
    self.out_links = set()
    self.keep_tags = {}  # (set of trees) --> [tag, outport1, outport2, ...]
    self.remove_tags = {}  # (tree_id) --> [tag, outport1, outport2, ...]
    self.new_tags = {} # (set of trees) --> [tag, outport1, outport2, ...]
    self.no_tags = {} # (tree id) --> [outport1, outport2, ...] 
    # TODO: Watch out later for stale dict entries because we are using the (set of trees) as the hash key, and this value can change as links fail
  
  def update_no_tags(self,tree_id,outport):
    if self.no_tags.has_key(tree_id):
      val_list = self.no_tags[tree_id]
      val_list.append(outport)
    else:
      val_list = [outport]
      self.no_tags[tree_id] = val_list
  
  def update_remove_tags(self,tree_id,in_tag,outport):
    if self.remove_tags.has_key(tree_id):
      val_list = self.remove_tags[tree_id]
      val_list.append(outport)
    else:
      val_list = [in_tag,outport]
      self.remove_tags[tree_id] = val_list
  
  def update_new_tags(self,trees,tag,outport):
    if self.new_tags.has_key(trees):
      val_list = self.new_tags[trees]
      val_list.append(outport)
    else:
      val_list = [tag,outport]
      self.new_tags[trees] = val_list  
          
  def update_keep_tags(self,trees,in_tag,outport):
    if self.keep_tags.has_key(trees):
      val_list = self.keep_tags[trees]
      val_list.append(outport)
    else:
      val_list = [in_tag,outport]
      self.keep_tags[trees] = val_list
  
  def __str__(self):
    type = "s"
    if self.is_host: type = "h"
    return "%s%s; in = %s; out=%s " %(type,self.id,self.in_links,self.out_links)
  
  def __repr__(self):
    return self.__str__()    
    