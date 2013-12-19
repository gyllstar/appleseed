# @author: dpg/gyllstar/Dan Gyllstrom


""" Implements multicast.

This module contains helper functions called by the controller to implement multicast,
along with some data structures to create and manage multicast trees (Tree and PrimaryTree).

"""


from Queue import Queue
from pox.core import core
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from types import NoneType
import os
import pox.openflow.libopenflow_01 as of
import utils
import appleseed
import pcount_all
import time
log = core.getLogger("multicast")


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
dummy_mac_addr = EthAddr("99:99:99:99:99:99")

#measure_pnts_file_str="measure-h6s10-1d-1p.csv"
#measure_pnts_file_str="measure-h9s6-2d-2p.csv"
measure_pnts_file_str="measure-h6s9-1d-1p.csv"
#measure_pnts_file_str ="measure-h4s8-1d-1p.csv"
#measure_pnts_file_str="measure-h3s4-3d-1p.csv"
#measure_pnts_file_str="measure-h3s4-2d-1p.csv"
#measure_pnts_file_str="measure-h3s4-1p.csv"
#measure_pnts_file_str="measure-h3s3-2p.csv"
#measure_pnts_file_str="measure-h3s3-1p.csv"
#measure_pnts_file_str="measure-h3s3-2d-1p.csv"
#measure_pnts_file_str="measure-h3s2-2p.csv"
#measure_pnts_file_str="measure-h3s2-1p.csv"

#mtree_file_str="mtree-h6s10-3t.csv"
mtree_file_str="mtree-h6s9-2t.csv"
#mtree_file_str="mtree-h4s8-1t.csv"
#mtree_file_str="mtree-h3s4-1t.csv"
#mtree_file_str="mtree-h9s6-2t.csv"
#################### End of Hard-coded IP addresses and config files ####################


depracted_installed_mtrees=[] #list of multicast addresses with an mtree already installed

garbage_collection_total = 0
nodes = {} # node_id --> Node
edges = {} #(u,d) --> Edge
default_ustar_backup_flow_priority= of.OFP_DEFAULT_PRIORITY + 1
new_tags = [EthAddr("66:66:66:66:66:39"),EthAddr("66:66:66:66:66:38"),EthAddr("66:66:66:66:66:37"),EthAddr("66:66:66:66:66:36"),EthAddr("66:66:66:66:66:35"),EthAddr("66:66:66:66:66:34"),
            EthAddr("66:66:66:66:66:33"),EthAddr("66:66:66:66:66:32"),EthAddr("66:66:66:66:66:31"),EthAddr("66:66:66:66:66:30"),EthAddr("66:66:66:66:66:29"),EthAddr("66:66:66:66:66:28"),
            EthAddr("66:66:66:66:66:27"),EthAddr("66:66:66:66:66:26"),EthAddr("66:66:66:66:66:25"),EthAddr("66:66:66:66:66:24"),EthAddr("66:66:66:66:66:23"),EthAddr("66:66:66:66:66:22"),
            EthAddr("66:66:66:66:66:21"),EthAddr("66:66:66:66:66:20"),EthAddr("66:66:66:66:66:19"),EthAddr("66:66:66:66:66:18"),EthAddr("66:66:66:66:66:17"),EthAddr("66:66:66:66:66:16"),
            EthAddr("66:66:66:66:66:15"),EthAddr("66:66:66:66:66:14"),EthAddr("66:66:66:66:66:13"),EthAddr("66:66:66:66:66:12"),EthAddr("66:66:66:66:66:11"),EthAddr("66:66:66:66:66:10")]

backup_tree_ids = [EthAddr("BB:BB:BB:BB:BB:39"),EthAddr("BB:BB:BB:BB:BB:38"),EthAddr("BB:BB:BB:BB:BB:37"),EthAddr("BB:BB:BB:BB:BB:36"),EthAddr("BB:BB:BB:BB:BB:35"),EthAddr("BB:BB:BB:BB:BB:34"),
            EthAddr("BB:BB:BB:BB:BB:33"),EthAddr("BB:BB:BB:BB:BB:32"),EthAddr("BB:BB:BB:BB:BB:31"),EthAddr("BB:BB:BB:BB:BB:30"),EthAddr("BB:BB:BB:BB:BB:29"),EthAddr("BB:BB:BB:BB:BB:28"),
            EthAddr("BB:BB:BB:BB:BB:27"),EthAddr("BB:BB:BB:BB:BB:26"),EthAddr("BB:BB:BB:BB:BB:25"),EthAddr("BB:BB:BB:BB:BB:24"),EthAddr("BB:BB:BB:BB:BB:23"),EthAddr("BB:BB:BB:BB:BB:22"),
            EthAddr("BB:BB:BB:BB:BB:21"),EthAddr("BB:BB:BB:BB:BB:20"),EthAddr("BB:BB:BB:BB:BB:19"),EthAddr("BB:BB:BB:BB:BB:18"),EthAddr("BB:BB:BB:BB:BB:17"),EthAddr("BB:BB:BB:BB:BB:16"),
            EthAddr("BB:BB:BB:BB:BB:15"),EthAddr("BB:BB:BB:BB:BB:14"),EthAddr("BB:BB:BB:BB:BB:13"),EthAddr("BB:BB:BB:BB:BB:12"),EthAddr("BB:BB:BB:BB:BB:11"),EthAddr("BB:BB:BB:BB:BB:10"),
            EthAddr("BB:BB:BB:BB:BB:09"),EthAddr("BB:BB:BB:BB:BB:08"),EthAddr("BB:BB:BB:BB:BB:07"),EthAddr("BB:BB:BB:BB:BB:06"),EthAddr("BB:BB:BB:BB:BB:05"),EthAddr("BB:BB:BB:BB:BB:04"),
            EthAddr("BB:BB:BB:BB:BB:03"),EthAddr("BB:BB:BB:BB:BB:02"),EthAddr("BB:BB:BB:BB:BB:01")]


tree_default_tags = {1:EthAddr("AA:AA:AA:AA:AA:01"),2:EthAddr("AA:AA:AA:AA:AA:02"),3:EthAddr("AA:AA:AA:AA:AA:03"),4:EthAddr("AA:AA:AA:AA:AA:04"),5:EthAddr("AA:AA:AA:AA:AA:05"),6:EthAddr("AA:AA:AA:AA:AA:06"),
                     7:EthAddr("AA:AA:AA:AA:AA:07"),8:EthAddr("AA:AA:AA:AA:AA:08"),9:EthAddr("AA:AA:AA:AA:AA:09"),10:EthAddr("AA:AA:AA:AA:AA:10"),11:EthAddr("AA:AA:AA:AA:AA:11"),12:EthAddr("AA:AA:AA:AA:AA:12"),
                     13:EthAddr("AA:AA:AA:AA:AA:13"),14:EthAddr("AA:AA:AA:AA:AA:14"),15:EthAddr("AA:AA:AA:AA:AA:15"),16:EthAddr("AA:AA:AA:AA:AA:16"),17:EthAddr("AA:AA:AA:AA:AA:17"),18:EthAddr("AA:AA:AA:AA:AA:18"),
                     19:EthAddr("AA:AA:AA:AA:AA:19"),20:EthAddr("AA:AA:AA:AA:AA:20"),21:EthAddr("AA:AA:AA:AA:AA:21"),22:EthAddr("AA:AA:AA:AA:AA:22"),23:EthAddr("AA:AA:AA:AA:AA:23"),24:EthAddr("AA:AA:AA:AA:AA:24"),
                     25:EthAddr("AA:AA:AA:AA:AA:25"),26:EthAddr("AA:AA:AA:AA:AA:26"),27:EthAddr("AA:AA:AA:AA:AA:27"),28:EthAddr("AA:AA:AA:AA:AA:28"),29:EthAddr("AA:AA:AA:AA:AA:29"),30:EthAddr("AA:AA:AA:AA:AA:30"),
                     31:EthAddr("AA:AA:AA:AA:AA:31"),32:EthAddr("AA:AA:AA:AA:AA:32"),33:EthAddr("AA:AA:AA:AA:AA:33"),34:EthAddr("AA:AA:AA:AA:AA:34"),35:EthAddr("AA:AA:AA:AA:AA:35"),36:EthAddr("AA:AA:AA:AA:AA:36"),}

def enum(**enums):
    return type('Enum', (), enums)
  
BackupMode = enum(REACTIVE=1,PROACTIVE=2)
Mode = enum(BASELINE=1,MERGER=2,MERGER_DEPRACATED=3)
                                

def is_mcast_address(dst_ip_address,controller):
  return controller.mcast_groups.has_key(dst_ip_address)


def install_rewrite_dst_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,new_dst,switch_ports,controller,ofp_match=None,priority=-1):
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
  if ofp_match == None:
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
  else:
    msg.match = ofp_match
    msg.priority = priority
  
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
  
def install_basic_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,priority,controller,ofp_match=None):
  """ Install a flow table rule using the multicast destination address and list of outports  """
  msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
  if ofp_match == None:
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
  else:
    msg.match = ofp_match
  
  for prt in ports:
    msg.actions.append(of.ofp_action_output(port = prt))
  
  #print "\n\n"
  #print msg
  
  
  if priority > 0:  # if the priority is negative we just take the default value
    msg.priority = priority
    
  utils.send_msg_to_switch(msg, switch_id)
  controller.cache_flow_table_entry(switch_id, msg)
  


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

def generate_multicast_groups(controller,backup_tree_expt=False):
  """ Temporary solution is just use the multicast groups read from a text file (see utils.read_mtree_file).  Would like to generate multicast groups w/ a random process.
      
      Currently this a no-op as the multicast groups are already read from a text file.
  """
  if backup_tree_expt:
    # clear the mcast groups, read in the mcast groups from file
    controller.mcast_groups.clear()
    
    
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

    # NICK: this is where you want to insert your multicast tree computation using the root and terminal_hosts read from the file
    #       this will replace the hard-coded mutlicast trees created below (although keep those hard-coded trees because they are good for testing :) )
    
    # NICK: the commented code below is some starter code to set up the call the computing the Steiner Arboresence
#    flag_to_run_nicks_code = True
#    if flag_to_run_nicks_code == True:
#      adjacency_list = controller.adjacency.keys()
#      root_id = find_node_id(root)
#      terminal_ids = list()
#      for host in terminal_hosts:
#        terminal_ids.append(find_node_id(host))
#      
#      # NICK: replace "compute_steiner_arboresence()" with the name of your function.  
#      edges = compute_steiner_arboresence(adjacency_list,root_id,terminal_ids) 
#      
#      data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
#      tree = PrimaryTree(**data)
#      controller.primary_trees.append(tree)
#      continue
    
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
  
def mark_primary_tree_edges(controller):
  """ Traverse the links of each tree and mark that the tree uses that edge. """
  for tree in controller.primary_trees:
    for edge_id in tree.edges:
      edge = edges[edge_id]
      edge.trees.add(tree.id)
      
def mark_backup_tree_edges(controller):
  """ Traverse the links of each tree and mark that the tree uses that edge. """
  for ptree in controller.primary_trees:
    for btree in ptree.backup_trees.values():
      for edge_id in btree.edges:
        edge = edges[edge_id]
        edge.add_backup_tree(btree.id,btree.backup_edge)
   


def generate_new_tag():
  return new_tags.pop()


def get_backup_group_tag(controller,trees,curr_bak_tree_id,u_node,outport,shared_bak_trees,d_node,backup_edge):  
  """ (1) Check if flow entry exists at d_node for one of the shared_bak_trees (those with same outport as current tree).  
      (2) Try to reuse a group_tag at u_node if possible.  
      (3) If none of this works, generate a new one. """

  # (1) look downstream existing flow_entry using GROUP tag
  u_action_tag = None
  d_match_tag= None
  for stree_id in shared_bak_trees:
    if not d_node.has_backup_treeid_rule(backup_edge,stree_id):
      continue
    d_rule = d_node.backup_treeid_rule_map[backup_edge][stree_id]
    d_match_type = d_rule.match_tag.type
    if d_match_type == TagType.GROUP_REUSE or d_match_type == TagType.GROUP:
      u_action_tag = Tag(TagType.GROUP, d_rule.match_tag.value)
      d_match_tag = Tag(d_match_type, d_rule.match_tag.value) 
      u_rule = u_node.backup_treeid_rule_map[backup_edge][curr_bak_tree_id]
      if u_rule.match_tag.type != TagType.MCAST_DST_ADDR and u_rule.match_tag.value == d_rule.match_tag.value:
        u_action_tag.type = TagType.GROUP_REUSE
      return u_action_tag,d_match_tag
  
  for tree_id in trees:
    if not u_node.has_backup_treeid_rule(backup_edge,tree_id):
      continue
    u_rule = u_node.backup_treeid_rule_map[backup_edge][tree_id]
    u_match_type = u_rule.match_tag.type
    if u_match_type == TagType.GROUP_REUSE or u_match_type == TagType.GROUP:   
      return Tag(TagType.GROUP_REUSE, u_rule.match_tag.value),Tag(TagType.GROUP_REUSE, u_rule.match_tag.value)
   
    if tree_id != curr_bak_tree_id and u_rule.outport_tags.has_key(outport):    #see if a previously processed tree with the same downstream forwarding has an action we can reuse
      return u_rule.outport_tags[outport],u_rule.outport_tags[outport]                                  # special case for 1-hop from sending host 
  
  # single tree merging with a new group
  if len(trees) == 1:
    return get_single_backup_tag(controller,curr_bak_tree_id, u_node,backup_edge)
                     
  new_tag = Tag(TagType.GROUP, generate_new_tag())
  return new_tag,new_tag

def get_group_tag(controller,trees,curr_tree_id,u_node,outport,shared_trees,d_node):  
  """ (1) Check if flow entry exists at d_node for one of the shared_trees (those with same outport as current tree).  
      (2) Try to reuse a group_tag at u_node if possible.  
      (3) If none of this works, generate a new one. """

  # (1) look downstream existing flow_entry using GROUP tag
  u_action_tag = None
  d_match_tag= None
  for stree_id in shared_trees:
    if not d_node.treeid_rule_map.has_key(stree_id):
      continue
    d_rule = d_node.treeid_rule_map[stree_id]
    d_match_type = d_rule.match_tag.type
    if d_match_type == TagType.GROUP_REUSE or d_match_type == TagType.GROUP:
      u_action_tag = Tag(TagType.GROUP, d_rule.match_tag.value)
      d_match_tag = Tag(d_match_type, d_rule.match_tag.value) 
      u_rule = u_node.treeid_rule_map[curr_tree_id]
      if u_rule.match_tag.type != TagType.MCAST_DST_ADDR and u_rule.match_tag.value == d_rule.match_tag.value:
        u_action_tag.type = TagType.GROUP_REUSE
      return u_action_tag,d_match_tag
  
  for tree_id in trees:
    if not u_node.treeid_rule_map.has_key(tree_id):
      continue
    u_rule = u_node.treeid_rule_map[tree_id]
    u_match_type = u_rule.match_tag.type
    if u_match_type == TagType.GROUP_REUSE or u_match_type == TagType.GROUP:   
      return Tag(TagType.GROUP_REUSE, u_rule.match_tag.value),Tag(TagType.GROUP_REUSE, u_rule.match_tag.value)
   
    if tree_id != curr_tree_id and u_rule.outport_tags.has_key(outport):    #see if a previously processed tree with the same downstream forwarding has an action we can reuse
      return u_rule.outport_tags[outport],u_rule.outport_tags[outport]                                  # special case for 1-hop from sending host 
  
  # single tree merging with a new group
  if len(trees) == 1:
    return get_single_tag(controller,curr_tree_id, u_node)
                     
  new_tag = Tag(TagType.GROUP, generate_new_tag())
  return new_tag,new_tag


def  get_single_backup_tag(controller,tree_id,u_node,backup_edge,group_logic=False):  
  """ Try to reuse a signle_tag if possible (i.e., when match at u_node using SINGLE).  Otherwise return the tree's default value. 
  
      return action value, match value.  These values are different if u_node has group processing for tree_id
  """
  rule = u_node.backup_treeid_rule_map[backup_edge][tree_id]
  match_type = rule.match_tag.type
  
  tree = get_tree(tree_id, controller)
  
  if u_node.already_processed(backup_edge,tree_id):   # upstream forwarding using Primary Tree tag so have to match at d_node using MCAST ADDRESS
    mcast_tag = Tag(TagType.MCAST_DST_ADDR,tree.mcast_address)
    return mcast_tag,mcast_tag
  
  reuse_action_tag = Tag(TagType.SINGLE_REUSE, rule.match_tag.value)
  if match_type == TagType.SINGLE_REUSE:
    return reuse_action_tag,reuse_action_tag
  
  if match_type == TagType.SINGLE:
    return reuse_action_tag,reuse_action_tag
  
  
  
  if match_type == TagType.MCAST_DST_ADDR:
    return tree.default_tag,tree.default_tag
  
  if group_logic:
    mcast_tag = Tag(TagType.MCAST_DST_ADDR,tree.mcast_address)
    return mcast_tag,mcast_tag
  
  return tree.default_tag,tree.default_tag

def get_single_tag(controller,tree_id,u_node,group_logic=False):  
  """ Try to reuse a signle_tag if possible (i.e., when match at u_node using SINGLE).  Otherwise return the tree's default value. 
  
      return action value, match value.  These values are different if u_node has group processing for tree_id
  """
  rule = u_node.treeid_rule_map[tree_id]
  match_type = rule.match_tag.type
  
  reuse_action_tag = Tag(TagType.SINGLE_REUSE, rule.match_tag.value)
  if match_type == TagType.SINGLE_REUSE:
    return reuse_action_tag,reuse_action_tag
  
  if match_type == TagType.SINGLE:
    return reuse_action_tag,reuse_action_tag
  
  tree = get_tree(tree_id, controller)
  
  if match_type == TagType.MCAST_DST_ADDR:
    return tree.default_tag,tree.default_tag
  
  if group_logic:
    mcast_tag = Tag(TagType.MCAST_DST_ADDR,tree.mcast_address)
    return mcast_tag,mcast_tag
  
  return tree.default_tag,tree.default_tag

  
def write_backup_tag_upstream(bak_trees, u_node,tag,outport,u2d_link,backup_edge,group_logic=False):
  
  for tree_id in bak_trees:
    if not u_node.has_backup_treeid_rule(backup_edge,tree_id):
      continue
    u_rule = u_node.backup_treeid_rule_map[backup_edge][tree_id]
    
    if group_logic:
      if u_rule.match_tag.type != TagType.GROUP_REUSE and u_rule.match_tag.type != TagType.GROUP:
        modified_tag = Tag(TagType.GROUP, tag.value)
        u_rule.add_outport_tag(outport,modified_tag)
        continue
      
    u_rule.add_outport_tag(outport,tag)
  
  u2d_link.add_backup_tag(tag,backup_edge)  
  
def write_tag_upstream(trees, u_node,tag,outport,u2d_link,group_logic=False):
  
  for tree_id in trees:
    if not u_node.treeid_rule_map.has_key(tree_id):
      continue
    u_rule = u_node.treeid_rule_map[tree_id]
    
    if group_logic:
      if u_rule.match_tag.type != TagType.GROUP_REUSE and u_rule.match_tag.type != TagType.GROUP:
        modified_tag = Tag(TagType.GROUP, tag.value)
        u_rule.add_outport_tag(outport,modified_tag)
        continue
      
    u_rule.add_outport_tag(outport,tag)
  
  u2d_link.add_tag(tag)
  

def remove_backup_flow_entry_duplicates(d_node,match_tag,backup_edge):
  
  num_entries = 0
  for flow in d_node.backup_flow_entries[backup_edge]:
    if flow.match_tag == match_tag:
      num_entries+=1
  
  remove_flows = set()
  
  for flow in d_node.backup_flow_entries[backup_edge]:
    if num_entries <= 1:
      break
    if flow.match_tag == match_tag:
      remove_flows.add(flow)
      num_entries-=1
  
  for flow in remove_flows:
    d_node.backup_flow_entries[backup_edge].discard(flow)
        
def match_backup_tag_downstream(trees, d_node,tag,backup_edge):
  
  flow_entry = FlowEntry()
  flow_entry.match_tag = tag
  
  for tree_id in trees:
    has_rule, existing_flow = d_node.has_empty_match_backup_treeid_rule(backup_edge,tree_id,flow_entry)
    if has_rule:
      existing_flow.match_tag = tag
      flow_entry = existing_flow
    #d_node.add_backup_treeid_rule(backup_edge,tree_id,flow_entry)
    if not d_node.has_backup_match_tag(tag,backup_edge):
      d_node.add_backup_treeid_rule(backup_edge,tree_id,flow_entry)
      d_node.add_backup_flow_entry(backup_edge,flow_entry)

  # remove any add_backup_flow duplicates
  remove_backup_flow_entry_duplicates(d_node, tag, backup_edge)

    
def match_tag_downstream(trees, d_node,tag):
  
  flow_entry = FlowEntry()
  flow_entry.match_tag = tag
  
  if not d_node.has_match_tag(tag):
    d_node.flow_entries.add(flow_entry)
  
  for tree_id in trees:
    d_node.treeid_rule_map[tree_id] = flow_entry
    
def check_remove_stale_d_node_backup_entry(in_bak_trees,d_node,new_tag,backup_edge):
  """ Needed if future Group Address Forwarding Tag overwrites an Old one"""
  for tree_id in in_bak_trees:
    if d_node.has_backup_treeid_rule(backup_edge,tree_id):
      old_rule = d_node.backup_treeid_rule_map[backup_edge][tree_id]
      #if old_rule.match_tag.type != TagType.NONE and old_rule.match_tag != new_tag and len(old_rule.outport_tags) == 0:
      if old_rule.match_tag.type != TagType.NONE and old_rule.match_tag != new_tag:   # want to keep the rules with empty match_tag (None) because will later create a rule that inherits their actions
        log.debug("removing B%s l=%s, Flow=%s" %(tree_id,backup_edge,old_rule))
        del d_node.backup_treeid_rule_map[backup_edge][tree_id]
        d_node.backup_flow_entries[backup_edge].discard(old_rule)
  
def check_remove_stale_d_node_entry(in_trees,d_node,new_tag):
  """ Needed if future Group Address Forwarding Tag overwrites an Old one"""
  for tree_id in in_trees:
    if d_node.treeid_rule_map.has_key(tree_id):
      old_rule = d_node.treeid_rule_map[tree_id]
      if old_rule.match_tag != new_tag:
        del d_node.treeid_rule_map[tree_id]
        d_node.flow_entries.discard(old_rule)

def find_outports(controller,tree_id,node):
  outports = set()
  for link in node.out_links:
    if tree_id in link.trees:
      outport = controller.adjacency[(link.upstream_node.id,link.downstream_node.id)]
      outports.add(outport)
      
  return outports

def find_backup_outports(controller,tree_id,node,backup_edge):
  outports = set()
  for link in node.out_links:
    
    if link.backup_trees.has_key(backup_edge) and tree_id in link.backup_trees[backup_edge]:
      outport = controller.adjacency[(link.upstream_node.id,link.downstream_node.id)]
      outports.add(outport)
      
  return outports
 
def has_group_forwarding(controller,in_trees,d_node):   
  """ Return True if in_trees have common_forwarding common forwarding. 
    
    (1) For each tree \in in_trees, find the set of outports.  Return False if they are not the same
    (2) Find the set of trees shared along in_tree links.  Check of these trees has the same outports from (1), If no, return False
  """
  outports = None
  for tree_id in in_trees:
    t_outports = find_outports(controller, tree_id, d_node)
    if outports == None:
      outports = t_outports
    elif outports != t_outports:
      return False,None
  
  shared_trees = set()
  for d_link in d_node.out_links:
    out_trees = d_link.trees
    if len(in_trees.intersection(out_trees)) == 0: continue
    curr_share = out_trees.difference(in_trees)
    for tree in curr_share:
      shared_trees.add(tree)
  
  non_shared_trees = set()
  for s_tree in shared_trees:
    s_outports = find_outports(controller, s_tree, d_node)
    if s_outports != outports and len(in_trees) == 1:
      return False,None
    elif s_outports != outports and len(in_trees) > 1:
      non_shared_trees.add(s_tree)
  
   # removes any trees from shared_trees with not exactly the same outports
  for n_tree in non_shared_trees:
    shared_trees.remove(n_tree)
  if len(in_trees) > 1:
    return True,shared_trees    # not sure about returning shared trees
  
  if len(in_trees) == 1 and len(shared_trees) == 0:
    return False,None
  
  return True,shared_trees

def has_group_backup_forwarding(controller,in_bak_trees,d_node,backup_edge):   
  """ Return True if in_bak_trees have common_forwarding common forwarding. 
    
    (1) For each tree \in in_bak_trees, find the set of outports.  Return False if they are not the same
    (2) Find the set of trees shared along in_tree links.  Check of these trees has the same outports from (1), If no, return False
  """
  outports = None
  completed = set()
  for tree_id in in_bak_trees:
    if d_node.already_processed(backup_edge,tree_id):
      completed.add(tree_id)
      continue
    b_outports = find_backup_outports(controller, tree_id, d_node,backup_edge)
    if outports == None:
      outports = b_outports
    elif outports != b_outports:
      return False,None
  
  shared_trees = set()
  out_trees = set()
  for d_link in d_node.out_links:
    if d_link.backup_trees.has_key(backup_edge):
      out_trees = d_link.backup_trees[backup_edge]
    if len(in_bak_trees.intersection(out_trees)) == 0: continue
    curr_share = out_trees.difference(in_bak_trees)
    for tree in curr_share:
      shared_trees.add(tree)
  
  non_shared_trees = set()
  for s_tree in shared_trees:
    s_outports = find_backup_outports(controller, s_tree, d_node,backup_edge)
    if s_outports != outports and len(in_bak_trees) == 1:
      return False,None
    elif s_outports != outports and len(in_bak_trees) > 1:
      non_shared_trees.add(s_tree)
  
   # removes any trees from shared_trees with not exactly the same outports
  for n_tree in non_shared_trees:
    shared_trees.remove(n_tree)
  if len(in_bak_trees) > 1:
    return True,shared_trees    # not sure about returning shared trees
  
  if len(in_bak_trees) == 1 and len(shared_trees) == 0:
    return False,None
  
  return True,shared_trees


def tag_and_match(controller,tree_id,u_node,d_node,u2d_link):
  """ We are at 'u_node' looking at (u,d), i.e., 'u2d_link', and checking each of d_nodes's outlinks for common forwarding behavior among tree using (u,d) """
  in_trees = u2d_link.trees
  shared_trees = set()
  group_forwarding,shared_trees = has_group_forwarding(controller,in_trees, d_node)

  outport = controller.adjacency[(u_node.id,d_node.id)]

  if group_forwarding:
    action_tag,match_tag = get_group_tag(controller,in_trees,tree_id, u_node,outport,shared_trees,d_node)
    write_tag_upstream(in_trees, u_node,action_tag,outport,u2d_link,len(in_trees) != 1)
    check_remove_stale_d_node_entry(in_trees,d_node,match_tag)
    match_tag_downstream(in_trees, d_node,match_tag)
  else:
    if len(in_trees) == 1:
      action_tag,match_tag = get_single_tag(controller,tree_id, u_node)    #action_tag and match_tag are the same here
      write_tag_upstream(in_trees, u_node,action_tag,outport,u2d_link)
      match_tag_downstream(in_trees, d_node,match_tag)
    elif len(in_trees) > 1:
      action_tag,match_tag = get_single_tag(controller, tree_id, u_node,True)
      trees = set()
      trees.add(tree_id)
      write_tag_upstream(trees, u_node,action_tag,outport,u2d_link)
      match_tag_downstream(trees, d_node,match_tag)
      
def match_mcast_addr(controller,tree_id,d_node,u2d_link,backup_edge=None,priority=None):
  """ Special logic for node 1 hop downstream from root.  Create a match rule to match based on tree's destination address."""
  flow_entry = FlowEntry()
  root,mcast_dst = find_tree_root_and_mcast_addr(tree_id, controller)
  tag = Tag(TagType.MCAST_DST_ADDR,mcast_dst)
  flow_entry.match_tag = tag
  if backup_edge == None:
    d_node.treeid_rule_map[tree_id] = flow_entry
    d_node.flow_entries.add(flow_entry)
  else:
    flow_entry.priority = priority
    d_node.add_backup_treeid_rule(backup_edge,tree_id,flow_entry)
    d_node.add_backup_flow_entry(backup_edge,flow_entry)

def action_write_terminal_host_addr(controller,current_tree,current_tree_id,u_node,d_node,u2d_link):
  """ Create action to write the address of the terminal host at u_node (L3 and L2 addresses)"""

  outport = controller.adjacency[(u_node.id,d_node.id)]
  host_dst_addr = current_tree.find_ip_address(d_node.id)
  tag = Tag(TagType.HOST_DST_ADDR, host_dst_addr)
  
  for tree_id in u2d_link.trees:    # note: tree_ids can be pointing to same FlowEntry, causing value same (outport,value) value to be written multiple times (this is safe to do)
    if not u_node.treeid_rule_map.has_key(tree_id):
      continue
    rule = u_node.treeid_rule_map[tree_id]
    rule.add_outport_tag(outport,tag)
  
  u2d_link.add_tag(tag)
  
def create_single_tree_tagging_indices(controller,tree,tree_id,root_node):
  """  Do a BFS search of tree and determine the new_tag, keep_tag, and remove_tag indices we use to later to create the flow entry rules. """
  log.debug("\nTREE %s-----------------------------------------------------------------" %(tree_id))
  q = Queue()
  q.put(root_node)
  visited = set()
  while not q.empty():
    u_node = q.get()
    visited.add(u_node)
    log.debug("At n%s" %(u_node.id))
    
    for u2d_link in u_node.out_links:
      if not tree_id in u2d_link.trees: continue
      d_node = u2d_link.downstream_node
      if d_node in visited: continue
      if not d_node.is_host:
        q.put(d_node)
      
      log.debug("\t- visiting s%s" %(d_node.id))
      
      
      if controller.algorithm_mode == Mode.MERGER:
        if u_node.is_host:
          match_mcast_addr(controller,tree_id,d_node,u2d_link)
        elif d_node.is_host:
          action_write_terminal_host_addr(controller, tree,tree_id, u_node, d_node, u2d_link)
        else:
          tag_and_match(controller,tree_id,u_node,d_node,u2d_link)
      
  log.debug( "----------------------------------------------------------------------------\n")
  

def create_single_backup_tree_tagging_indices(controller,btree,btree_id,root_node,backup_edge,primary_tree_tagging=False):
  """ For each tree, if "primary_tree_tagging=True" check if overlap with primary_tree.  Otherwise, try creating tags based on common forwarding with other backup trees. """
  log.debug( "\nBACKUP TREE B%s for %s-----------------------------------------------------------------" %(btree_id,backup_edge))
  q = Queue()
  q.put(root_node)
  visited = set()
  while not q.empty():
    u_node = q.get()
    visited.add(u_node)
    log.debug("At n%s" %(u_node.id))
    
    for u2d_link in u_node.out_links:
      if not u2d_link.backup_trees.has_key(backup_edge): continue
      if not btree_id in u2d_link.backup_trees[backup_edge]: continue
      d_node = u2d_link.downstream_node
      if d_node in visited: continue
      if not d_node.is_host:
        q.put(d_node)
      
      if u_node.id not in btree.nodes_to_signal:     
        log.debug( "\t Skipping s%s backup tree tagging because s%s is not a node BT%s needs to signal" %(u_node.id,u_node.id,btree_id))
        continue
      
      if d_node.already_processed(backup_edge,btree_id):     
        log.debug( "\t Skipping creating match rule at s%s because s%s has already been processed for BT%s" %(d_node.id,d_node.id,btree_id))
        continue

      # for now will assume that neither u_node nor d_node are hosts.  this should be safe with my assumptions about topologies
      if u_node.is_host and not primary_tree_tagging:  
        continue  #skip because already processed during first round of BFS traversal
      elif u_node.is_host: 
        match_mcast_addr(controller,btree_id,d_node,u2d_link,backup_edge,default_ustar_backup_flow_priority)
      elif primary_tree_tagging:
        primary_tree_overlap(controller,u_node,d_node,btree,btree_id,backup_edge)
      else:
        create_backup_group_single_tags(controller,u_node,d_node,btree,btree_id,u2d_link,backup_edge)
      
      log.debug( "\t- visited s%s" %(d_node.id))
  log.debug( "----------------------------------------------------------------------------\n"  )

def create_backup_group_single_tags(controller,u_node,d_node,btree,btree_id,u2d_link,backup_edge):
  """ We are at 'u_node' looking at (u,d), i.e., 'u2d_link', and checking each of d_nodes's outlinks for common forwarding behavior among tree using (u,d) """
  bak_in_trees = u2d_link.backup_trees[backup_edge]
  shared_bak_trees = set()
  group_forwarding,shared_bak_trees = has_group_backup_forwarding(controller,bak_in_trees, d_node,backup_edge)
  if u_node.already_processed(backup_edge,btree_id) and not d_node.already_processed(backup_edge,btree_id): 
    group_forwarding = False
  
  outport = controller.adjacency[(u_node.id,d_node.id)]

  if group_forwarding:
    action_tag,match_tag = get_backup_group_tag(controller,bak_in_trees,btree_id, u_node,outport,shared_bak_trees,d_node,backup_edge)
    write_backup_tag_upstream(bak_in_trees, u_node,action_tag,outport,u2d_link,backup_edge,len(bak_in_trees) != 1)
   #check_remove_stale_d_node_backup_entry(bak_in_trees,d_node,match_tag,backup_edge)
    match_backup_tag_downstream(bak_in_trees, d_node,match_tag,backup_edge)
  else:
    if len(bak_in_trees) == 1:
      action_tag,match_tag = get_single_backup_tag(controller,btree_id, u_node,backup_edge)    #action_tag and match_tag are the same here
      write_backup_tag_upstream(bak_in_trees, u_node,action_tag,outport,u2d_link,backup_edge)
      match_backup_tag_downstream(bak_in_trees, d_node,match_tag,backup_edge)
    elif len(bak_in_trees) > 1:
      action_tag,match_tag = get_single_backup_tag(controller, btree_id, u_node,backup_edge,True)
      trees = set()
      trees.add(btree_id)
      write_backup_tag_upstream(trees, u_node,action_tag,outport,u2d_link,backup_edge)
      match_backup_tag_downstream(trees, d_node,match_tag,backup_edge)


def primary_tree_overlap(controller,u_node,d_node,btree,btree_id,backup_edge):
  """ Processes one u2d_node link.  looks at all of d_node's out-links for primary tree overlap"""
  btree_outports = btree.find_outports(d_node.id)
  candidates = set()
  
  for ptree_id in d_node.treeid_rule_map.keys():
    p_flow = d_node.treeid_rule_map[ptree_id]  #tree_id --> FlowEntry
    p_outports = set(p_flow.outport_tags.keys())
    
    if p_outports == btree_outports:
      candidates.add((ptree_id,p_flow))
  
  # look through candidates to see if we are already matching using the primary_tree at u_node
  reuse_u_match = False
  no_write_flow = None
  reuse_d_match = False
  write_flow = None
  u_flow = None
  if u_node.has_backup_treeid_rule(backup_edge,btree_id):  # if u_flow is None that means we will have to write a tag upstream
    u_flow = u_node.backup_treeid_rule_map[backup_edge][btree_id]
  for candidate in candidates:
    ptree_id = candidate[0]
    p_flow = candidate[1]   # primary tree flow at d_node
    
    if p_flow.match_tag.type == TagType.MCAST_DST_ADDR and btree.mcast_address == p_flow.match_tag.value:   # backup tree intersecting with its primary
      reuse_u_match = True
      no_write_flow = p_flow
      break
    elif u_flow != None and u_flow.match_tag.value == p_flow.match_tag.value:   
      reuse_u_match = True
      no_write_flow = p_flow
      break
    elif not reuse_u_match and p_flow.match_tag.type != TagType.MCAST_DST_ADDR:
      reuse_d_match = True
      write_flow = p_flow

  
  if reuse_u_match:  # do nothing upstream, and create a rule for downstream (but this rule is not installed because we are reusing the downstream rule)
    reuse_flow = FlowEntry()
    reuse_flow.match_tag = no_write_flow.match_tag
    reuse_flow.outport_tags = no_write_flow.outport_tags
    reuse_flow.is_placeholder = True
    d_node.add_backup_treeid_rule(backup_edge,btree_id,reuse_flow)
    d_node.add_backup_flow_entry(backup_edge,reuse_flow)
    d_node.add_backup_tagging_completed(backup_edge,btree_id)
    outport = controller.adjacency[(u_node.id,d_node.id)]
    out_tag =reuse_flow.match_tag
    if u_flow == None:
      u_flow = FlowEntry()
    u_flow.add_outport_tag(outport, out_tag)
    u_node.add_backup_treeid_rule(backup_edge,btree_id,u_flow)
    u_node.add_backup_flow_entry(backup_edge,u_flow)
    
    
    log.debug( "\t\t At s%s writing a placeholder flow (b/c reusuing a primary tree flow at s%s). At s%s, outport action with no tag created." %(d_node.id,d_node.id,u_node.id))
    
  elif reuse_d_match:
    reuse_flow = FlowEntry()
    reuse_flow.match_tag = write_flow.match_tag
    reuse_flow.outport_tags = write_flow.outport_tags
    reuse_flow.is_placeholder = True
    d_node.add_backup_treeid_rule(backup_edge,btree_id,reuse_flow)
    d_node.add_backup_flow_entry(backup_edge,reuse_flow)
    d_node.add_backup_tagging_completed(backup_edge,btree_id)
    
    if u_flow == None:
      u_flow = FlowEntry()

    outport = controller.adjacency[(u_node.id,d_node.id)]
    out_tag = reuse_flow.match_tag
    if out_tag.type == TagType.GROUP_REUSE:
      out_tag = Tag(TagType.GROUP,reuse_flow.match_tag.value)
    elif out_tag.type == TagType.SINGLE_REUSE:
      out_tag = Tag(TagType.SINGLE,reuse_flow.match_tag.value)
    u_flow.add_outport_tag(outport, out_tag)
    u_node.add_backup_treeid_rule(backup_edge,btree_id,u_flow)
    u_node.add_backup_flow_entry(backup_edge,u_flow)
    log.debug("\t\t At s%s, writing a placeholder flow (b/c reusuing a primary tree flow at s%s).  at s%s, created flow with no match and action to write the tag." %(d_node.id,d_node.id,u_node.id))
  else:  
     log.debug("\t\t No primary tree overlap action at s%s" %(d_node.id))
  
def create_tag_indices(controller):
  """ For each tree do a BFS. """  
  for tree in controller.primary_trees:
    root_id = find_node_id(tree.root_ip_address)
    root_node = nodes[root_id]
    create_single_tree_tagging_indices(controller,tree,tree.id,root_node)
  
  
  print_flow_entries()
  log.debug("Total Number of Flows = %s" %(total_num_flows()))


def cache_merger_activate_backup_rules(controller):
  """ When called, it assumed we are in MERGER mode and BackupMode = PROACTIVE"""
  backup_map = find_unique_backup_edges(controller)
  for backup_edge in backup_map:
    for backup_tree in backup_map[backup_edge]:
      level_one_nodes = backup_tree.compute_node_levels()[1]
      for node_id in level_one_nodes:
        node = nodes[node_id]
        node.cache_merger_activate_backup_rules(controller,backup_edge,backup_tree)

def preinstall_all_merged_backup_flows(controller):
  """ PROACTIVE Mode: For each backup tree, preinstall backup tree flows for nodes. """
  for node in nodes.values():
    for backup_edge in node.preinstalled_backup_ofp_rules.keys():
      node.preinstall_merged_backup_ofp_rules(controller,backup_edge)
      
def find_safe_flow_priority(controller,node_id):
  
  highest_priority = of.OFP_DEFAULT_PRIORITY 
  
  if not controller.flowTables.has_key(node_id):
    return highest_priority + 1
  
  for flow_entry in controller.flowTables[node_id]:
    #if flow_entry.match.nw_src == self.root_ip_address and flow_entry.match.nw_dst == self.mcast_address:
    if flow_entry.priority > highest_priority:
      highest_priority = flow_entry.priority

  return highest_priority + 1

def activate_merger_backups(controller,affected_trees,failed_link):
  
  if controller.backup_tree_mode == BackupMode.PROACTIVE:
    for node in nodes.values():
      if node.cached_write_bid_ofp_rules.has_key(failed_link):
        safe_priority = find_safe_flow_priority(controller, node.id)
        node.install_cached_write_bid_ofp_rules(controller,failed_link,safe_priority)
    
  elif controller.backup_tree_mode == BackupMode.REACTIVE:
    signaled_nodes = set()
    for ptree in affected_trees:
      backup_tree = ptree.backup_trees[failed_link]
      for node_id in backup_tree.nodes_to_signal:
        node = nodes[node_id]
        if node_id in signaled_nodes or node.is_host:
          continue
        backup_flow_entry = node.backup_treeid_rule_map[backup_tree.backup_edge][backup_tree.id]
        if backup_flow_entry.is_placeholder: continue
        safe_priority = find_safe_flow_priority(controller, node_id)
        node.install_precomputed_backup_ofp_rules(controller,failed_link,safe_priority)
        signaled_nodes.add(node_id)
        
  garbage_collect_merger_rules(failed_link,affected_trees)

def garbage_collect_merger_rules(failed_link,affected_trees):
  "For now just computes how many flows can be garbage collected."
  
  node_garbage_flows = {}
  node_affected_trees = {}
  
  # for each node, build a list of primary trees with a stale flow
  for ptree in affected_trees:
    backup_tree = ptree.backup_trees[failed_link]
    garbage_nodes = ptree.find_garbage_collect_nodes(failed_link,backup_tree)
    for node_id in garbage_nodes:
      if node_affected_trees.has_key(node_id):
        node_affected_trees[node_id].add(ptree.id)
      else:
        ptrees = set()
        ptrees.add(ptree.id)
        node_affected_trees[node_id] = ptrees
        node_garbage_flows[node_id] = set()   #intialize
        
  for node_id in node_affected_trees.keys():
    node = nodes[node_id]
    has_garbage,garbage_flow = node.garbage_collect_merge_flows(ptree.id,failed_link,node_affected_trees[node_id])
    if has_garbage:
      node_garbage_flows[node_id].add(garbage_flow)
  
  global garbage_collection_total
  garbage_collection_total = len(node_garbage_flows.values())
  #print node_garbage_flows

def generate_all_backup_ofp_rules(controller):
  """ For each backup_edge, create the OpenFlow rules for each Primary Tree using the backup edge.  The OpenFlow rules are created using the tagging indices created earlier.
      
      The OFP rules are stored at each node, but not installed.
  """
  backup_map = find_unique_backup_edges(controller)
  generate_ofp_rule_nodes = set()
  level_one_map = {}
  for backup_edge in backup_map:
    for backup_tree in backup_map[backup_edge]:
      level_one_nodes = backup_tree.compute_node_levels()[1]
      for node_id in backup_tree.nodes_to_signal:
        node = nodes[node_id]
        if node.is_host: continue
#        if backup_tree.id == 5: #for debugging
#          level_one_nodes = []
        if controller.backup_tree_mode == BackupMode.REACTIVE:
          generate_ofp_rule_nodes.add(node_id)
        elif controller.backup_tree_mode == BackupMode.PROACTIVE and (node_id not in level_one_nodes):
          generate_ofp_rule_nodes.add(node_id)
        elif controller.backup_tree_mode == BackupMode.PROACTIVE and (node_id in level_one_nodes):
          if level_one_map.has_key(node_id):
            level_one_map[node_id].add(backup_tree.id)
          else: 
            level_ones = set()
            level_ones.add(backup_tree.id)
            level_one_map[node_id] = level_ones
  
  # 2 possible cases: (1) node is not a level-one node for any node --> either match using Bid or whatever other conditions specified in each FlowEntry
  #                   (2) node is a level one node for some nodes --> should generate only rules for tree_ids where node id not level_one 
  for node_id in generate_ofp_rule_nodes:
    node = nodes[node_id]  
    if not level_one_map.has_key(node_id):  #all REACTIVE node satisfy this if condition
      node.generate_backup_ofp_rules(controller,backup_edge)
    else:
      # create backup ofp_rule only for tree_ids that do not have node_id as a level_one 
      node.generate_backup_ofp_rules(controller,backup_edge,level_one_map[node_id])
          
          
#  for backup_edge in backup_map:
#    for backup_tree in backup_map[backup_edge]:
#      level_one_nodes = backup_tree.compute_node_levels()[1]
#      for node_id in backup_tree.nodes_to_signal:
#        node = nodes[node_id]
#        if node.is_host: continue
#        if controller.backup_tree_mode == BackupMode.REACTIVE or (node_id not in level_one_nodes):  # only want to skip for PROACTIVE
#          node.generate_backup_ofp_rules(controller,backup_edge,backup_tree)
  
def install_ofp_merge_rules(controller):
  """ Create the OpenFlow rules using the tagging indices created earlier. """
  for node in nodes.values():
    node.generate_ofp_rules(controller,node.id) 
    node.install_ofp_rules(controller)

def total_num_flows():
  total_flows = 0
  for node in nodes.values():
    if not node.is_host:
      total_flows += len(node.flow_entries)
  return total_flows

def print_node_flow_entries(node,skip_if_empty=False,logging=False):
    
  if skip_if_empty and len(node.flow_entries) == 0:
    return
  
  out_str = "\n\t\tS%s Flow Entries ----------------------------------------------------------------------------------------------------\n" %(node.id)
  for flow in node.flow_entries:
    out_str += "\t\t\t %s\n" %(flow)
  out_str += "\t\t--------------------------------------------------------------------------------------------------------------------" 
  if not logging:
    print out_str
  else:
    log.debug(out_str)
    
def print_node_backup_flow_entries(node,backup_edge,skip_if_empty=False,msg=None,logging=False):
  
  if skip_if_empty and (not node.backup_flow_entries.has_key(backup_edge) or len(node.backup_flow_entries[backup_edge]) == 0):
    return
  out_str = ""
  if msg!=None:
    out_str = "(%s) " %(msg)
  out_str += "\n\t\tS%s Flow Entries for l=%s----------------------------------------------------------------------------------------------------\n" %(node.id,backup_edge)
  for flow in node.backup_flow_entries[backup_edge]:
    out_str += "\t\t\t %s\n" %(flow)
  out_str += "\t\t--------------------------------------------------------------------------------------------------------------------" 
  if not logging:
    print out_str
  else:
    log.debug(out_str)
    
def print_flow_entries():
  
  for node in nodes.values():
    if not node.is_host:
      print_node_flow_entries(node,True,logging=True)

def print_backup_ofp_rules(controller,backup_edge):
  
  for node in nodes.values():
    if controller.backup_tree_mode == BackupMode.PROACTIVE:
      node.print_proactive_backup_ofp_rules(backup_edge)
    elif controller.backup_tree_mode == BackupMode.REACTIVE:
      node.print_reactive_backup_ofp_rules(backup_edge) 
    

def log_backup_flow_entries(backup_map,msg=None):
  
  for backup_edge in backup_map:
    for node in nodes.values():
      if not node.is_host:
        print_node_backup_flow_entries(node,backup_edge,True,msg,logging=True)
      
def find_unique_backup_edges(controller):
  """ Create and return a dict of all backup edges and the backup trees for that backup edge """
  backup_map = {}   # edge --> set of backup trees for that edge
  for ptree in controller.primary_trees:
    for btree in ptree.backup_trees.values():
      edge = btree.backup_edge
      if backup_map.has_key(edge):
        backup_map[edge].add(btree)
      else:
        backup_set = set()
        backup_set.add(btree)
        backup_map[edge] = backup_set
        
  return backup_map
         
      
def create_backup_tag_indices(controller):
  """ For each backup_edge, create the indices for all backup trees using this edge.  

      First, check all trees for primary tree overlap.  Then, for each edge without primary tree overlap, try to create tags based on backup trees with same forwarding.
  """
  primary_tree_tagging = True
  backup_map = find_unique_backup_edges(controller)
  for backup_edge in backup_map:
    for backup_tree in backup_map[backup_edge]:
      root_id = find_node_id(backup_tree.root_ip_address)
      root_node = nodes[root_id]
      create_single_backup_tree_tagging_indices(controller,backup_tree,backup_tree.id,root_node,backup_edge,primary_tree_tagging) 
  
#  log_backup_flow_entries(backup_map,"Primary Tree Overlap Only")
  primary_tree_tagging = False
  for backup_edge in backup_map:
    for backup_tree in backup_map[backup_edge]:
      root_id = find_node_id(backup_tree.root_ip_address)
      root_node = nodes[root_id]
      create_single_backup_tree_tagging_indices(controller,backup_tree,backup_tree.id,root_node,backup_edge,primary_tree_tagging)   
    
  #log_backup_flow_entries(backup_map)
def create_merged_backup_tree_flows(controller):
  """ Merger Algorithm for backup trees """
  
  mark_backup_tree_edges(controller)
  
  create_backup_tag_indices(controller)
  
  if controller.backup_tree_mode == BackupMode.PROACTIVE:
    create_bid_match_tags(controller)
  
  generate_all_backup_ofp_rules(controller)
  
  if controller.backup_tree_mode == BackupMode.PROACTIVE:
    cache_merger_activate_backup_rules(controller)
    preinstall_all_merged_backup_flows(controller)
  
  backup_map = find_unique_backup_edges(controller)
  log_backup_flow_entries(backup_map)
      
def create_install_merged_primary_tree_flows(controller):
  """ Merger Algorithm for primary trees """
  
  create_node_edge_objects(controller)
  
  mark_primary_tree_edges(controller)
  
  create_tag_indices(controller)
  
  install_ofp_merge_rules(controller)
  
  log.debug("\t\t  INSTALLED MERGED FLOW ENTRIES!!!! ")
  

def create_bid_match_tags(controller):
  """ For any backup tree node that also in the primary tree but has different outports across the primary tree and backup tree, modify the 
      TagType to match using Bid (backup tree id) if currently matching using SINGLE TAG or MCAST ADDRESS
  """
  backup_map = find_unique_backup_edges(controller)
  for backup_edge in backup_map:
    for backup_tree in backup_map[backup_edge]:
      for diverge_node_id in backup_tree.diverge_nodes:
        level_one_nodes = backup_tree.compute_node_levels()[1]
        if diverge_node_id in level_one_nodes: 
          continue    # level one node should continue to match using mcast address
        
        diverge_node = nodes[diverge_node_id]
        # (1) update: diverge_node's backup_treeid_rule_map if needed
        backup_rule = diverge_node.backup_treeid_rule_map[backup_edge][backup_tree.id]
        new_match_tag = None
        if backup_rule.match_tag.type == TagType.MCAST_DST_ADDR or backup_rule.match_tag.type == TagType.SINGLE or backup_rule.match_tag.type == TagType.SINGLE_REUSE:
          new_match_tag = Tag(TagType.BACKUP_ID, backup_tree.bid)
          new_match_tag.extras = backup_tree.mcast_address
          backup_rule.match_tag = new_match_tag
          backup_rule.is_placeholder = False
        else: continue
        
        # (2) update: diverge_node's backup_flow_entries if needed
        for backup_rule in diverge_node.backup_flow_entries[backup_edge]:
          if (backup_rule.match_tag.type == TagType.MCAST_DST_ADDR and backup_rule.match_tag.value == backup_tree.mcast_address) or \
             (backup_rule.match_tag.type == TagType.SINGLE and backup_rule.match_tag.value == backup_tree.default_tag) or \
             (backup_rule.match_tag.type == TagType.SINGLE_REUSE and backup_rule.match_tag.value == backup_tree.default_tag):
            
            backup_rule.match_tag = new_match_tag
            backup_rule.is_placeholder = False

def get_tree(tree_id,controller):
  for tree in controller.primary_trees:
    if tree.id == tree_id:
      return tree
   
    
def append_rewrite_dst_ofp_action(controller,switch_id,rule,switch_ports,tag_ports, new_dst,port_map,tag = None):
  """ For any switch_port, applies the value action if specified in 'value' and writes the outport without modifying the destination address.  For
      the other ports, the nw_addr is rewritten to the one in the port_map   """
    
  for prt in switch_ports:
    if prt in tag_ports:
      if tag != None:
        new_tag_action = of.ofp_action_dl_addr.set_dst(tag)
        rule.actions.append(new_tag_action)
        
      rule.actions.append(of.ofp_action_output(port = prt))
  
  for dst in new_dst:
    prt = port_map[dst]  
    if prt not in tag_ports:
      continue
    
    action = of.ofp_action_nw_addr.set_dst(IPAddr(dst))
    rule.actions.append(action)
    
    new_mac_addr = controller.arpTable[switch_id][dst].mac
    l2_action = of.ofp_action_dl_addr.set_dst(new_mac_addr)
    rule.actions.append(l2_action)
    
    rule.actions.append(of.ofp_action_output(port = prt))
    
  return rule
    

def find_tree_root_and_mcast_addr(tree_id,controller):
  
  for tree in controller.primary_trees:
    if tree.id == tree_id:
      return tree.root_ip_address,tree.mcast_address
  msg = "Error looking up the root and multicast address of T%s.  " %(tree_id)
  raise appleseed.AppleseedError(msg)



def append_ether_dst_ofp_action(ofp_rule,ether_dst,ports):
  """ Applies the value (ethernet dest address) and adds actions to send outports."""
  new_ether_action = of.ofp_action_dl_addr.set_dst(ether_dst)
  ofp_rule.actions.append(new_ether_action)
  for prt in ports:
    ofp_rule.actions.append(of.ofp_action_output(port = prt))
  return ofp_rule
                            
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
    
def install_pcount_unicast_flows(controller):
  """ Used by PCount Experiments"""
  num_hosts_half = int(pcount_all.PCOUNT_NUM_UNICAST_FLOWS)
  u_id = int(num_hosts_half * 2) +1
  d_id = u_id+1
  
  controller.monitored_links[(u_id,d_id)] = (True,True)
  controller.pcount_link_results[(u_id,d_id)] = set()
  
  log.debug("about to create primary trees for unicast flows")
  # create fake primary tree with flow entry at u and d for each (host i,host 10 i pair)
  for src_id in range(1,num_hosts_half+1):
    dst_id = src_id + num_hosts_half
    src_host = find_host_ip_addr(src_id) 
    dst_host = find_host_ip_addr(dst_id)
    edges = [(src_id,u_id),(u_id,d_id),(d_id,dst_id)]
    terminal_hosts = [dst_host]
    data = {"edges":edges, "mcast_address":dst_host, "root":src_host, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
    tree = PrimaryTree(**data)
    controller.primary_trees.append(tree)
    log.debug("installing primary tree for unicast flow (%s,%s)" %(src_id,dst_id))
    tree.install()


def install_all_trees(controller,backup_tree_expt=False):
  """  (1) Compute and install the primary trees. 
       (2) Triggers a pcount session after a 5 second delay (using a timer)
       (3) Precompute backup trees
  
      NICK: Here is where the primary trees are computed and installed.  Also, we precompute (and potentially pre-install) backup trees here.
   """
  generate_multicast_groups(controller,backup_tree_expt)  # NICK: currently the mutlicast groups are just read from a file 'mtree_file_str'
  
  compute_primary_trees(controller)   # NICK: look at this function 
  
  if controller.algorithm_mode != Mode.BASELINE:
    create_install_merged_primary_tree_flows(controller)
    
  else:   # run baseline
    for tree in controller.primary_trees:
      tree.install()
#      log.info( "============== installed tree = %s" %(tree.mcast_address))
#      try:
#        u_switch_id, d_switch_ids = pcount.get_tree_measure_points(tree.root_ip_address,tree.mcast_address,controller)
#        core.callDelayed(pcount.PCOUNT_CALL_FREQUENCY,pcount.start_pcount_thread,u_switch_id, d_switch_ids,tree.root_ip_address,tree.mcast_address,controller)
#      except appleseed.AppleseedError:
#        log.info("found no flow measurement points for flow = (%s,%s) but continuing operation becasue it assumed that no PCount session is wanted for this flow." %(tree.root_ip_address,tree.mcast_address))
#      
    msg = " ================= Primary Trees Installed ================="
    log.info(msg)
  
  compute_backup_trees(controller)
  
  
def compute_backup_trees(controller):
  """ Short-term: hard-coded backup tree + assume only one backup tree per primary tree"""
  num_switches = len(core.openflow_discovery._dps)
  
  for primary_tree in controller.primary_trees:  # self-note: would require another loop to precompute backups for ALL links
    end_hosts = controller.mcast_groups[primary_tree.mcast_address]   # this is the root and all terminal nodes
    backup_tree_edges = []
    backup_edge = ()
    
    # NICK. this is where you should insert your backup tree computation.  Below is some starter code, that sets up the call to your function "compute_backup_trees"
    
#    flag_to_run_nicks_code = True
#    if flag_to_run_nicks_code == True:
#      adjacency_list = controller.adjacency.keys()
#      root_id = find_node_id(primary_tree.root_ip_address)
#      terminal_ids = list()
#      for host in primary_tree.terminal_ip_addresses:
#        terminal_ids.append(find_node_id(host))
#      
#      for backup_edge in primary_tree.edges:
#        upstream_node_id = backup_edge[0]
#        downstream_node_id = backup_edge[1]
#        if primary_tree.is_host(upstream_node_id) or primary_tree.is_host(downstream_node_id):
#          continue  # We don't need to compute backup trees for edges to and from a host.
#        
#        # NICK: replace "compute_backup_tree()" with the name of your function.  
#        backup_tree_edges = compute_backup_tree(adjacency_list,root_id,terminal_ids,primary_tree.edges,backup_edge)  # remove the backup_edge from G' and set the edge weights of each primary_tree edge to 0
#        
#        data = {"edges":backup_tree_edges, "mcast_address":primary_tree.mcast_address, "root":primary_tree.root_ip_address, "terminals":primary_tree.terminal_ip_addresses, 
#              "adjacency":controller.adjacency, "controller":controller,"primary_tree":primary_tree,"backup_edge":backup_edge}
#        backup_tree = BackupTree(**data)
#        primary_tree.backup_trees.append(backup_tree) 
#      
#        if controller.algorithm_mode == Mode.BASELINE and controller.backup_tree_mode == BackupMode.PROACTIVE:
#          backup_tree.preinstall_baseline_backups()
#      
#      continue
    
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
    primary_tree.backup_trees[backup_edge] = backup_tree
    
    if controller.algorithm_mode == Mode.BASELINE and controller.backup_tree_mode == BackupMode.PROACTIVE:
      backup_tree.preinstall_baseline_backups()
  
  if controller.algorithm_mode == Mode.MERGER:    
    create_merged_backup_tree_flows(controller)
  
def find_node_id(ip_address):
  """ Takes the IP Address of a node and returns its node id number. 
  
  We asssume that the last value in IP address corresponds to the node id. For example, IP address of
  10.0.0.8 has node id of 8"
  """
  ip_str = str(ip_address)
  parse = ip_str.split(".")
  id = parse[-1]
  return int(id) 
     
     
def find_host_ip_addr(node_id):
  """ Takes the IP Address of a node and returns its node id number. 
  
  We asssume that the last value in IP address corresponds to the node id. For example, IP address of
  10.0.0.8 has node id of 8"
  """
  ip_str = '10.0.0.%s' %(node_id)
  return IPAddr(ip_str)

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
    self.default_tag = Tag(TagType.SINGLE, tree_default_tags[self.id])
    
  def find_ip_address(self,id):
    
    for ip in self.terminal_ip_addresses:
      if find_node_id(ip) == id:
        return ip
      
    if find_node_id(self.root_ip_address) == id:
      return self.root_ip_address
  
  def find_parent_node(self,node_id):
    
    for edge in self.edges:
      if edge[1] == node_id:
        return edge[0]
      
    msg = "Error to parent node found for s%s for T%s" %(node_id,self.id)
    raise appleseed.AppleseedError(msg)
  
  def uses_link(self,link):
    return link in self.edges
  
  def find_downstream_neighbors(self,node_id):
    
    neighbors = []
    for edge in self.edges:
      if edge[0] == node_id:
        neighbors.append(edge[1])
    
    return neighbors
  
  def compute_host_port_maps(self,node_id,neighbors=None):
    """ The node_id must have at least one connected host.  It is possible that a neighbor is a switch (rather than a host)."""
    if neighbors == None:
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
    
    return host_to_port_map,switch_ports,dst_addresses
 
  
  def install_leaf_flow(self,node_id):
    """ The node_id must have at least one connected host.  It is possible that a neighbor is a switch (rather than a host)."""
    
    host_to_port_map, switch_ports, dst_addresses = self.compute_host_port_maps(node_id)
    
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
    if self.find_ip_address(node_id) == self.root_ip_address:
      return True   
    return False
    
    
  def find_outports(self,node_id):
    out_links = []
    for edge in self.edges:
      if edge[0] == node_id:
        out_links.append(edge)
    
    outports = set()
    for out_link in out_links:
      outport = self.adjacency[(out_link[0],out_link[1])]
      outports.add(outport)
      
    return outports
class PrimaryTree (MulticastTree):
  
  def __init__(self, **kwargs):
    MulticastTree.__init__(self, **kwargs)
    self.backup_trees = {} #edge --> BackupTree
    self.next_bid = 1
    
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
   
  def find_garbage_collect_nodes(self,backup_edge,backup_tree):
    
    unique_edges =  [link for link in self.edges if link not in backup_tree.edges]
    upstream_nodes = set([link[0] for link in unique_edges]) 
    
    return upstream_nodes
    
  def garbage_collect_stale_baseline_flows(self,backup_edge,backup_tree):
    """ Remove primary tree flows made obsolete because the backup tree was activated.
    
        For now, don't actually delete the flows, just update the garbage collection stats."""
    
    garbage_collect_nodes = self.find_garbage_collect_nodes(backup_edge, backup_tree)
    
    global garbage_collection_total
    garbage_collection_total+=len(garbage_collect_nodes)
    
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
    self.diverge_nodes = set() # nodes where backup tree diverges from primary tree
    self.bid = -1   # backup tree id
    self.compute_nodes_to_signal()
    self.compute_diverge_nodes()
    self.proactive_activate_msgs = {}  # switch_id --> ofp_msg
    self.set_bid()
    
  def set_bid(self):
    index = self.primary_tree.next_bid * -1  #pull from end of the backup_tree_id list
    self.bid = backup_tree_ids[index] 
    self.primary_tree.next_bid+=1
    
  def compute_diverge_nodes(self):
    """  check if any of the nodes_to_signal are in primary tree"""
    for node_id in self.nodes_to_signal:
      for p_edge in self.primary_tree.edges:
        if p_edge[0] == node_id and not self.is_host(node_id):
          self.diverge_nodes.add(node_id)
    
  def compute_nodes_to_signal(self):
    """ Precompute the set of nodes we need to signal after a link failure. 
    
    For each backup_tree node (non-switch) add any node that has different outports for the primary tree than backup tree.
    (Old behavior: find the set of edges in the backup tree but not in the primary tree, and save the upstream node id of each edge.)
    """
    if len(self.edges) == 0:
      msg = "Error.  Backup tree has no edges.  Exiting program."
      log.error(msg)
      raise appleseed.AppleseedError(msg)
    upstream_nodes = set([link[0] for link in self.edges])
    signal_nodes = []
    for backup_node in upstream_nodes:
      if self.is_host(backup_node): continue
      primary_ports = self.primary_tree.find_outports(backup_node)
      backup_ports = self.find_outports(backup_node)
      if primary_ports != backup_ports:
        signal_nodes.append(backup_node)
       
    self.nodes_to_signal = self.sort_nodes_bottom_up(signal_nodes)
    

    if self.controller.algorithm_mode == Mode.MERGER:
      # add the parent node of most upstream node, if the parent is not a host (EDIT: adding parent even if its a host)
      most_upstream = self.nodes_to_signal[-1]
      parent = self.find_parent_node(most_upstream)
      self.nodes_to_signal.append(parent)
#      if not self.is_host(parent):
#        self.nodes_to_signal.append(parent)
 
  def find_backup_child_nodes(self,node_id):
    neighbors = []
    for edge in self.edges:
      if edge[0] == node_id:
        neighbors.append(edge[1])
    
    return neighbors
 
  def install_nonleaf_diverge_flow(self,node_id,set_priority_flag=False):
    neighbors = self.find_backup_child_nodes(node_id)
    
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
      
    ofp_match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=self.root_ip_address, nw_dst = self.mcast_address,dl_src=self.bid)
    
    #print "called install_basic_mcast_flow(s%s,root=%s,outport=%s,mcast_addr=%s,priority=%s)" %(node_id,self.root_ip_address,outports,self.mcast_address,priority)
    install_basic_mcast_flow(node_id,self.root_ip_address,outports,self.mcast_address,priority,self.controller,ofp_match)
    
  
  def install_leaf_diverge_flow(self,node_id):
    """ The node_id must have at least one connected host.  It is possible that a neighbor is a switch (rather than a host)."""
    
    neighbors = self.find_backup_child_nodes(node_id)
    host_to_port_map, switch_ports, dst_addresses = self.compute_host_port_maps(node_id,neighbors)
    
    ofp_match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=self.root_ip_address, nw_dst = self.mcast_address,dl_src=self.bid)
    
    priority = self.determine_flow_priority(node_id)    
    install_rewrite_dst_mcast_flow(node_id, self.root_ip_address, host_to_port_map, self.mcast_address, dst_addresses, switch_ports,self.controller,ofp_match,priority) 
  
  
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
  
  def cache_activate_rule(self,node_id):
    """ Create and cache a message with higher priority than other flows, that writes the bid"""
    neighbors = self.find_downstream_neighbors(node_id)
    
    outports = []
    for d_switch in neighbors:
      outport = self.adjacency[(node_id,d_switch)]
      outports.append(outport)
      
    # set the priority later when its time to actually install the activation rule 
    
    msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
    msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=self.root_ip_address, nw_dst = self.mcast_address)
  
    write_bid_action = of.ofp_action_dl_addr.set_src(self.bid)
    msg.actions.append(write_bid_action)
    for prt in outports:
       msg.actions.append(of.ofp_action_output(port = prt))
       
    self.proactive_activate_msgs[node_id] = msg
  
  
  def preinstall_baseline_backups(self):
    log.debug("Baseline Algorithm: Preinstalling backup tree B%s for l=%s" %(self.id,self.backup_edge))
    
    self.preinstall_baseline_basic_rules()
    self.preinstall_baseline_diverge_rules()
    
    # precompute the activatation messages
    # (1): find the nodes one hop from the root,  (2): create a message with higher priority than other flows, that writes the bid
    node_levels = self.compute_node_levels()
    for level_one_node in node_levels[1]:
      self.cache_activate_rule(level_one_node)
    
  def preinstall_baseline_basic_rules(self):
    """ Used by the Proactive Algorithm to preinstall_baseline_backups flow entries.  Signal all nodes in 'self.nodes_to_signal' except the ones that are in diverge_nodes"""
    node_levels = self.compute_node_levels()
    for node_id in self.nodes_to_signal:
      if node_id in self.diverge_nodes or node_id in node_levels[1]: continue
      
      if self.is_leaf_node(node_id):
        log.debug("Baseline Algorithm: Preinstalling basic flow entry at s%s for backup tree B%s for l=%s" %(node_id,self.id,self.backup_edge))
        self.install_leaf_flow(node_id)
      else:
        #is_most_upstream = (node_id == self.nodes_to_signal[-1])
        #if is_most_upstream:
        #  continue
        log.debug("Baseline Algorithm: Preinstalling basic flow entry at s%s for backup tree B%s for l=%s" %(node_id,self.id,self.backup_edge))
        self.install_nonleaf_flow(node_id)
  
  def preinstall_baseline_diverge_rules(self):
    """ Used by the Proactive Algorithm to preinstall_baseline_backups flow entries at nodes that diverge from the primary tree.  These nodes match using the backup tree id."""
    node_levels = self.compute_node_levels()
    for node_id in self.diverge_nodes:
      if node_id in node_levels[1]: continue
      if self.is_leaf_node(node_id):
        log.debug("Baseline Algorithm: Preinstalling flow entry matching at s%s for backup tree B%s for l=%s with bid=%s" %(node_id,self.id,self.backup_edge,self.bid))
        self.install_leaf_diverge_flow(node_id)
      else:
        log.debug("Baseline Algorithm: Preinstalling flow entry at s%s for backup tree B%s for l=%s with bid=%s" %(node_id,self.id,self.backup_edge,self.bid))
        self.install_nonleaf_diverge_flow(node_id)
       
  def proactive_activate(self): 
    for switch_id in self.proactive_activate_msgs.keys():
      ofp_msg =  self.proactive_activate_msgs[switch_id]
      ofp_msg.priority = self.determine_flow_priority(switch_id)    # set this relative to the current flow entry priorities
      utils.send_msg_to_switch(ofp_msg, switch_id)
      self.controller.cache_flow_table_entry(switch_id, ofp_msg)
        
  def reactive_install(self):
    """ Reactive Algorithm.  Signal switches bottom up to activate backup tree."""
    for node_id in self.nodes_to_signal:
      if self.is_leaf_node(node_id):
        self.install_leaf_flow(node_id)
      else:
        is_most_upstream = (node_id == self.nodes_to_signal[-1])
        self.install_nonleaf_flow(node_id,is_most_upstream)
  
  def get_most_upstream_node(self):
    if self.controller.algorithm_mode == Mode.MERGER:
      candidate = self.nodes_to_signal[-1]
      if self.is_host(candidate):
        return self.nodes_to_signal[-2] #because we add the host to signal set in order to create backup flow entries
      return self.nodes_to_signal[-1]
    elif self.controller.algorithm_mode == Mode.BASELINE:
      return self.nodes_to_signal[-1]
  
  def activate_baseline_backups(self):
    """ Baseline Algorithm for recovery."""
    if self.controller.backup_tree_mode == BackupMode.REACTIVE:
      self.reactive_install()
    elif self.controller.backup_tree_mode == BackupMode.PROACTIVE:    # only need signal the most upstream node
      self.proactive_activate()
    
    msg = "============== Backup Tree Activated =============="
    log.info(msg)
    
    self.primary_tree.garbage_collect_stale_baseline_flows(self.backup_edge,self)
    
  def activate(self):
    """ Activate the backup tree.  For Proactive, signal the most upstream node.  For reactive signal all relevant nodes bottom up. 
    
        Note: this means that we are signalling one tree at-a-time to activate backups, rather than iterating over the set of switches and sending messages
              for all backup trees to that switch before moving to the next switch.
    """
#    if self.controller.algorithm_mode == Mode.MERGER:
#      self.activate_merger_backups()
    if self.controller.algorithm_mode == Mode.BASELINE:
      self.activate_baseline_backups()
    elif self.controller.algorithm_mode == Mode.MERGER_DEPRACATED:
      raise appleseed.AppleseedError("No implementation of backup tree activation for MERGER_DEPRACATED mode.")
    else:
      raise appleseed.AppleseedError("No relevant optimization strategy set.  Exiting.")
    
    
  def __str__(self):
    unique_edges =  [link for link in self.edges if link not in self.primary_tree.edges]
    return "(%s,%s) --> unique-edges: %s" %(self.mcast_address,self.backup_edge,unique_edges)
  
  def __repr__(self):
    return self.__str__()

class Edge ():
  
  def __init__(self):
    self.upstream_node = None
    self.downstream_node = None
    self.trees = set()
    self.tags = set()     # list of tags written or reused for packets sent along this link
    
    self.backup_trees = {}      # backup_edge --> set(tree_id2,tree_id2,...)
    self.backup_tags = {}     # backup_edge --> Tag 
  
  def add_backup_tree(self, tree_id,backup_edge):
    if self.backup_trees.has_key(backup_edge):
      self.backup_trees[backup_edge].add(tree_id)
    else:
      btrees = set()
      btrees.add(tree_id)
      self.backup_trees[backup_edge] = btrees
    
    #print "\t\t %s, l=%s --> add BT%s " %(self.end_points_str(),backup_edge,tree_id)
  
  def add_backup_tag(self,tag,backup_edge):
    if self.backup_tags.has_key(backup_edge):
      self.backup_tags[backup_edge].add(tag)
    else:
      btags = set()
      btags.add(tag)
      self.backup_tags[backup_edge] = btags
  
  def has_tag(self,tag):
    for action_tag in self.tags:
      if action_tag == tag:
        return True
    return False
  
  def add_tag(self,tag):
    if not self.has_tag(tag):
      self.tags.add(tag)
    
  def print_if_marked(self):
    """ Only prints output if the Edge is used by a tree of backup tree"""
    tree_strs = []
    for id in self.trees:
      tstr = "T%s" %(id)
      tree_strs.append(tstr)
      
    backup_strs = []
    if len(self.backup_trees) > 0:
      
      for backup_edge in self.backup_trees:
        bstr="b_edge="
        bstr += str(backup_edge)
        bstr += ", ("
        for id in self.backup_trees[backup_edge]:
          bstr += "B%s," %(id)
        bstr +=")"
        backup_strs.append(bstr)
    
    if len(tree_strs) == 0 and len(backup_strs) == 0:
      return
    if len(backup_strs) == 0:
      print "\t (%s,%s), %s " %(self.upstream_node.id,self.downstream_node.id,tree_strs)
    else:
      print "\t (%s,%s), P=%s, B=%s" %(self.upstream_node.id,self.downstream_node.id,tree_strs,backup_strs)
   
  def end_points_str(self):
    return "(%s,%s)" %(self.upstream_node.id,self.downstream_node.id)
  
  def __str__(self):
    tree_strs = []
    for id in self.trees:
      tstr = "T%s" %(id)
      tree_strs.append(tstr)
      
    backup_strs = []
    if len(self.backup_trees) > 0:
      
      for backup_edge in self.backup_trees:
        bstr="b_edge="
        bstr += str(backup_edge)
        bstr += ", ("
        for id in self.backup_trees[backup_edge]:
          bstr += "B%s," %(id)
        bstr +=")"
        backup_strs.append(bstr)
    
    if len(backup_strs) == 0:
      return "(%s,%s), %s " %(self.upstream_node.id,self.downstream_node.id,tree_strs)
    else:
      return "(%s,%s), P=%s,B=%s" %(self.upstream_node.id,self.downstream_node.id,tree_strs,backup_strs)
  
  def __repr__(self):
    return self.__str__()    

TagType = enum(NONE=-1,GROUP_REUSE=0,GROUP=1,SINGLE=2,SINGLE_REUSE=3,MCAST_DST_ADDR=4,HOST_DST_ADDR=5,BACKUP_ID=6)    

class Tag ():
  
  def __init__(self,type,tag=None):
    self.value = tag
    self.type = type    #TagType: SINGLE is for tree specific address, MCAST_DST_ADDR is for matching using destination address, HOST_DST_ADDR is for rewritng host dest addres
    self.extras = None  # hack to store the MCAST Address for TagType =  BACKUP_ID
  def __eq__(self,other):
#    if self.type == TagType.NONE or other.type == TagType.NONE:
#      return False
    if self.type == other.type and self.value == other.value:
      return True
    return False
  
  def __hash__(self):
    #print "\t\t\t\t\t\t\t\t\t\t\t \t\t\t%s= %s" %(self,hash(self.type) + hash(self.value))
    return hash(self.type) + hash(self.value)
  
  def __str__(self):
    if self.type == TagType.NONE:
       return "(None,%s)" %(self.value)
    if self.type == TagType.GROUP_REUSE:
       return "(Group_Reuse,%s)" %(self.value)
    if self.type == TagType.GROUP:
       return "(Group,%s)" %(self.value)
    if self.type == TagType.SINGLE:
       return "(Single,%s)" %(self.value)
    if self.type == TagType.SINGLE_REUSE:
       return "(Single_Reuse,%s)" %(self.value)
    if self.type == TagType.MCAST_DST_ADDR:
       return "(Mcast_Dst,%s)" %(self.value)
    if self.type == TagType.HOST_DST_ADDR:
       return "(Host_Dst,%s)" %(self.value)
    if self.type == TagType.BACKUP_ID:
       return "(Bid,%s)" %(self.value)
     
class Node ():
  
  def __init__(self,id,is_host):
    self.id = id
    self.is_host = is_host
    self.in_links = set()
    self.out_links = set()
    
    self.treeid_rule_map = {}  # tree_id --> FlowEntry
    self.flow_entries = set()
    self.installed_ofp_rules = set()
    
    self.backup_treeid_rule_map = {}  # backup_edge --> {tree_id --> flow_entry}
    self.backup_flow_entries = {} # backup_edge --> flow_entries (set)
    self.backup_tagging_completed = {} # backup_edge --> set(btree_ids)
    
    self.preinstalled_backup_ofp_rules = {}   # For Proactive Mode: backup_edge --> ofp_rules (set).  Rules are installed
    self.cached_write_bid_ofp_rules = {}    # For Proactive Mode: backup_edge --> ofp_rules (set).  Rules are not installed
    self.precomputed_backup_ofp_rules = {}    # For Reactive Mode: backup_edge --> ofp_rules (set).  Rules are not installed.
    
    
  def garbage_collect_merge_flows(self,ptree_id,backup_edge,all_affected_primary_trees):
    """ For now just returns the flow so we can compute the stats of # flows to remove"""
    flow_entry = self.treeid_rule_map[ptree_id]
    
    for pt_id in self.treeid_rule_map.keys():
     # if pt_id == ptree_id: continue
      if pt_id in all_affected_primary_trees: continue
      pt_flow = self.treeid_rule_map[pt_id]
      if flow_entry.match_tag == pt_flow.match_tag:
        return False,None
    
    if not self.backup_flow_entries.has_key(backup_edge):
      return True,flow_entry.match_tag
    
    # if we are at u* node
    if self.backup_treeid_rule_map[backup_edge].has_key(ptree_id):
      return True,flow_entry.match_tag
    
    for backup_flow in self.backup_flow_entries[backup_edge]:
      if flow_entry.match_tag == backup_flow.match_tag:
        return False,None
      
    return True,flow_entry.match_tag
    
  def update_flow_entry_priority(self,tree_id,new_priority):
    
    flow_entry = self.treeid_rule_map[tree_id]
    flow_entry.priority = new_priority
    
    for flow in self.flow_entries:
      if flow.match_tag == flow_entry.match_tag:
        flow.priority = new_priority
    return flow_entry
  
  def has_match_tag(self,match_tag):
    for flow_entry in self.flow_entries:
      if flow_entry.match_tag == match_tag:
        return True
    return False
  
  def has_backup_match_tag(self,match_tag,backup_edge):
    if not self.backup_flow_entries.has_key(backup_edge):
      return False
    for flow_entry in self.backup_flow_entries[backup_edge]:
      if flow_entry.match_tag != None and flow_entry.match_tag == match_tag:
        return True
    return False

  def already_processed(self,backup_edge,tree_id):
    """ Check if the a flow entry match has already been created at this node for given backup_edge and tree_id"""
    if not self.backup_tagging_completed.has_key(backup_edge):
      return False
    trees = self.backup_tagging_completed[backup_edge]
    
    return tree_id in trees
 
  def add_backup_tagging_completed(self,backup_edge,btree_id):
    if self.backup_tagging_completed.has_key(backup_edge):
      self.backup_tagging_completed[backup_edge].add(btree_id)
    else:
      completed = set()
      completed.add(btree_id)
      self.backup_tagging_completed[backup_edge] = completed
 
     
  def add_backup_treeid_rule(self,backup_edge,tree_id,flow_entry):
    if self.backup_treeid_rule_map.has_key(backup_edge):
      map = self.backup_treeid_rule_map[backup_edge]
      map[tree_id] = flow_entry
    else:
      map = {tree_id:flow_entry}
      self.backup_treeid_rule_map[backup_edge] = map
    
  def has_empty_match_backup_treeid_rule(self,backup_edge,tree_id,flow_entry):
    if self.backup_treeid_rule_map.has_key(backup_edge):
      map = self.backup_treeid_rule_map[backup_edge]
      if map.has_key(tree_id) and map[tree_id].match_tag.type == TagType.NONE:
        return True,map[tree_id]
    return False, None

  def add_backup_flow_entry(self,backup_edge,new_flow_entry):
    if self.backup_flow_entries.has_key(backup_edge):
      flows = self.backup_flow_entries[backup_edge]
      # need special logic here to remove an existing flow(s) from 'backup_flow_entries' with an empty match and the same outport_tags as new_flow_entry 
      remove_flows = set()
      for flow in flows:
        if flow.match_tag == new_flow_entry.match_tag and flow.outport_tags.keys() == new_flow_entry.outport_tags.keys():
          remove_flows.add(flow)
      for flow in remove_flows: flows.discard(flow)
      flows.add(new_flow_entry)
    else:
      flows = set()
      flows.add(new_flow_entry)
      self.backup_flow_entries[backup_edge]= flows 

  def has_backup_treeid_rule(self,backup_edge,tree_id):
    if self.backup_treeid_rule_map.has_key(backup_edge):
      map = self.backup_treeid_rule_map[backup_edge]
      return map.has_key(tree_id)
    else:
      return False

  def add_preinstalled_backup_ofp_rule(self,backup_edge,ofp_rule):
    if self.preinstalled_backup_ofp_rules.has_key(backup_edge):
      rules = self.preinstalled_backup_ofp_rules[backup_edge]
      rules.add(ofp_rule)
    else:
      rules = set()
      rules.add(ofp_rule)
      self.preinstalled_backup_ofp_rules[backup_edge]= rules
       

  def save_write_bid_ofp_rule(self,backup_edge,ofp_rule):
    if self.cached_write_bid_ofp_rules.has_key(backup_edge):
      rules = self.cached_write_bid_ofp_rules[backup_edge]
      rules.add(ofp_rule)
    else:
      rules = set()
      rules.add(ofp_rule)
      self.cached_write_bid_ofp_rules[backup_edge]= rules
       

  def add_precomputed_backup_ofp_rule(self,backup_edge,ofp_rule):
    if self.precomputed_backup_ofp_rules.has_key(backup_edge):
      rules = self.precomputed_backup_ofp_rules[backup_edge]
      rules.add(ofp_rule)
    else:
      rules = set()
      rules.add(ofp_rule)
      self.precomputed_backup_ofp_rules[backup_edge]= rules
       
  def generate_ofp_rule(self,flow_entry,controller,node_id,backup_rule = True,backup_tree=None): 
    rule = of.ofp_flow_mod(command=of.OFPFC_ADD)
    rule.match = flow_entry.generate_ofp_match(backup_tree)
    
    highest_priority = flow_entry.priority
    if backup_rule:
      for pt_flow in self.flow_entries:
        if pt_flow.priority > highest_priority:
          highest_priority = pt_flow.priority

    rule.priority = highest_priority+1
    flow_entry.generate_ofp_actions(rule,controller,node_id,backup_tree)
    return rule

  def generate_ofp_rules(self,controller,node_id):
    """ Iterate through self.flow_entries and create ofp_rule"""
    for flow_entry in self.flow_entries:
      rule = self.generate_ofp_rule(flow_entry,controller,node_id)
      self.installed_ofp_rules.add(rule)
 
  def generate_backup_ofp_rules(self,controller,backup_edge,level_one_trees=None): 
    """ Iterate through self.backup_flow_entries and create ofp_rule as long as that FlowEntry does not correspond to a tree where self is a level one node."""
    if not self.backup_flow_entries.has_key(backup_edge): return
    for flow_entry in self.backup_flow_entries[backup_edge]:
      if flow_entry.is_placeholder:
        continue
      if level_one_trees != None:   # skip if  FlowEntry corresponds to a tree where self is a level one node
        if self.is_level_one_tree_node(backup_edge,level_one_trees,flow_entry):
          continue
      rule = self.generate_ofp_rule(flow_entry,controller,self.id,backup_rule = True)

      if controller.backup_tree_mode == BackupMode.REACTIVE:
        self.add_precomputed_backup_ofp_rule(backup_edge,rule)
      elif controller.backup_tree_mode == BackupMode.PROACTIVE:
        self.add_preinstalled_backup_ofp_rule(backup_edge, rule)
        
  def is_level_one_tree_node(self,backup_edge,level_one_trees,flow_entry):
    for tree_id in level_one_trees:
      if not self.backup_treeid_rule_map[backup_edge].has_key(tree_id): 
        continue
      candidate_flow_entry = self.backup_treeid_rule_map[backup_edge][tree_id]
      if flow_entry.match_tag == candidate_flow_entry.match_tag and flow_entry.outport_tags == candidate_flow_entry.outport_tags:
        return True
    return False 
      
  def cache_merger_activate_backup_rules(self,controller,backup_edge,btree): 
    # (1) create the FlowEntry object, (2) generate the rule and (3) save the rule
    pt_flow_entry = self.treeid_rule_map[btree.id]
    write_bid_flow_entry = FlowEntry()
    write_bid_flow_entry.write_bid_flow = True
    write_bid_flow_entry.match_tag = pt_flow_entry.match_tag
    
    write_bid_flow_entry.priority = pt_flow_entry.priority +1 # this priority number is overwritten when the activation takes place based on the priorities of existing flows at the time of activation
    
    # check if there is a backup tree flow entry, if so inherit its actions, otherwise use the pt_flow_entry
    if self.backup_treeid_rule_map.has_key(backup_edge) and self.backup_treeid_rule_map[backup_edge].has_key(btree.id):
      backup_flow_entry= self.backup_treeid_rule_map[backup_edge][btree.id]
      write_bid_flow_entry.outport_tags = backup_flow_entry.outport_tags
      del self.backup_treeid_rule_map[backup_edge][btree.id]
      self.backup_flow_entries[backup_edge].remove(backup_flow_entry)
    else:
      write_bid_flow_entry.outport_tags = pt_flow_entry.outport_tags
    
    self.add_backup_flow_entry(backup_edge, write_bid_flow_entry)
    self.add_backup_treeid_rule(backup_edge, btree.id, write_bid_flow_entry)
    
    log.debug("B%s l=%s activate backup rule at s%s = %s " %(btree.id,backup_edge,self.id,write_bid_flow_entry))
    
    rule = self.generate_ofp_rule(write_bid_flow_entry,controller,self.id,backup_rule = True,backup_tree=btree)
    
    #print rule
    
    self.save_write_bid_ofp_rule(backup_edge, rule)
  
  def install_precomputed_backup_ofp_rules(self,controller,backup_edge,safe_priority):
    for ofp_rule in self.precomputed_backup_ofp_rules[backup_edge]:
      ofp_rule.priority = safe_priority
      #print "s%s match=%s \n " %(self.id,ofp_rule.match)
      utils.send_msg_to_switch(ofp_rule, self.id)
      controller.cache_flow_table_entry(self.id, ofp_rule)
      
  def install_cached_write_bid_ofp_rules(self,controller,backup_edge,safe_priority):
    for ofp_rule in self.cached_write_bid_ofp_rules[backup_edge]:
      ofp_rule.priority = safe_priority
      #print "ACTIVATE: s%s match=%s \n " %(self.id,ofp_rule.match)
      utils.send_msg_to_switch(ofp_rule, self.id)
      controller.cache_flow_table_entry(self.id, ofp_rule)
     
  def preinstall_merged_backup_ofp_rules(self,controller,backup_edge): 
    """ Note: we do NOT want to install the flows for u_star nodes."""
    for ofp_rule in self.preinstalled_backup_ofp_rules[backup_edge]:
      #print "PREINSTALL: s%s match=%s \n " %(self.id,ofp_rule.match)
      utils.send_msg_to_switch(ofp_rule, self.id)
      controller.cache_flow_table_entry(self.id, ofp_rule)
    
  def install_ofp_rules(self,controller):
    """ Install the ofp_rules."""
    for rule in self.installed_ofp_rules:
      utils.send_msg_to_switch(rule, self.id)
      controller.cache_flow_table_entry(self.id, rule)
     
  def print_proactive_backup_ofp_rules(self,backup_edge):
    """ Install the ofp_rules."""
    if not self.preinstalled_backup_ofp_rules.has_key(backup_edge) and not self.cached_write_bid_ofp_rules.has_key(backup_edge): return
    cnt = 0
    print "S%s, l=%s Proactive Mode Rules ------------------------------------------------------------------------------------------------------------------------------------------------------------" %(self.id,backup_edge)
    if self.preinstalled_backup_ofp_rules.has_key(backup_edge):
      for rule in self.preinstalled_backup_ofp_rules[backup_edge]:
        cnt+=1
        print "S%s, l=%s Rule %s " %(self.id,backup_edge, cnt)
        print "%s \n" %(utils.get_ofp_rule_str(rule))     
    if self.cached_write_bid_ofp_rules.has_key(backup_edge):
      for rule in self.cached_write_bid_ofp_rules[backup_edge]:
        cnt+=1
        print "S%s, l=%s Rule %s " %(self.id,backup_edge, cnt)
        print "%s \n" %(utils.get_ofp_rule_str(rule))     
   
  def print_reactive_backup_ofp_rules(self,backup_edge):
    if not self.precomputed_backup_ofp_rules.has_key(backup_edge): return
    cnt = 0
    print "S%s, l=%s Reactive Mode Rules ------------------------------------------------------------------------------------------------------------------------------------------------------------" %(self.id,backup_edge)
    for rule in self.precomputed_backup_ofp_rules[backup_edge]:
      cnt+=1
      print "S%s, l=%s Rule %s " %(self.id,backup_edge, cnt)
      print "%s \n" %(utils.get_ofp_rule_str(rule))

  def print_ofp_rules(self):
    cnt = 0
    print "S%s Rules ------------------------------------------------------------------------------------------------------------------------------------------------------------" %(self.id)
    for rule in self.installed_ofp_rules:
      cnt+=1
      print "S%s Rule %s " %(self.id,cnt)
      print "%s \n" %(utils.get_ofp_rule_str(rule))
  

class FlowEntry(): 

  def __init__(self):
    self.match_tag = Tag(TagType.NONE)   # Tag
    self.outport_tags = {}  # outport -> Tag  (value can be None if we are reusing a value, host_id if we need to write the host_id, of )
    self.is_placeholder = False  # True for backup tree flow entry writing or reusing the tag of a primary tree
    self.write_bid_flow = False
    self.priority = of.OFP_DEFAULT_PRIORITY
  
  def add_outport_tag(self,outport,tag):
    if self.outport_tags.has_key(outport):
      if self.outport_tags[outport] == tag:
        return
    self.outport_tags[outport] = tag
  
  def generate_ofp_actions(self,ofp_rule,controller,switch_id,backup_tree=None):
    """ Need to order the actions with the no tagging rules first and then rules with tagging to ensure tags are applied or not applied correclty on each outport  """
    # (0) write the bid if appropriate (no port binding because action applies to all outports
    if self.write_bid_flow and backup_tree != None:
      write_bid_action = of.ofp_action_dl_addr.set_src(backup_tree.bid)
      ofp_rule.actions.append(write_bid_action)
    
    # (1) process the no action rules 
    for outport in self.outport_tags:
      tag = self.outport_tags[outport]
      
      if tag.type == TagType.SINGLE_REUSE or tag.type == TagType.GROUP_REUSE or tag.type == TagType.MCAST_DST_ADDR:
        ofp_rule.actions.append(of.ofp_action_output(port = outport))
      
    # (2) process the non-host rewrite action rules
    for outport in self.outport_tags:
      tag = self.outport_tags[outport]
      
      if tag.type == TagType.GROUP or tag.type == TagType.SINGLE:
         write_tag_action = of.ofp_action_dl_addr.set_dst(tag.value)
         ofp_rule.actions.append(write_tag_action)
         ofp_rule.actions.append(of.ofp_action_output(port = outport))
          
    # (3) process the host rewrite actions      
    for outport in self.outport_tags:
      tag = self.outport_tags[outport]
      
      if tag.type == TagType.HOST_DST_ADDR:
        l2_addr=-1
        if len(controller.arpTable) == 0:   # this is for unit tests
          l2_addr = dummy_mac_addr
        else:
          l2_addr = controller.arpTable[switch_id][tag.value].mac
        write_l2_action = of.ofp_action_dl_addr.set_dst(l2_addr)
        ofp_rule.actions.append(write_l2_action)
        write_l3_action = of.ofp_action_nw_addr.set_dst(tag.value)
        ofp_rule.actions.append(write_l3_action)
        ofp_rule.actions.append(of.ofp_action_output(port = outport))
        
        
  def generate_ofp_match(self,backup_tree=None):
    
    if self.match_tag.type == TagType.BACKUP_ID:
      self.priority = self.priority + 1
      return of.ofp_match(dl_type = ethernet.IP_TYPE, nw_dst = self.match_tag.extras, dl_src = self.match_tag.value)
    elif self.match_tag.type == TagType.GROUP_REUSE or self.match_tag.type == TagType.GROUP or self.match_tag.type == TagType.SINGLE or self.match_tag.type ==TagType.SINGLE_REUSE:
      return of.ofp_match(dl_type = ethernet.IP_TYPE, dl_dst = self.match_tag.value) 
    elif self.match_tag.type == TagType.MCAST_DST_ADDR:
      self.priority = self.priority + 1
      return of.ofp_match(dl_type = ethernet.IP_TYPE, nw_dst = self.match_tag.value)
    elif self.match_tag.type == TagType.HOST_DST_ADDR:
      msg = "trying to create a match rule using host destination address = %s.  This should never happen.  Exiting" %(self.match_tag.value)
      raise appleseed.AppleseedError(msg)
    
  def __str__(self):
    out_str = ""
    if self.is_placeholder:
      out_str += "Placeholder, "
    if self.write_bid_flow:
      out_str += "M=%s, A=Bid,{" %(self.match_tag)
    else:
      out_str += "M=%s, A={" %(self.match_tag)
    for outport in self.outport_tags.keys():
      tag = self.outport_tags[outport]
      out_str += "%s:%s," %(outport,tag)

    out_str += "}"
    return out_str
    
