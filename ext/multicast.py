# @author: dpg/gyllstar/Dan Gyllstrom


""" Implements multicast.

This module contains helper functions called by the controller to implement multicast,
along with some data structures to create and manage multicast trees (Tree and PrimaryTree).

"""


import utils, appleseed,pcount
from pox.lib.addresses import IPAddr,EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.core import core
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

#measure_pnts_file_str="measure-6s-2d-2p.csv"
#measure_pnts_file_str="measure-4s-3d-1p.csv"
#measure_pnts_file_str="measure-4s-2d-1p.csv"
#measure_pnts_file_str="measure-4s-1p.csv"
#measure_pnts_file_str="measure-3s-2p.csv"
#measure_pnts_file_str="measure-3s-1p.csv"
#measure_pnts_file_str="measure-3s-2d-1p.csv"
#measure_pnts_file_str="measure-2s-2p.csv"
measure_pnts_file_str="measure-2s-1p.csv"

mtree_file_str="mtree-4s-1t.csv"
#mtree_file_str="mtree-6s-2t.csv"
#################### End of Hard-coded IP addresses and config files ####################


installed_mtrees=[] #list of multicast addresses with an mtree already installed

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

def install_rewrite_dst_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,new_dst,controller):
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
  
def install_basic_mcast_flow(switch_id,nw_src,ports,nw_mcast_dst,controller):
  """ Install a flow table rule using the multicast destination address and list of outports  """

  msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
  msg.match = of.ofp_match(dl_type = ethernet.IP_TYPE, nw_src=nw_src, nw_dst = nw_mcast_dst)
  
  for prt in ports:
    msg.actions.append(of.ofp_action_output(port = prt))
  
  utils.send_msg_to_switch(msg, switch_id)
  controller.cache_flow_table_entry(switch_id, msg)
  
def setup_mtree(nw_src,nw_mcast_dst,inport,controller):
  """ Hard-coded setup of mutlicast trees using the switch_id numbers. """
  if nw_mcast_dst == mcast_ip_addr1:
    mtree1_switches = []
    primary_tree = []
    if len(controller.mcast_groups.keys()) == 2:
      mtree1_switches = [10,11,13,12]
      primary_tree = [(13,12),(12,11),(12,10)]
    else:
      mtree1_switches = [7,6,5,4]
      primary_tree = [(7,6),(6,4),(6,5)]
    
    controller.primary_trees[nw_mcast_dst] = primary_tree
    return setup_mtree1_flow_tables(nw_src, nw_mcast_dst, inport,mtree1_switches,controller)
  elif nw_mcast_dst == mcast_ip_addr2:
    mtree2_switches = []
    primary_tree = []
    if len(controller.mcast_groups.keys()) == 2:
      mtree2_switches = [10,14,15]
      primary_tree = [(15,14),(15,10)]
    
    controller.primary_trees[nw_mcast_dst] = primary_tree  #TODO REFACTOR !!!!!!!!!!!!!!!!!!!
    return setup_mtree2_flow_tables(nw_src, nw_mcast_dst, inport,mtree2_switches,controller)
  

# should really use self.mcast_groups to determine which hosts are a part of the multicast group and tree
# should have some way to determine which hosts are downstream from a given switch, rather than hard coding this  
def setup_mtree1_flow_tables(nw_src,nw_mcast_dst,inport,mtree_switches,controller):
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
  controller.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h2]
  
  # s4: rewrite destination address from 10.10.10.10 to h1 (10.0.0.1)
  switch_id = mtree_switches[3]
  s4_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h1)
  depracted_install_rewrite_dst_mcast_flow(switch_id, nw_src, s4_ports, nw_mcast_dst, h1,controller)  
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s4_ports,mcast_mac_addr) 
  controller.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h1]
  
  global installed_mtrees
  installed_mtrees.append(nw_mcast_dst)
  
  u_switch_id,d_switch_ids = find_mcast_measure_points(nw_src,mcast_ip_addr1,controller)
  
  return u_switch_id, d_switch_ids

def setup_mtree2_flow_tables(nw_src,nw_mcast_dst,inport,mtree_switches,controller):
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
  #self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h5]
  h5_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h5)
  h6_ports = utils.find_nonvlan_flow_outport(controller.flowTables,switch_id, nw_src, h6)
  s14_ports = {h5:h5_ports, h6:h6_ports}
  depracted_install_rewrite_dst_mcast_flow(switch_id, nw_src, s14_ports, nw_mcast_dst, [h5,h6],controller)
  controller.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h5,h6]
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
  #self.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h7]
  controller.mtree_dstream_hosts[(nw_src,nw_mcast_dst,switch_id)] = [h7,h8,h9]
  controller.arpTable[switch_id][nw_mcast_dst] = appleseed.Entry(s15_ports,mcast_mac_addr) 
  
  global installed_mtrees
  installed_mtrees.append(nw_mcast_dst)
  
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
  """ Temporary solution is just use the multicast groups read from a text file (see utils.read_mtree_file).  Would like to generate multicast groups w/ a random process."""
  
  return controller.mcast_groups

def compute_primary_trees(controller):
  """ In the short-term the primary trees are hard-coded.  This is where the code for computing the Steiner Arboresence approxiation goes. """
  
  
  num_switches = len(core.openflow_discovery._dps)
  
  discover = core.openflow_discovery
  
  for mcast_addr in controller.mcast_groups.keys():
    
    end_hosts = controller.mcast_groups[mcast_addr]
    root = end_hosts[0]
    terminal_hosts = end_hosts[1:]
    
    #some check here for # of switches
    edges = []

    # some temporary hard-coding going on here 
    if mcast_addr == mcast_ip_addr1:
      if num_switches == 4:
        #edges = [(7,6),(6,4),(6,5)]
        edges = [(3,7),(7,6),(6,4),(6,5),(4,1),(5,2)]
      elif num_switches == 6:
        #edges = [(3,13),(13,12),(12,11),(12,10),(4,1),(5,2)]
        edges = [(3,10),(10,11),(11,12),(11,13),(12,1),(13,2)]
    elif mcast_addr == mcast_ip_addr2:
      if num_switches == 6:
        edges = [(4,10),(10,14),(10,15),(14,5),(14,6),(15,7),(15,8),(15,9)]
      else:
        msg = "should be 6 switches in topology when using the hard-coded multicast address %s" %(mcast_ip_addr2)
        log.error(msg)
        raise appleseed.AppleseedError(msg)
    data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
    tree = PrimaryTree(**data)
    
    controller.trees_rename.append(tree)




def install_primary_trees(controller):
  """  Want this to take place after the adjacency matrix is populated."""
  
  mcast_groups = generate_multicast_groups(controller)
  
  compute_primary_trees(controller)
  
  for tree in controller.trees_rename:
    tree.install()
    u_switch_id, d_switch_ids = pcount.get_tree_measure_points(tree.root_ip_address,tree.mcast_address,controller)
    core.callDelayed(pcount.PCOUNT_CALL_FREQUENCY,pcount.start_pcount_thread,u_switch_id, d_switch_ids,tree.root_ip_address,tree.mcast_address,controller)
          # CALL PCOUNT HERE???
  #start_pcount,u_switch_id,d_switch_ids = pcount.check_start_pcount(dpid,match.nw_src,match.nw_dst,self)
  #pcount.start_pcount_thread(u_switch_id, d_switch_ids, match.nw_src, match.nw_dst,self)
  
  
def find_node_id(ip_address):
  """ Takes the IP Address of a node and returns its node id number. 
  
  We asssume that the last value in IP address corresponds to the node id. For example, IP address of
  10.0.0.8 has node id of 8"
  """
  ip_str = str(ip_address)
  parse = ip_str.split(".")
  id = parse[-1]
  return int(id) 
     

#####################################################################################################

class MulticastTree ():
  """ Multicast Tree Abstraction """
  
  def __init__(self,**kwargs):
    self.edges = kwargs["edges"]
    self.mcast_address = kwargs["mcast_address"]
    self.root_ip_address = kwargs["root"]
    self.terminal_ip_addresses = kwargs["terminals"]
    self.node_levels = []  #list of lists, index 0 is for level 0 nodes, index 1 is for level 1 nodes, ...
    self.adjacency = kwargs["adjacency"]
    self.controller = kwargs["controller"]
    
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
    
  def compute_node_levels(self):
    """ Finds the level in the tree each node occupies.  Populates node_and_level_list"""
    level = 0
    id = find_node_id(self.root_ip_address)
    upstream_ids = [id]
    while len(upstream_ids)>0:
      self.node_levels.append(upstream_ids)
      downstream_ids = []
      for id in upstream_ids:
        downstream = self.find_downstream_neighbors(id)
        downstream_ids = downstream_ids + downstream
      level+=1
      upstream_ids = downstream_ids
    
    
  def sort_nodes_bottom_up(self,nodes_to_signal):
    print "placeholder"
    
    
class PrimaryTree (MulticastTree):
  
  def __init__(self, **kwargs):
    MulticastTree.__init__(self, **kwargs)
    self.backup_trees = {}  # (link) -> Tree
  
  def find_nodes_to_signal(self,failed_link):
    """ Find the set of edges in the backup tree, for the given link, but not in the primary tree, and return the upstream node id of each edge"""
    
    backup_tree_edges = self.backup_trees[failed_link].edges
    unique_edges =  [link for link in backup_tree_edges if link not in self.edges]
    
    upstream_nodes = [link[0] for link in unique_edges] 
    
    return upstream_nodes
  
  def install_leaf_flow(self,node_id):
    
    neighbors = self.find_downstream_neighbors(node_id)
    
    host_to_port_map= {}
    dst_addresses = []
    for host in neighbors:
      ip_addr = self.find_ip_address(host)
      dst_addresses.append(ip_addr)
      outport = self.adjacency[(node_id,host)]  # won't be in there until i figure out how to do the host discovery
      host_to_port_map[ip_addr] = outport
      
    # create and install a flow entry
    install_rewrite_dst_mcast_flow(node_id, self.root_ip_address, host_to_port_map, self.mcast_address, dst_addresses, self.controller)
    
  def install_nonleaf_flow(self,node_id):
    neighbors = self.find_downstream_neighbors(node_id)
    
    outports = []
    for d_switch in neighbors:
      outport = self.adjacency[(node_id,d_switch)]  
      outports.append(outport)
    
    install_basic_mcast_flow(node_id,self.root_ip_address,outports,self.mcast_address,self.controller)
    
  def install(self):
    
    # (1) order nodes from top to bottom
    self.compute_node_levels()
    
    # (2) install each flow entry (bottom-up) -- skip the root and leaf nodes because these are hosts and no flow entry is needed
    leaf_level = len(self.node_levels)-2
    
    for level in range(leaf_level,0,-1):
      
      for id in self.node_levels[level]:
        if level == leaf_level:
          self.install_leaf_flow(id)
        else:
          self.install_nonleaf_flow(id)
    
    
    
    
  
  
  def __str__(self):
    
    return "%s-->%s" %(self.mcast_address,self.edges)
  
  def __repr__(self):
    return self.__str__()




###############################################################################################################################################################################

class BackupTreeInstaller ():
  """ TODO document
  
  Note: probably should be a singleton or don't need
  
  """
  
  def __init__ (self):

    #self.flowTables = {}  # copy of the flow tables from fault_tolerant_controller
    #self.arpTable = {}
    #self.primary_trees = {}
    
     # multicast_dst_address,link -> list of tuples (u,d), representing a directed edge from u to d, that constitute all edges in the backup tree
    self.backup_trees = {}
    
    self.controller = None # fault_tolerant_controller instance
 
   
  def preinstall_backup_trees(self,controller):
    
    print "not sure if we need this"
    
  
  def activate_preinstalled_backup_trees(self):
    print "not sure if we need this"
    
    
  def _sort_nodes_bottom_up(self,node_list,root_node):
    
    print "placeholder"
  
  def install_backup_trees(self,failed_link,controller):
    """ Reactive Algorithm: install backup trees bottom-up
    
    Keyword Arguments:
    failed_link -- tuple (u,d) representing a link from upstream_switch_id to the downstream_swtich_id
    controller -- an fault_tolerant_controller instance
    """
    self.controller = controller
    
    # (1) T <- find the primary trees using failed_link
    affected_primary_trees = self._find_affected_trees(controller.primary_trees, failed_link)
    
    # (2) For each T: U <- the set of switches to signal
    for primary_tree in affected_primary_trees:
      
      nodes_to_signal = primary_tree.find_nodes_to_signal(failed_link)
      primary_tree.sort_nodes_bottom_up(nodes_to_signal)
      
    
    # (2a) for u \in U determine the flow entry rule
    
    # (3) Signal the switches 

  def _find_affected_trees(self,primary_trees,failed_link):
    """ Find and return a list of trees using the failed link 
    
    Keyword Arguments:
    primary_trees -- list of PrimaryTree
    failed_link -- tuple (upstream_switch_id,downstream_switch_id)
    
    """
    
    affected_primary_trees = []
    for primary_tree in primary_trees:
      for link in primary_tree.edges:
        if link == failed_link:
          affected_primary_trees.append(primary_tree)
          
    return affected_primary_trees

    
 
          