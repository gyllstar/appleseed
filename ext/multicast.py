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
from types import NoneType
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

#measure_pnts_file_str="measure-h9s6-2d-2p.csv"
measure_pnts_file_str ="measure-h4s8-1d-1p.csv"
#measure_pnts_file_str="measure-h3s4-3d-1p.csv"
#measure_pnts_file_str="measure-h3s4-2d-1p.csv"
#measure_pnts_file_str="measure-h3s4-1p.csv"
#measure_pnts_file_str="measure-h3s3-2p.csv"
#measure_pnts_file_str="measure-h3s3-1p.csv"
#measure_pnts_file_str="measure-h3s3-2d-1p.csv"
#measure_pnts_file_str="measure-h3s2-2p.csv"
#measure_pnts_file_str="measure-h3s2-1p.csv"

mtree_file_str="mtree-h4s8-1t.csv"
#mtree_file_str="mtree-h3s4-1t.csv"
#mtree_file_str="mtree-h9s6-2t.csv"
#################### End of Hard-coded IP addresses and config files ####################


depracted_installed_mtrees=[] #list of multicast addresses with an mtree already installed

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
    elif mcast_addr == mcast_ip_addr2:
      if num_switches == 6 and len(end_hosts) == 6:
        edges = [(4,10),(10,14),(10,15),(14,5),(14,6),(15,7),(15,8),(15,9)]
      else:
        msg = "should be 6 switches in topology when using the hard-coded multicast address %s" %(mcast_ip_addr2)
        log.error(msg)
        raise appleseed.AppleseedError(msg)
    data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
    tree = PrimaryTree(**data)
    
    controller.primary_trees.append(tree)


def install_all_trees(controller):
  """  (1) Compute and install the primary trees. 
       (2) Triggers a pcount session after a 5 second delay (using a timer)
       (3) Precompute backup trees
  
   """
  
  generate_multicast_groups(controller)
  
  compute_primary_trees(controller)
  
  for tree in controller.primary_trees:
    tree.install()
    u_switch_id, d_switch_ids = pcount.get_tree_measure_points(tree.root_ip_address,tree.mcast_address,controller)
    core.callDelayed(pcount.PCOUNT_CALL_FREQUENCY,pcount.start_pcount_thread,u_switch_id, d_switch_ids,tree.root_ip_address,tree.mcast_address,controller)
    
  msg = " ================= Primary Trees Installed ================="
  log.info(msg)
  print "\t\t %s" %(msg)
  
  compute_backup_trees(controller)
    

def compute_backup_trees(controller):
  """ Short-term: hard-coded backup tree + assume only one primary tree"""
  num_switches = len(core.openflow_discovery._dps)
  primary_tree = controller.primary_trees[0]
  end_hosts = controller.mcast_groups[primary_tree.mcast_address]   # this is the root and all terminal nodes
  backup_tree_edges = []
  backup_edge = ()

  if primary_tree.mcast_address == mcast_ip_addr1 and num_switches == 8 and len(end_hosts) == 4: #H4S8
    backup_tree_edges = [(1,5),(5,11),(11,7),(11,12),(12,10),(12,9),(7,2),(9,3),(10,4)]
    backup_edge = (5,6)
  
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
    
    neighbors = self.find_downstream_neighbors(node_id)
    
    host_to_port_map= {}
    dst_addresses = []
    for host in neighbors:
      ip_addr = self.find_ip_address(host)
      dst_addresses.append(ip_addr)
      outport = self.adjacency[(node_id,host)]
      
      if isinstance(outport, NoneType):
        msg = ("Tree %s want to add install flow for link (%s,%s) which does is not the adjacency list.  It likely that the (%s,%s) was not\n" 
          "discovered during intialization or the the tree computation algorithm added a non-existent link." %(self,node_id,host,node_id,host))
        log.error("%s. Exiting Program." %(msg))
        raise appleseed.AppleseedError(msg)  
      
      host_to_port_map[ip_addr] = outport
      
    # create and install a flow entry
    print "called install_rewrite_dst_mcast_flow(s%s,root=%s,host_prt_map=%s,mcast_addr=%s,dst_addr=%s) " %(node_id, self.root_ip_address, host_to_port_map, self.mcast_address, dst_addresses)
    install_rewrite_dst_mcast_flow(node_id, self.root_ip_address, host_to_port_map, self.mcast_address, dst_addresses, self.controller)
    
  def determine_flow_priority(self,node_id):
    """ Determine the priority of other entries corresponding to this flow  and set the priority to be 1 greater than the existing max priority"""
    highest_priority = -1
    for flow_entry in self.controller.flowTables[node_id]:
      if flow_entry.match.nw_src == self.root_ip_address and flow_entry.match.nw_dst == self.mcast_address:
        if flow_entry.priority > highest_priority:
          highest_priority = flow_entry.priority
#        for flow_action in flow_entry.actions:
#          if flow_action.type == of.OFPAT_SET_VLAN_VID and flow_action.vlan_vid == vlan_id:
#            return flow_entry.match,flow_entry.priority

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
      
    print "called install_basic_mcast_flow(s%s,root=%s,outport=%s,mcast_addr=%s,priority=%s)" %(node_id,self.root_ip_address,outports,self.mcast_address,priority)
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
        if level == leaf_level:
          self.install_leaf_flow(id)
        else:
          self.install_nonleaf_flow(id)
    
  def __str__(self):
    
    return "%s-->%s" %(self.mcast_address,self.edges)
  
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
    """ Proactive Algorithm. Preinstall flow entries.  Signal all nodes in 'self.nodes_to_signal' except the most upstream node"""
    msg = "Preinstall backup trees is not yet implemented at BackupTree.preinstall().  Exciting program"
    log.error(msg)
    raise applseed.AppleseedError(msg)
  
  def reactive_install(self):
    """ Reactive Algorithm.  Signal switches bottom up to activate backup tree."""
    for node_id in self.nodes_to_signal:
      if self.is_leaf_node(node_id):
        self.install_leaf_flow(node_id)
      else:
        is_most_upstream = (node_id == self.nodes_to_signal[-1])
        self.install_nonleaf_flow(node_id,is_most_upstream)
        
  def activate(self):
    """ Currently just does a reactive install 
    
    TODO: For Proactive, signal the most upstream node
    """
    print "made it to BackupTree.activate()!!!!"
    if self.controller.backup_tree_mode == Backup_Mode.REACTIVE:
      self.reactive_install()
    elif self.controller.backup_tree_mode == Backup_Mode.PROACIVE:
      msg = "No yet implemented signalling the most upstream node to activate teh backup tree for the Proactive backup tree scenario. Exciting program"
      log.error(msg)
      raise applseed.AppleseedError(msg)
    
  def is_leaf_node(self,node_id):
    """ Return True if the node_id is a leaf node.  We consider a leaf node one directly connected with a end-host. """
    neighbors = self.find_downstream_neighbors(node_id)
    
    for id in neighbors:
      if self.find_ip_address(id) in self.terminal_ip_addresses:
        return True
    return False
    
  def __str__(self):
    unique_edges =  [link for link in self.edges if link not in self.primary_tree.edges]
    return "(%s,%s)--> unique-edges: %s" %(self.mcast_address,self.backup_edge,unique_edges)
  
  def __repr__(self):
    return self.__str__()

          