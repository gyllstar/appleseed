# @author: dpg/gyllstar/Dan Gyllstrom


""" Tests the Merger algorithm.

To run this test run "pox.py --no-cli multicast_test"

"""


import appleseed,multicast
from multicast import BackupTree
from multicast import TagType
from pox.lib.addresses import IPAddr,EthAddr
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.core import core
from types import NoneType
from compiler.ast import nodes
log = core.getLogger("multicast")
import os

def setup():
  
  multicast.nodes.clear()
  multicast.edges.clear()
  global garbage_collection_total
  garbage_collection_total = 0


def get_num_type_matches(node_id,type):
  
  node = multicast.nodes[node_id]
  actual_value = 0
  for flow_entry in node.flow_entries:
    match = flow_entry.match_tag
    if match.type == type:
      actual_value += 1
  
  return actual_value

def get_num_type_backup_matches(node_id,type,backup_edge):
  
  node = multicast.nodes[node_id]
  actual_value = 0
  
  if not node.backup_flow_entries.has_key(backup_edge):
    return actual_value
  for flow_entry in node.backup_flow_entries[backup_edge]:
    match = flow_entry.match_tag
    if match.type == type:
      actual_value += 1
  
  return actual_value


def get_num_type_backup_actions(node_id,type,backup_edge):
  
  node = multicast.nodes[node_id]
  actual_value = 0
  if not node.backup_flow_entries.has_key(backup_edge):
    return actual_value
  for flow_entry in node.backup_flow_entries[backup_edge]:
    for action in flow_entry.outport_tags.values():
      if action.type == type:
        actual_value += 1
  
  return actual_value

def get_num_placeholder_flows(node_id,backup_edge):
  
  node = multicast.nodes[node_id]
  actual_value = 0
  if not node.backup_flow_entries.has_key(backup_edge):
    return actual_value
  for flow_entry in node.backup_flow_entries[backup_edge]:
    if flow_entry.is_placeholder:
      actual_value += 1
  
  return actual_value

def get_num_type_actions(node_id,type):
  
  node = multicast.nodes[node_id]
  actual_value = 0
  for flow_entry in node.flow_entries:
    for action in flow_entry.outport_tags.values():
      if action.type == type:
        actual_value += 1
  
  return actual_value

def get_tag_type_str(type):
  # GROUP_REUSE=0,GROUP=1,SINGLE=2,SINGLE_REUSE=3,MCAST_DST_ADDR=4,HOST_DST_ADDR=5) 
  if type == 0:
    return "GROUP_REUSE"
  if type == 1:
    return "GROUP"
  if type == 2:
    return "SINGLE"
  if type == 3:
    return "SINGLE_REUSE"
  if type == 4:
    return "MCAST_DST_ADDR"
  if type == 5:
    return "HOST_DST_ADDR"
  
  return "error in merger_test.get_tag_type_str() function"

def check_correct_flow_matches(expected_matches,test_name):
  
  for node_id in expected_matches.keys():
    for tuple in expected_matches[node_id]:
      type = tuple[0]
      expected_value = tuple[1]
      actual_value = get_num_type_matches(node_id,type)
      #print "MMMMMM RESULT ===== %s s%s should have %s match tags of type=%s, and has %s. "  %(test_name,node_id,expected_value,get_tag_type_str(type),actual_value)
      if expected_value != actual_value:
        tag_type_str = get_tag_type_str(type)
        msg = "\n [TEST-ERROR] %s s%s should have %s match tags of type=%s, but has %s.  Exiting test. "  %(test_name,node_id,expected_value,tag_type_str,actual_value)
        print msg
        os._exit(0)

def check_correct_backup_flow_matches(expected_matches,backup_edge,test_name):
  
  for node_id in expected_matches.keys():
    for tuple in expected_matches[node_id]:
      type = tuple[0]
      expected_value = tuple[1]
      actual_value = get_num_type_backup_matches(node_id,type,backup_edge)
      if expected_value != actual_value:
        tag_type_str = get_tag_type_str(type)
        msg = "\n [TEST-ERROR] %s, Backup trees for l=%s: s%s should have %s match backup tags of type=%s, but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,tag_type_str,actual_value)
        print msg
        os._exit(0) 
  
def check_correct_backup_flow_actions(expected_actions,backup_edge,test_name):
  
  for node_id in expected_actions.keys():
    for tuple in expected_actions[node_id]:
      type = tuple[0]
      expected_value = tuple[1]
      actual_value = get_num_type_backup_actions(node_id,type,backup_edge)
      if expected_value != actual_value:
        tag_type_str = get_tag_type_str(type)
        msg = "\n [TEST-ERROR] %s, Backup trees for l=%s: s%s should have %s action tags of type=%s, but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,tag_type_str,actual_value)
        print msg   
        os._exit(0)   
  
def check_correct_num_placeholder_backup_flows(expected_placeholders,backup_edge,test_name):
  
  for node_id in expected_placeholders.keys():
    expected_value = expected_placeholders[node_id]
    actual_value = get_num_placeholder_flows(node_id,backup_edge)
    if expected_value != actual_value:
      msg = "\n [TEST-ERROR]  %s, Backup trees for l=%s: s%s should have %s placeholder flows but has %s placeholder flows.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
      print msg   
      os._exit(0) 
 
def check_correct_reactive_ofp_flows(expected_reactive_ofp_flows, backup_edge, test_name):
   for node_id in expected_reactive_ofp_flows.keys():
    expected_value = expected_reactive_ofp_flows[node_id]
    node = multicast.nodes[node_id]
    actual_value = -1
    if node.precomputed_backup_ofp_rules.has_key(backup_edge):
      actual_value = len(node.precomputed_backup_ofp_rules[backup_edge])
    else:
      actual_value = 0
    if expected_value != actual_value:
      msg = "\n [TEST-ERROR]  %s, Reactive Mode, Merger Optimization, Backup trees for l=%s: s%s should have %s precomputed ofp flows rules but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
      print msg   
      os._exit(0) 
 
def check_correct_proactive_ofp_flows(expected_proactive_preinstall_ofp_flows, expected_proactive_activate_ofp_flows, backup_edge, test_name):
  
  for node_id in expected_proactive_preinstall_ofp_flows.keys():
    expected_value = expected_proactive_preinstall_ofp_flows[node_id]
    node = multicast.nodes[node_id]
    actual_value = -1
    if node.preinstalled_backup_ofp_rules.has_key(backup_edge):
      actual_value = len(node.preinstalled_backup_ofp_rules[backup_edge])
    else:
      actual_value = 0
    #msg = "\n PREINTALLED RESULT %s, Backup trees for l=%s: s%s should have %s preinstalled ofp flows rules but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
    #print msg   
    if expected_value != actual_value:
      msg = "\n [TEST-ERROR]  %s, Proactive Mode, Merger Optimization, Backup trees for l=%s: s%s should have %s preinstalled ofp flows rules but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
      print msg   
      os._exit(0) 

  for node_id in expected_proactive_activate_ofp_flows.keys():
    expected_value = expected_proactive_activate_ofp_flows[node_id]
    node = multicast.nodes[node_id]
    if node.cached_write_bid_ofp_rules.has_key(backup_edge):
      actual_value = len(node.cached_write_bid_ofp_rules[backup_edge])
    else:
      actual_value = 0
    #actual_value = len(node.cached_write_bid_ofp_rules[backup_edge])
    #msg = "\n ACTIVATE RESULT  %s, Backup trees for l=%s: s%s should have %s cached activation ofp flows rules but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
    #print msg   
    if expected_value != actual_value:
      msg = "\n [TEST-ERROR]  %s, Proactive Mode, Merger Optimization, Backup trees for l=%s: s%s should have %s cached activation ofp flows rules but has %s.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
      print msg   
      os._exit(0) 
       
def check_correct_flow_actions(expected_actions,test_name):
  
  for node_id in expected_actions.keys():
    for tuple in expected_actions[node_id]:
      type = tuple[0]
      expected_value = tuple[1]
      actual_value = get_num_type_actions(node_id,type)
      #print "AAAAAAA RESULT ===== %s s%s should have %s action tags of type=%s, and has %s. "  %(test_name,node_id,expected_value,get_tag_type_str(type),actual_value)
      if expected_value != actual_value:
        tag_type_str = get_tag_type_str(type)
        msg = "\n [TEST-ERROR] %s s%s should have %s action tags of type=%s, but has %s.  Exiting test. "  %(test_name,node_id,expected_value,tag_type_str,actual_value)
        print msg
        os._exit(0)

        
def check_correct_num_flows(expected_num_flows,test_name):
  
  for node_id in expected_num_flows.keys():
    expected_value = expected_num_flows[node_id]
    node = multicast.nodes[node_id]
    actual_value = len(node.flow_entries)
    
    if expected_value != actual_value:
      msg = "\n [TEST-ERROR] %s s%s should have %s flows but has %s flows.  Exiting test. "  %(test_name,node_id,expected_value,actual_value)
      print msg
      os._exit(0)
      
def check_correct_num_backup_flows(expected_num_flows,backup_edge,test_name):
  
  for node_id in expected_num_flows.keys():
    expected_value = expected_num_flows[node_id]
    node = multicast.nodes[node_id]
    actual_value = 0
    if node.backup_flow_entries.has_key(backup_edge):
      actual_value = len(node.backup_flow_entries[backup_edge])
    
    if expected_value != actual_value:
      msg = "\n [TEST-ERROR] %s, Backup trees for l=%s: s%s should have %s backup flows but has %s flows.  Exiting test. "  %(test_name,backup_edge,node_id,expected_value,actual_value)
      print msg
      os._exit(0)      

def check_garbage_nodes_correct(primary_tree_id,actual_garbage_nodes,expected_garbage_nodes,test_name):
  
  if actual_garbage_nodes != expected_garbage_nodes:
    msg = "\n [TEST-ERROR] %s, Primary Tree T%s should have garbage collection nodes = %s but has garbage nodes = %s. Exiting. "  %(test_name,primary_tree_id, expected_garbage_nodes,actual_garbage_nodes)
    print msg
    os._exit(0)      


def check_diverge_nodes(expected_diverge_nodes,actual_diverge_nodes,backup_edge,tree_id,test_name):
  
  if expected_diverge_nodes != actual_diverge_nodes:
    msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, should have diverge nodes = %s but has diverge nodes = %s. Exiting. "  %(test_name,tree_id,backup_edge,expected_diverge_nodes,actual_diverge_nodes)
    print msg
    os._exit(0)   
    
def check_num_garbage_flows_correct(expected_num_garbage_flows,test_name):
  if multicast.garbage_collection_total != expected_num_garbage_flows:
    msg = "\n [TEST-ERROR] %s, Should have %s garbage collection flows but has %s. Exiting. "  %(test_name,expected_num_garbage_flows,multicast.garbage_collection_total)
    print msg
    os._exit(0)   
  
  
def check_merge_reactive_activate_msgs(test_name,backup_tree):
  """ Should have no match tags or write tag actions to do with Bid"""
  level_one_nodes = backup_tree.compute_node_levels()[1]
  for activate_node_id in level_one_nodes:
    # (1) check the FlowEntry in 'backup_treeid_rule_map' and 'backup_flow_entries'
    backup_edge = backup_tree.backup_edge
    activate_node = multicast.nodes[activate_node_id]
    backup_flow_entry = activate_node.backup_treeid_rule_map[backup_edge][backup_tree.id]
    
    if backup_flow_entry.write_bid_flow == True:
      msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, should have NOT cached a Merger Flow Entry to write bid=%s at s%s in the field 'backup_treeid_rule_map' because this is REACTIVE mode. Exiting. "  %(test_name,backup_tree.id,backup_edge,backup_tree.bid,activate_node_id)
      print msg
      os._exit(0)
      
    num_matching_flow_entry_found = 0
    for flow_entry in activate_node.backup_flow_entries[backup_edge]:
      if backup_flow_entry.match_tag == flow_entry.match_tag:
        if flow_entry.write_bid_flow:
          msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, should have NOT cached a Merger Flow Entry that writes bid=%s at s%s in the field 'backup_flow_entries'. Exiting. "  %(test_name,backup_tree.id,backup_edge,backup_tree.bid,activate_node_id)
          print msg
          os._exit(0)
  
def check_merge_proactive_activate_msgs(test_name,backup_tree):
  
  level_one_nodes = backup_tree.compute_node_levels()[1]
  for activate_node_id in level_one_nodes:
    # (1) check the FlowEntry in 'backup_treeid_rule_map' and 'backup_flow_entries'
    backup_edge = backup_tree.backup_edge
    activate_node = multicast.nodes[activate_node_id]
    backup_flow_entry = activate_node.backup_treeid_rule_map[backup_edge][backup_tree.id]
    
    if backup_flow_entry.write_bid_flow == False:
      msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, should have cached a Merger Flow Entry to write bid=%s at s%s in the field 'backup_treeid_rule_map'. Exiting. "  %(test_name,backup_tree.id,backup_edge,backup_tree.bid,activate_node_id)
      print msg
      os._exit(0)
      
    num_matching_flow_entry_found = 0
    for flow_entry in activate_node.backup_flow_entries[backup_edge]:
      if backup_flow_entry.match_tag == flow_entry.match_tag:
        if flow_entry.write_bid_flow:
          num_matching_flow_entry_found+=1
        else:
          msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, has cached a Merger Flow Entry that does not write bid=%s at s%s in the field 'backup_flow_entries'. Exiting. "  %(test_name,backup_tree.id,backup_edge,backup_tree.bid,activate_node_id)
          print msg
          os._exit(0)
    
    #print "NUM MATCH FLOW ENTRY at s%s = %s" %(activate_node_id,num_matching_flow_entry_found)
    
    if num_matching_flow_entry_found == 0:
      msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, should have cached a Merger Flow Entry to write bid=%s at s%s in the field 'backup_flow_entries'. Exiting. "  %(test_name,backup_tree.id,backup_edge,backup_tree.bid,activate_node_id)
      print msg
      os._exit(0)
    elif num_matching_flow_entry_found > 1:
      msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, has cached %s Merger Flow Entry that write bid=%s at s%s in the field 'backup_flow_entries'. Should only be 1 such Flow Entry. Exiting. "  %(test_name,backup_tree.id,backup_edge,num_matching_flow_entry_found,backup_tree.bid,activate_node_id)
      print msg
      os._exit(0)     
    
  
def print_successful_test_results(baseline_test_names,merger_test_names):
  
  print "\n\n************************************************** THESE TESTS ALL COMPLETED CORRECTLY **************************************************************" 
  cnt = 0
  print "**** BASELINE TESTS \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ****"
  for test_name in baseline_test_names:
    cnt+=1
    print "**** \t\t (%s)  %s  \t\t\t\t\t\t\t\t\t\t\t ****" %(cnt,test_name)
  cnt = 0
  print "**** MERGER TESTS \t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ****"
  for test_name in merger_test_names:
    cnt+=1
    print "**** \t\t (%s)  %s  \t\t\t\t\t\t\t\t\t\t\t\t ****" %(cnt,test_name)
  print "*****************************************************************************************************************************************************"
  

def test_steiner_arboresence():
  """ NICK: here the starter code for your multicast test. """
  print "**** RUNNING test_steiner_arboresence() ****"
  setup()
  
  
  # NICK: this is the adjacency matrix, where each entry is of the form: "(u,d): p" where u is the upstream node, d is the downstream node, and p is the port from u to d
  #       replace with your adjacency matrix. the port numbers don't matter much for your testing purposes, but ideally should be unique at each node for each of its outgoing links
  adjacency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, 
                     (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 
                     3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  
  # NICK: you will probably either (1) have to create your own "mtree" and "measure_pnts_file" or 
  #                                (2) remove the call to read this files in the constructor of appleseed.fault_tolerant_controller 
  #      either way you need some way to indicate what the root and terminals are for your multicast group
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.BASELINE
  controller.adjacency = adjacency
  
  # NICK: replace this with the switch ids
  list_of_switches = [7,8,9,10,11,12,13,14,15]
  core.openflow_discovery._dps = list_of_switches
  multicast.compute_primary_trees(controller)
  
  #NICK: this dictionary specifies the expected results.  Each entry "a:b" is switch 'a' should have 'b' flow entries for primary trees.  To determine the correct number of flow
  #      entries for your example, you need to look at each switch, a, and determine in how many multicast trees is 'a' used?  One flow entry is created for each such multicast tree.  
  #      For example, if switch 7 is used in 3 multicast trees, the dictionary should have the value 7:3
  expected_num_flows = {7:3,8:2,9:2,10:1,11:1,12:3,13:1,14:1,15:2,16:0,17:1}
  
  test_name = "test_steiner_arboresence()"
  check_correct_num_flows(expected_num_flows, test_name)


  # NICK: let me know when you are ready to test backup trees and I can add the boierplate test code for you.
  

def test_reactive_backups_h6s9():
  print "**** RUNNING MERGER_TEST.test_reactive_backups_h6s9() ****"
  setup()
  h6s9_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.backup_tree_mode = multicast.BackupMode.REACTIVE
  controller.adjacency = h6s9_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15]
  multicast.compute_primary_trees(controller)
  multicast.create_install_merged_primary_tree_flows(controller)
  
    # GROUP_REUSE=0,GROUP=1,SINGLE=2,SINGLE_REUSE=3,MCAST_DST_ADDR=4,HOST_DST_ADDR=5) 
  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  test_name = "test_reactive_backups_h6s9()"
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],    
                    }
  check_correct_flow_actions(expected_actions, test_name)
  
  multicast.compute_backup_trees(controller)
  
  
  set_values = [7,8,10]
  expected_garbage_nodes = {1:set(set_values), 5:set(set_values)}
  backup_edges = set()
  for ptree in controller.primary_trees:
    for btree in ptree.backup_trees.values():
      edge = btree.backup_edge
      backup_edges.add(edge)
      garbage_nodes = ptree.find_garbage_collect_nodes(edge,btree)
      check_garbage_nodes_correct(ptree.id,garbage_nodes,expected_garbage_nodes[ptree.id],test_name)
      check_merge_reactive_activate_msgs(test_name, btree)
      
  failed_link = (7,8)
  affected_trees = multicast.find_affected_primary_trees(controller.primary_trees,failed_link)
  multicast.garbage_collect_merger_rules(failed_link,affected_trees)
  expected_num_garbage_flows = 3
  check_num_garbage_flows_correct(expected_num_garbage_flows,test_name)
  
  # includes placeholders
  expected_num_backup_flows = {7:2,8:0,9:1,10:0,11:1,12:2,13:1,14:1,15:0}
  expected_backup_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      14:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  
  
  expected_backup_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)],
                    13:[(TagType.GROUP_REUSE,1),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],    
                    }
  expected_placeholder_backup_flows = {7:0,8:0,9:1,10:0,11:1,12:2,13:0,14:0,15:0}    

  for backup_edge in backup_edges:
    check_correct_num_backup_flows(expected_num_backup_flows, backup_edge, test_name)
    check_correct_backup_flow_matches(expected_backup_matches, backup_edge, test_name)
    check_correct_backup_flow_actions(expected_backup_actions, backup_edge, test_name)
    check_correct_num_placeholder_backup_flows(expected_placeholder_backup_flows, backup_edge, test_name)
    controller.activate_backup_trees(backup_edge)
    expected_reactive_ofp_flows = {7:2,13:1,14:1,8:0,9:0,10:0,11:0,12:0,15:0}
    check_correct_reactive_ofp_flows(expected_reactive_ofp_flows, backup_edge, test_name)
  
  #print "OS EXIT AT test_reactive_backups_h6s9() "
  #os._exit(0)

def test_backups_h6s9():
  print "**** RUNNING MERGER_TEST.test_backups_h6s9() ****"
  setup()
  h6s9_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.backup_tree_mode = multicast.BackupMode.PROACTIVE
  controller.adjacency = h6s9_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15]
  multicast.compute_primary_trees(controller)
  multicast.create_install_merged_primary_tree_flows(controller)
  
    # GROUP_REUSE=0,GROUP=1,SINGLE=2,SINGLE_REUSE=3,MCAST_DST_ADDR=4,HOST_DST_ADDR=5) 
  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  test_name = "test_backups_h6s9()"
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],    
                    }
  check_correct_flow_actions(expected_actions, test_name)
  
  multicast.compute_backup_trees(controller)
  
  
  set_values = [7,8,10]
  expected_garbage_nodes = {1:set(set_values), 5:set(set_values)}
  backup_edges = set()
  for ptree in controller.primary_trees:
    for btree in ptree.backup_trees.values():
      edge = btree.backup_edge
      backup_edges.add(edge)
      garbage_nodes = ptree.find_garbage_collect_nodes(edge,btree)
      check_garbage_nodes_correct(ptree.id,garbage_nodes,expected_garbage_nodes[ptree.id],test_name)
      check_merge_proactive_activate_msgs(test_name, btree)
      
  failed_link = (7,8)
  affected_trees = multicast.find_affected_primary_trees(controller.primary_trees,failed_link)
  multicast.garbage_collect_merger_rules(failed_link,affected_trees)
  expected_num_garbage_flows = 3
  check_num_garbage_flows_correct(expected_num_garbage_flows,test_name)
  
  # includes placeholders
  expected_num_backup_flows = {7:2,8:0,9:1,10:0,11:1,12:2,13:1,14:1,15:0}
  expected_backup_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      14:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  
  
  expected_backup_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)],
                    13:[(TagType.GROUP_REUSE,1),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],    
                    }
  expected_placeholder_backup_flows = {7:0,8:0,9:1,10:0,11:1,12:2,13:0,14:0,15:0}    
  expected_proactive_preinstall_ofp_flows = {13:1,14:1,7:0,8:0,9:0,10:0,11:0,12:0,15:0}
  expected_proactive_activate_ofp_flows = {7:2,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0}
  
  for backup_edge in backup_edges:
    check_correct_num_backup_flows(expected_num_backup_flows, backup_edge, test_name)
    check_correct_backup_flow_matches(expected_backup_matches, backup_edge, test_name)
    check_correct_backup_flow_actions(expected_backup_actions, backup_edge, test_name)
    check_correct_num_placeholder_backup_flows(expected_placeholder_backup_flows, backup_edge, test_name)
    controller.activate_backup_trees(backup_edge)
    check_correct_proactive_ofp_flows(expected_proactive_preinstall_ofp_flows, expected_proactive_activate_ofp_flows, backup_edge, test_name)
  
#  print "OS EXIT AT test_backups_h6s9() "
#  os._exit(0)
  
def test_merger_treeid_h6s12():
  print "**** RUNNING BASELINE_TEST.test_merger_treeid_h6s12() ****"
  setup()
  h6s12_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 16): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3,(18,13):5,(13, 18): 1, (13,8): 4, 
                      (12, 10): 2, (17,12):1, (17,15):2, (17,14):3, (12, 17): 1, (7, 1): 1, (7, 5): 2, (8, 18): 1, (12, 15): 3, (9, 2): 3, (7, 18): 3, (11, 3): 3, (14, 17): 2, 
                      (15, 6): 2, (12, 4): 4, (13, 16): 2, (18,7):2, (18,8):1,(16,11):1, (16,13):2}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.backup_tree_mode = multicast.BackupMode.PROACTIVE
  controller.adjacency = h6s12_adjancency
  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16,17,18]
  
  #multicast.compute_primary_trees(controller)
  
  edges1 = [(1,7),(7,18),(18,13),(13,16),(13,14),(14,17),(16,11),(11,3),(17,15),(17,12),(12,4),(15,6)]
  mcast_addr1 = IPAddr("10.10.10.10")
  root1 = IPAddr("10.0.0.1")
  terminal_hosts1 = [IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges1, "mcast_address":mcast_addr1, "root":root1, "terminals":terminal_hosts1, "adjacency":controller.adjacency, "controller":controller}
  tree1 = multicast.PrimaryTree(**data)
  controller.primary_trees.append(tree1)  
 
  edges5 =[(5,7),(7,18),(18,13),(18,8),(8,9),(9,2),(13,16),(13,14),(14,17),(16,11),(11,3),(17,15),(17,12),(12,4),(15,6)]
  mcast_addr5 = IPAddr("10.11.11.11")
  root5 = IPAddr("10.0.0.5")
  terminal_hosts5 = [IPAddr("10.0.0.2"),IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges5, "mcast_address":mcast_addr5, "root":root5, "terminals":terminal_hosts5, "adjacency":controller.adjacency, "controller":controller}
  tree5 = multicast.PrimaryTree(**data) 
  controller.primary_trees.append(tree5)  
  
  
 # controller.mcast_groups[mcast_addr5] = [root5]+terminal_hosts5
  
  #multicast.compute_primary_trees(controller)
  
  
  expected_num_flows = {7:3,8:2,9:2,10:1,11:1,12:3,13:1,14:1,15:2,16:0,17:1}
  
  test_name = "test_merger_treeid_h6s12()"
  #check_correct_num_flows(expected_num_flows, test_name)
  
  backup_tree_edges5 = [(5,7),(7,18),(18,13),(13,8),(8,9),(9,2),(13,16),(13,14),(14,17),(16,11),(11,3),(17,15),(17,12),(12,4),(15,6)]
  backup_edge = (18,8)
  
  data = {"edges":backup_tree_edges5, "mcast_address":tree5.mcast_address, "root":tree5.root_ip_address, "terminals":tree5.terminal_ip_addresses, 
            "adjacency":controller.adjacency, "controller":controller,"primary_tree":tree5,"backup_edge":backup_edge}
  backup_tree = BackupTree(**data)
  tree5.backup_trees[backup_edge] = backup_tree
  
  #multicast.compute_backup_trees(controller)
  
  expected_diverge_nodes = set()
  expected_diverge_nodes.add(18)
  expected_diverge_nodes.add(13)
  expected_diverge_nodes.add(7)
  check_diverge_nodes(expected_diverge_nodes,backup_tree.diverge_nodes,backup_edge,tree5.id,test_name)
  
  multicast.create_install_merged_primary_tree_flows(controller)
  multicast.compute_backup_trees(controller)
  
  check_merge_proactive_activate_msgs(test_name, backup_tree)
  
  controller.activate_backup_trees(backup_edge)
  expected_proactive_preinstall_ofp_flows = {13:1,18:1}
  expected_proactive_activate_ofp_flows = {7:1}
  check_correct_proactive_ofp_flows(expected_proactive_preinstall_ofp_flows, expected_proactive_activate_ofp_flows, backup_edge, test_name)
  
        
  #os._exit(0)  
  
def test_baseline_treeid_h6s12():
  print "**** RUNNING BASELINE_TEST.test_baseline_treeid_h6s12() ****"
  setup()
  h6s12_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 16): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3,(18,13):5,(13, 18): 1, (13,8): 4, 
                      (12, 10): 2, (17,12):1, (17,15):2, (17,14):3, (12, 17): 1, (7, 1): 1, (7, 5): 2, (8, 18): 1, (12, 15): 3, (9, 2): 3, (7, 18): 3, (11, 3): 3, (14, 17): 2, 
                      (15, 6): 2, (12, 4): 4, (13, 16): 2, (18,7):2, (18,8):1,(16,11):1, (16,13):2}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.BASELINE
  controller.backup_tree_mode = multicast.BackupMode.PROACTIVE
  controller.adjacency = h6s12_adjancency
  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16,17,18]
  
  #multicast.compute_primary_trees(controller)
  
  edges1 = [(1,7),(7,18),(18,13),(13,16),(13,14),(14,17),(16,11),(11,3),(17,15),(17,12),(12,4),(15,6)]
  mcast_addr1 = IPAddr("10.10.10.10")
  root1 = IPAddr("10.0.0.1")
  terminal_hosts1 = [IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges1, "mcast_address":mcast_addr1, "root":root1, "terminals":terminal_hosts1, "adjacency":controller.adjacency, "controller":controller}
  tree1 = multicast.PrimaryTree(**data)
  controller.primary_trees.append(tree1)  
 
  edges5 =[(5,7),(7,18),(18,13),(18,8),(8,9),(9,2),(13,16),(13,14),(14,17),(16,11),(11,3),(17,15),(17,12),(12,4),(15,6)]
  mcast_addr5 = IPAddr("10.11.11.11")
  root5 = IPAddr("10.0.0.5")
  terminal_hosts5 = [IPAddr("10.0.0.2"),IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges5, "mcast_address":mcast_addr5, "root":root5, "terminals":terminal_hosts5, "adjacency":controller.adjacency, "controller":controller}
  tree5 = multicast.PrimaryTree(**data) 
  controller.primary_trees.append(tree5)  
  
  
 # controller.mcast_groups[mcast_addr5] = [root5]+terminal_hosts5
  
  #multicast.compute_primary_trees(controller)
  expected_num_flows = {7:3,8:2,9:2,10:1,11:1,12:3,13:1,14:1,15:2,16:0,17:1}
  
  test_name = "test_baseline_treeid_h6s12()"
  #check_correct_num_flows(expected_num_flows, test_name)
  
  backup_tree_edges5 = [(5,7),(7,18),(18,13),(13,8),(8,9),(9,2),(13,16),(13,14),(14,17),(16,11),(11,3),(17,15),(17,12),(12,4),(15,6)]
  backup_edge = (18,8)
  
  data = {"edges":backup_tree_edges5, "mcast_address":tree5.mcast_address, "root":tree5.root_ip_address, "terminals":tree5.terminal_ip_addresses, 
            "adjacency":controller.adjacency, "controller":controller,"primary_tree":tree5,"backup_edge":backup_edge}
  backup_tree = BackupTree(**data)
  tree5.backup_trees[backup_edge] = backup_tree

  #multicast.compute_backup_trees(controller)
  
  expected_diverge_nodes = set()
  expected_diverge_nodes.add(18)
  expected_diverge_nodes.add(13)
  check_diverge_nodes(expected_diverge_nodes,backup_tree.diverge_nodes,backup_edge,tree5.id,test_name)
  
  backup_tree.preinstall_baseline_backups()
  #backup_tree.cache_activate_rule(7)
  
  for activate_node in backup_tree.proactive_activate_msgs.keys():
    ofp_msg = backup_tree.proactive_activate_msgs[activate_node]
    correct_bid_action_found = False
    for action in ofp_msg.actions:
      if isinstance(action,of.ofp_action_dl_addr):
        if action.dl_addr == backup_tree.bid:
       #   print action
          correct_bid_action_found = True
    
    if not correct_bid_action_found:
      msg = "\n [TEST-ERROR] %s, Backup Tree %s for l=%s, should cached an action to write bid=%s in the tp_port field but did not. Exiting. "  %(test_name,backup_tree.id,backup_edge,backup_tree.bid)
      print msg
      os._exit(0)
      
        
  
def test_backups_h6s11():
  print "**** RUNNING MERGER_TEST.test_backups_h6s11() ****"
  setup()
  h6s11_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 16): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3, (13, 7): 1, 
                      (12, 10): 2, (17,12):1, (17,15):2, (17,14):3, (12, 17): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (12, 15): 3, (9, 2): 3, (7, 13): 3, (11, 3): 3, (14, 17): 2, 
                      (15, 6): 2, (12, 4): 4, (13, 16): 2, (7, 8): 4, (16,11):1, (16,13):2}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.backup_tree_mode = multicast.BackupMode.PROACTIVE
  controller.adjacency = h6s11_adjancency
  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16,17]
  
  #multicast.compute_primary_trees(controller)
  
  edges1 = [(1,7),(7,8),(8,9),(8,10),(10,11),(10,12),(9,2),(11,3),(12,4)]
  mcast_addr1 = IPAddr("10.10.10.10")
  root1 = IPAddr("10.0.0.1")
  terminal_hosts1 = [IPAddr("10.0.0.2"),IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges1, "mcast_address":mcast_addr1, "root":root1, "terminals":terminal_hosts1, "adjacency":controller.adjacency, "controller":controller}
  tree1 = multicast.PrimaryTree(**data)
  controller.primary_trees.append(tree1)  
 
  edges5= [(5,7),(7,8),(8,9),(8,10),(10,11),(10,12),(12,15),(9,2),(11,3),(12,4),(15,6)]
  mcast_addr5 = IPAddr("10.11.11.11")
  root5 = IPAddr("10.0.0.5")
  terminal_hosts5 = [IPAddr("10.0.0.2"),IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges5, "mcast_address":mcast_addr5, "root":root5, "terminals":terminal_hosts5, "adjacency":controller.adjacency, "controller":controller}
  tree5 = multicast.PrimaryTree(**data) 
  controller.primary_trees.append(tree5)  
  
  edges = [(2,9), (9,8), (8,7), (7,13), (13,14), (14,17), (17,15), (17,12), (12,4), (15,6)]
  mcast_addr = IPAddr("10.12.12.12")
  root = IPAddr("10.0.0.2")
  terminal_hosts = [IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  #controller.mcast_groups[mcast_addr] = [root]+terminal_hosts
  data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
  tree = multicast.PrimaryTree(**data)
  
  
  
  controller.primary_trees.append(tree)  
  controller.mcast_groups[mcast_addr] = [root]+terminal_hosts
  multicast.create_install_merged_primary_tree_flows(controller)

  expected_num_flows = {7:3,8:2,9:2,10:1,11:1,12:3,13:1,14:1,15:2,16:0,17:1}
  
  test_name = "test_backups_h6s11()"
  check_correct_num_flows(expected_num_flows, test_name)

  
  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      17:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,3)],
                    13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)], 
                    16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    17:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,2),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]     
                    }
  check_correct_flow_actions(expected_actions, test_name)  
  
  
  
  backup_tree_edges1 = [(1,7),(7,13),(13,16),(13,14),(14,17),(16,11),(11,3),(17,12),(12,4)]
  backup_edge = (7,8)
  
  data = {"edges":backup_tree_edges1, "mcast_address":tree1.mcast_address, "root":tree1.root_ip_address, "terminals":tree1.terminal_ip_addresses, 
            "adjacency":controller.adjacency, "controller":controller,"primary_tree":tree1,"backup_edge":backup_edge}
  backup_tree = BackupTree(**data)
  tree1.backup_trees[backup_edge] = backup_tree
  
  backup_tree_edges5 = [(5,7),(7,13),(13,16),(13,14),(14,17),(16,11),(11,3),(17,12),(12,15),(12,4),(15,6)]
  
  data = {"edges":backup_tree_edges5, "mcast_address":tree5.mcast_address, "root":tree5.root_ip_address, "terminals":tree5.terminal_ip_addresses, 
            "adjacency":controller.adjacency, "controller":controller,"primary_tree":tree5,"backup_edge":backup_edge}
  backup_tree = BackupTree(**data)
  tree5.backup_trees[backup_edge] = backup_tree

  multicast.compute_backup_trees(controller)
  
  set_values = [7,8,10,9]
  expected_garbage_nodes = {1:set(set_values), 5:set(set_values)}
  backup_edges = set()
  for ptree in controller.primary_trees:
    for btree in ptree.backup_trees.values():
      edge = btree.backup_edge
      backup_edges.add(edge)
      garbage_nodes = ptree.find_garbage_collect_nodes(edge,btree)
      check_garbage_nodes_correct(ptree.id,garbage_nodes,expected_garbage_nodes[ptree.id],test_name)
      check_merge_proactive_activate_msgs(test_name, btree)
      
  failed_link = (7,8)
  affected_trees = multicast.find_affected_primary_trees(controller.primary_trees,failed_link)
  multicast.garbage_collect_merger_rules(failed_link,affected_trees)
  expected_num_garbage_flows = 4
  check_num_garbage_flows_correct(expected_num_garbage_flows,test_name)
  
  # includes placeholders
  expected_num_backup_flows = {7:2,8:0,9:0,10:0,11:1,12:2,13:1,14:1,15:0,16:1,17:2}
  expected_backup_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      16:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      17:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  
  
  expected_backup_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                    10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)],
                    13:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                    16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    17:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)]      
                    }
  expected_placeholder_backup_flows = {7:0,8:0,9:0,10:0,11:1,12:2,13:0,14:1,15:0,16:0,17:0}    

  for backup_edge in backup_edges:
    check_correct_num_backup_flows(expected_num_backup_flows, backup_edge, test_name)
    check_correct_backup_flow_matches(expected_backup_matches, backup_edge, test_name)
    check_correct_backup_flow_actions(expected_backup_actions, backup_edge, test_name)
    check_correct_num_placeholder_backup_flows(expected_placeholder_backup_flows, backup_edge, test_name)
  
    controller.activate_backup_trees(backup_edge)
    expected_proactive_preinstall_ofp_flows = {13:1,16:1,17:2,8:0,9:0,10:0,11:0,12:0,14:0,15:0}
    expected_proactive_activate_ofp_flows = {7:2,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0,16:0,17:0}
    check_correct_proactive_ofp_flows(expected_proactive_preinstall_ofp_flows, expected_proactive_activate_ofp_flows, backup_edge, test_name)
    #multicast.print_backup_ofp_rules(controller,backup_edge)
  
  #print "OS EXIT AT test_backups_h6s11() "
  #os._exit(0)  
  

def test_backups_h6s9_3trees():
  print "**** RUNNING MERGER_TEST.test_backups_h6s9_3trees() ****"
  setup()
  h6s9_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  #controller.backup_tree_mode = multicast.BackupMode.REACTIVE
  controller.backup_tree_mode = multicast.BackupMode.PROACTIVE
  controller.adjacency = h6s9_adjancency
  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15]
  
  multicast.compute_primary_trees(controller)

  
  edges = [(2,9), (9,8), (8,7), (7,13), (13,14), (14,12), (14,11), (11,3), (12,4), (12,15), (15,6)]
  mcast_addr = IPAddr("10.12.12.12")
  root = IPAddr("10.0.0.2")
  terminal_hosts = [IPAddr("10.0.0.3"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  #controller.mcast_groups[mcast_addr] = [root]+terminal_hosts
  data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
  tree = multicast.PrimaryTree(**data)
  controller.primary_trees.append(tree)  
  controller.mcast_groups[mcast_addr] = [root]+terminal_hosts
  multicast.create_install_merged_primary_tree_flows(controller)
  
  expected_num_flows = {7:3,8:2,9:2,10:1,11:1,12:3,13:1,14:1,15:1}
  
  test_name = "test_backups_h6s9_3trees()"
  check_correct_num_flows(expected_num_flows, test_name)

  
  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,3)],
                    13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],    
                    }
  check_correct_flow_actions(expected_actions, test_name)  

  multicast.compute_backup_trees(controller)
  
  set_values = [7,8,10]
  expected_garbage_nodes = {1:set(set_values), 5:set(set_values)}
  backup_edges = set()
  for ptree in controller.primary_trees:
    for btree in ptree.backup_trees.values():
      edge = btree.backup_edge
      backup_edges.add(edge)
      garbage_nodes = ptree.find_garbage_collect_nodes(edge,btree)
      check_garbage_nodes_correct(ptree.id,garbage_nodes,expected_garbage_nodes[ptree.id],test_name)
  
  failed_link = (7,8)
  affected_trees = multicast.find_affected_primary_trees(controller.primary_trees,failed_link)
  multicast.garbage_collect_merger_rules(failed_link,affected_trees)
  expected_num_garbage_flows = 3
  check_num_garbage_flows_correct(expected_num_garbage_flows,test_name)
  
  # includes placeholders
  expected_num_backup_flows = {7:2,8:0,9:1,10:0,11:1,12:2,13:1,14:1,15:0}
  expected_backup_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)],
                      13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]    
                      }
  
  
  
  expected_backup_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,2)],
                    13:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    14:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],    
                    }
  expected_placeholder_backup_flows = {7:0,8:0,9:1,10:0,11:1,12:2,13:0,14:1,15:0}    

  for backup_edge in backup_edges:
    check_correct_num_backup_flows(expected_num_backup_flows, backup_edge, test_name)
    check_correct_backup_flow_matches(expected_backup_matches, backup_edge, test_name)
    check_correct_backup_flow_actions(expected_backup_actions, backup_edge, test_name)
    check_correct_num_placeholder_backup_flows(expected_placeholder_backup_flows, backup_edge, test_name)
  
    controller.activate_backup_trees(backup_edge)
    
    expected_proactive_preinstall_ofp_flows = {13:1,8:0,9:0,10:0,11:0,12:0,14:0,15:0}
    expected_proactive_activate_ofp_flows = {7:2,8:0,9:0,10:0,11:0,12:0,13:0,14:0,15:0}
    check_correct_proactive_ofp_flows(expected_proactive_preinstall_ofp_flows, expected_proactive_activate_ofp_flows, backup_edge, test_name)
    #multicast.print_backup_ofp_rules(controller,backup_edge)
  
  #print "OS EXIT AT test_backups_h6s9_3trees() "
  #os._exit(0)

def test_h6s10():
  
  print "**** RUNNING MERGER_TEST.test_h6s10 ****"
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s10-3t.csv"
  multicast.measure_pnts_file_str="measure-h6s10-1d-1p.csv"

  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.adjacency = h6s10_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16]
  multicast.compute_primary_trees(controller)
  multicast.create_install_merged_primary_tree_flows(controller)
  
  
  expected_num_flows = {7:2,8:1,9:2,10:1,11:1,12:3,13:0,14:0,15:1,16:1}

  
  test_name = "test_h6s10()"
  check_correct_num_flows(expected_num_flows, test_name)
  
    # GROUP_REUSE=0,GROUP=1,SINGLE=2,SINGLE_REUSE=3,MCAST_DST_ADDR=4,HOST_DST_ADDR=5) 
  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,3),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],    
                      16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]
                      }
  
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,3)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],    
                    16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]
                    }
  check_correct_flow_actions(expected_actions, test_name)
  
def test_h6s10_4trees_order1():
  
  print "**** RUNNING MERGER_TEST.test_h6s10_4trees_order1() ****"
  
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s10-3t.csv"
  multicast.measure_pnts_file_str="measure-h6s10-1d-1p.csv"
  
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.adjacency = h6s10_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16]
  multicast.compute_primary_trees(controller)
  
  
  edges = [(3,11),(11,10),(10,8),(10,12),(8,9),(12,4),(12,15),(9,2),(15,6)]
  mcast_addr = IPAddr("10.13.13.13")
  root = IPAddr("10.0.0.3")
  terminal_hosts = [IPAddr("10.0.0.2"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
  tree = multicast.PrimaryTree(**data)
  controller.mcast_groups[mcast_addr] = [root]+terminal_hosts
  controller.primary_trees.append(tree)  
  
  multicast.create_install_merged_primary_tree_flows(controller)
  controller.mcast_groups[mcast_addr] = [root]+terminal_hosts  
  
  expected_num_flows = {7:2,8:2,9:2,10:3,11:2,12:4,13:0,14:0,15:1,16:1}
  
  test_name = "test_h6s10_4trees_order1()"
  check_correct_num_flows(expected_num_flows, test_name)
  
  #total = 17
  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,2),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],    
                      16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]
                      }
  
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,3),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,3),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,4)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],    
                    16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]
                    }
  check_correct_flow_actions(expected_actions, test_name)


def test_h6s10_4trees_order2():
  
  print "**** RUNNING MERGER_TEST.test_h6s10_4trees_order2() ****"
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s10-3t.csv"
  multicast.measure_pnts_file_str="measure-h6s10-1d-1p.csv"
  
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.MERGER
  controller.adjacency = h6s10_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16]
  multicast.compute_primary_trees(controller)
  
  edges = [(3,11),(11,10),(10,8),(10,12),(8,9),(12,4),(12,15),(9,2),(15,6)]
  mcast_addr = IPAddr("10.13.13.13")
  root = IPAddr("10.0.0.3")
  terminal_hosts = [IPAddr("10.0.0.2"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
  tree = multicast.PrimaryTree(**data)

  controller.primary_trees.append(tree)  
  multicast.create_install_merged_primary_tree_flows(controller)
  controller.mcast_groups[mcast_addr] = [root]+terminal_hosts
  expected_num_flows = {7:2,8:2,9:2,10:3,11:2,12:4,13:0,14:0,15:1,16:1}
  test_name = "test_h6s10_4trees_order2()"
  check_correct_num_flows(expected_num_flows, test_name)
  
  #total = 17

  expected_matches = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      8:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                      9:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                      10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)], 
                      11:[(TagType.GROUP_REUSE,1),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)],
                      12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,2),(TagType.MCAST_DST_ADDR,2),(TagType.HOST_DST_ADDR,0)],
                      15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],    
                      16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]
                      }
  
  check_correct_flow_matches(expected_matches, test_name)
  
  expected_actions = {7:[(TagType.GROUP_REUSE,0),(TagType.GROUP,2),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    8:[(TagType.GROUP_REUSE,2),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)],
                    9:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)], 
                    10:[(TagType.GROUP_REUSE,1),(TagType.GROUP,1),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,3),(TagType.MCAST_DST_ADDR,1),(TagType.HOST_DST_ADDR,0)], 
                    11:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,1),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],
                    12:[(TagType.GROUP_REUSE,0),(TagType.GROUP,3),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,4)],
                    15:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,0),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,1)],    
                    16:[(TagType.GROUP_REUSE,0),(TagType.GROUP,0),(TagType.SINGLE,0),(TagType.SINGLE_REUSE,1),(TagType.MCAST_DST_ADDR,0),(TagType.HOST_DST_ADDR,0)]
                    }
  check_correct_flow_actions(expected_actions, test_name)


def baseline_check_nodes_to_signal(expected_result,actual_result,tree_id,backup_edge,test_name):

  if expected_result != actual_result:
    msg = "\n [TEST-ERROR] %s, Backup tree (B%s) for l=%s: should have nodes-to-signal = %s but has nodes-to-signal = %s.  Exiting test. "  %(test_name,tree_id,backup_edge,expected_result,actual_result)
    os.exit(0)
    
def depracated_test_baseline_bottom_up_signal_simple_path():
  """ Test no longer works because need port mappings in the adjacency matrix to compute these nodes. """
  setup()
  controller = appleseed.fault_tolerant_controller()
  #controller.adjacency = h6s10_adjancency
  controller.algorithm_mode = multicast.Mode.BASELINE

  #core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16]

  # just a simple path
  primary_edges = [(1,2),(2,3),(3,4),(4,5),(5,6)]
  backup_edges = [(1,2),(2,7),(7,8),(8,5),(5,6)]

  
  root = IPAddr("10.0.0.1")
  terminals = [IPAddr("10.0.0.6")]
  data = {"edges":primary_edges,"mcast_address":IPAddr("10.0.0.6"),"root":root,"terminals":terminals,"adjacency":None,"controller":controller}   
  primary = multicast.PrimaryTree(**data)
  
  
  print "before backup"
  data = {"primary_tree":primary,"edges":backup_edges,"backup_edge":(2,3),"root":root,"terminals":terminals,"adjacency":None,"controller":controller,"mcast_address":IPAddr("10.0.0.7")}    
  backup = multicast.BackupTree(**data)
  print "after backup"
  
  primary.backup_trees[(2,3)] = backup

  expected_result = [8,7,2]
  
  test_name = "test_baseline_bottom_up_signal_simple_path()"
  baseline_check_nodes_to_signal(expected_result, backup.nodes_to_signal, 1, (2,3), test_name)

def depracated_test_baseline_bottom_up_signal_trees1():
  """ Test no longer works because need port mappings in the adjacency matrix to compute these nodes. """
  setup()
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.BASELINE
  
  # just a simple path
  primary_edges =  [(1,5),(5,6),(6,7),(6,8),(8,9),(8,10),(7,2),(9,3),(10,4)]
  backup_edges = [(1,5),(5,11),(11,12),(11,7),(7,2),(12,10),(12,9),(10,4),(9,3)]

  
  root = IPAddr("10.0.0.1")
  terminals = [IPAddr("10.0.0.2"),IPAddr("10.0.0.3"),IPAddr("10.0.0.4")]
  data = {"edges":primary_edges,"mcast_address":IPAddr("10.10.10.10"),"root":root,"terminals":terminals,"adjacency":None,"controller":controller}   
  primary = multicast.PrimaryTree(**data)
  

  data = {"primary_tree":primary,"edges":backup_edges,"backup_edge":(1,2),"root":root,"terminals":terminals,"adjacency":None,"controller":controller,"mcast_address":IPAddr("10.0.0.7")}    
  backup = multicast.BackupTree(**data)
  
  primary.backup_trees[(1,2)] = backup

  #result = backup.compute_nodes_to_signal((2,3))
  
  expected_result = [12,11,5]
  
  test_name = "test_baseline_bottom_up_signal_trees1"
  baseline_check_nodes_to_signal(expected_result, backup.nodes_to_signal, 1, (1,2), test_name)

    
def depracated_test_baseline_bottom_up_signal_trees2():
  """ Test no longer works because need port mappings in the adjacency matrix to compute these nodes. """
  setup()
  controller = appleseed.fault_tolerant_controller()
  controller.algorithm_mode = multicast.Mode.BASELINE
  
  # just a simple path
  primary_edges = [(1,2),(2,3),(3,4),(3,5),(4,6),(5,7),(5,8)]
  backup_edges = [(1,9),(9,10),(9,4),(10,7),(10,8),(4,6)]

  
  root = IPAddr("10.0.0.1")
  terminals = [IPAddr("10.0.0.6"),IPAddr("10.0.0.7"),IPAddr("10.0.0.8")]
  data = {"edges":primary_edges,"mcast_address":IPAddr("10.10.10.10"),"root":root,"terminals":terminals,"adjacency":None,"controller":controller}   
  primary = multicast.PrimaryTree(**data)
  

  data = {"primary_tree":primary,"edges":backup_edges,"backup_edge":(1,2),"root":root,"terminals":terminals,"adjacency":None,"controller":controller,"mcast_address":IPAddr("10.0.0.7")}    
  backup = multicast.BackupTree(**data)
  
  primary.backup_trees[(1,2)] = backup
  
  expected_result = [10,9,1]
  
  test_name = "test_baseline_bottom_up_signal_trees2"
  baseline_check_nodes_to_signal(expected_result, backup.nodes_to_signal, 1, (1,2), test_name)

def launch ():
  if 'openflow_discovery' not in core.components:
    import pox.openflow.discovery as discovery
    discovery.LINK_TIMEOUT = 1000
    core.registerNew(discovery.Discovery)
    
  core.registerNew(appleseed.fault_tolerant_controller)
  
  
  baseline_test_names = ["test_merger_treeid_h6s12","test_baseline_treeid_h6s12()",] #"test_steiner_arboresence()"] 
  #test_steiner_arboresence()
  test_backups_h6s9()
  test_reactive_backups_h6s9()
  test_backups_h6s9_3trees()
  
  test_merger_treeid_h6s12()
  test_baseline_treeid_h6s12()
  #test_baseline_bottom_up_signal_simple_path()
  #test_baseline_bottom_up_signal_trees1()
  #test_baseline_bottom_up_signal_trees2()
  
  
  merger_test_names = ["test_backups_h6s11()\t", "test_backups_h6s9_3trees()","test_backups_h6s9()\t\t","test_reactive_backups_h6s9()", "test_h6s10()\t\t","test_h6s10_4trees_order1()","test_h6s10_4trees_order2()"]
  
  test_backups_h6s11()
  test_backups_h6s9_3trees()
  test_reactive_backups_h6s9()
  test_backups_h6s9()
  test_h6s10()
  test_h6s10_4trees_order1()
  test_h6s10_4trees_order2()
  print_successful_test_results(baseline_test_names,merger_test_names)
  
  
  os._exit(0)