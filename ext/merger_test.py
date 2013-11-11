# @author: dpg/gyllstar/Dan Gyllstrom


""" Tests the Merger algorithm.
"""


import unittest
import appleseed,multicast
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


def get_num_type_matches(node_id,type):
  
  node = multicast.nodes[node_id]
  actual_value = 0
  for flow_entry in node.flow_entries:
    match = flow_entry.match_tag
    if match.type == type:
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

def print_successful_test_results(test_names):
  
  print "\n\n************************************************** THESE TESTS ALL COMPLETED CORRECTLY **************************************************************" 
  cnt = 0
  for test_name in test_names:
    cnt+=1
    print "**** \t\t (%s)  %s  \t\t\t\t\t\t\t\t\t\t\t\t ****" %(cnt,test_name)
  print "*****************************************************************************************************************************************************"
  

def test_h6s9():
  print "**** RUNNING MERGER_TEST.test_backups_h6s9() ****"
  setup()
  h6s9_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
  controller.adjacency = h6s9_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15]
  multicast.install_all_trees(controller)
  #multicast.compute_primary_trees(controller)
  #multicast.create_install_merged_primary_tree_flows(controller)
  
  #print "OS EXIT AT test_h6s9() "
  #os._exit(0)

def test_backups_h6s9_3trees():
  print "**** RUNNING MERGER_TEST.test_backups_h6s9_3trees() ****"
  setup()
  h6s9_adjancency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s9-2t.csv"
  multicast.measure_pnts_file_str="measure-h6s9-1d-1p.csv"
  controller = appleseed.fault_tolerant_controller()
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

  
    # GROUP_REUSE=0,GROUP=1,SINGLE=2,SINGLE_REUSE=3,MCAST_DST_ADDR=4,HOST_DST_ADDR=5) 
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
  #print "OS EXIT AT test_backups_h6s9_3trees() "
  #os._exit(0)

def test_h6s10():
  
  print "**** RUNNING MERGER_TEST.test_h6s10 ****"
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  multicast.mtree_file_str="mtree-h6s10-3t.csv"
  multicast.measure_pnts_file_str="measure-h6s10-1d-1p.csv"

  controller = appleseed.fault_tolerant_controller()
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

def launch ():
  if 'openflow_discovery' not in core.components:
    import pox.openflow.discovery as discovery
    discovery.LINK_TIMEOUT = 1000
    core.registerNew(discovery.Discovery)
    
  core.registerNew(appleseed.fault_tolerant_controller)
  
  test_names = ["test_backups_h6s9_3trees()","test_h6s9()\t\t","test_h6s10()\t\t","test_h6s10_4trees_order1()","test_h6s10_4trees_order2()"]
  test_backups_h6s9_3trees()
  test_h6s9()
  test_h6s10()
  test_h6s10_4trees_order1()
  test_h6s10_4trees_order2()
  print_successful_test_results(test_names)
  
  
  os._exit(0)