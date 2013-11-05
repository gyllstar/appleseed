# @author: dpg/gyllstar/Dan Gyllstrom


""" Tests the Merger algorithm.
"""


import unittest
import appleseed,multicast
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
    
def test_h6s10():
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  
  
  controller = appleseed.fault_tolerant_controller()
  controller.adjacency = h6s10_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16]
  multicast.compute_primary_trees(controller)
  multicast.create_install_merged_primary_tree_flows(controller)
  
  expected_num_flows = {7:2,8:1,9:2,10:2,11:1,12:3,13:0,14:0,15:1,16:1}
  
  test_name = "test_h6s10()"
  check_correct_num_flows(expected_num_flows, test_name)
  
def test_h6s10_4trees_order1():
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  
  
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
  
  expected_num_flows = {7:2,8:2,9:2,10:3,11:2,12:4,13:0,14:0,15:1,16:1}
  
  test_name = "test_h6s10_4trees_order1()"
  check_correct_num_flows(expected_num_flows, test_name)
  
  #total = 17


def test_h6s10_4trees_order2():
  setup()
  h6s10_adjancency = {(10, 11): 2, (16, 9): 1, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, (16, 10): 2, (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (9, 16): 4, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (11, 3): 3, (13, 14): 3, (10, 16): 4, (7, 13): 3, (9, 2): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
  
  
  controller = appleseed.fault_tolerant_controller()
  controller.adjacency = h6s10_adjancency

  core.openflow_discovery._dps = [7,8,9,10,11,12,13,14,15,16]
  
  edges = [(3,11),(11,10),(10,8),(10,12),(8,9),(12,4),(12,15),(9,2),(15,6)]
  mcast_addr = IPAddr("10.13.13.13")
  root = IPAddr("10.0.0.3")
  terminal_hosts = [IPAddr("10.0.0.2"),IPAddr("10.0.0.4"),IPAddr("10.0.0.6")]
  data = {"edges":edges, "mcast_address":mcast_addr, "root":root, "terminals":terminal_hosts, "adjacency":controller.adjacency, "controller":controller}
  tree = multicast.PrimaryTree(**data)
  controller.primary_trees.append(tree)  
  
  multicast.compute_primary_trees(controller)
  multicast.create_install_merged_primary_tree_flows(controller)
  
  expected_num_flows = {7:2,8:2,9:2,10:3,11:2,12:4,13:0,14:0,15:1,16:1}
  test_name = "test_h6s10_4trees_order2()"
  check_correct_num_flows(expected_num_flows, test_name)
  
  #total = 17

def launch ():
  if 'openflow_discovery' not in core.components:
    import pox.openflow.discovery as discovery
    discovery.LINK_TIMEOUT = 1000
    core.registerNew(discovery.Discovery)
    
  core.registerNew(appleseed.fault_tolerant_controller)
  
  test_names = ["test_h6s10()\t\t","test_h6s10_4trees_order1()","test_h6s10_4trees_order1()"]
  test_h6s10()
  test_h6s10_4trees_order1()
  test_h6s10_4trees_order2()
  print_successful_test_results(test_names)
  
  
  os._exit(0)