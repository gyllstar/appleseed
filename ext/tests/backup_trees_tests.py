"""

Unit tests for multicast.py working with backup trees.

To run this test I had to add the appleseed root folder to the Python path

@author: dpg
"""

import unittest
#from pox.ext.backup_trees import BackupTreeInstaller

from ext.multicast import PrimaryTree,BackupTree
from pox.lib.addresses import IPAddr


class BackupTreeTests(unittest.TestCase):
  
  
  def setUp(self):
    unittest.TestCase.setUp(self)
  
  def test_bottom_up_signal_simple_path(self):
    
    # just a simple path
    primary_edges = [(1,2),(2,3),(3,4),(4,5),(5,6)]
    backup_edges = [(1,2),(2,7),(7,8),(8,5),(5,6)]
  
    
    root = IPAddr("10.0.0.1")
    terminals = [IPAddr("10.0.0.6")]
    data = {"edges":primary_edges,"mcast_address":IPAddr("10.0.0.6"),"root":root,"terminals":terminals,"adjacency":None,"controller":None}   
    primary = PrimaryTree(**data)
    

    data = {"primary_tree":primary,"edges":backup_edges,"backup_edge":(2,3),"root":root,"terminals":terminals,"adjacency":None,"controller":None,"mcast_address":IPAddr("10.0.0.7")}    
    backup = BackupTree(**data)
    
    primary.backup_trees.append(backup)

    #result = backup.compute_nodes_to_signal((2,3))
    
    expected_result = [8,7,2]
    
    print "test_bottom_up_signal_simple_path() result = %s" %(backup.nodes_to_signal)
    self.assertEquals(backup.nodes_to_signal, expected_result)

  def test_bottom_up_signal_trees1(self):
    
    # just a simple path
    primary_edges =  [(1,5),(5,6),(6,7),(6,8),(8,9),(8,10),(7,2),(9,3),(10,4)]
    backup_edges = [(1,5),(5,11),(11,12),(11,7),(7,2),(12,10),(12,9),(10,4),(9,3)]
  
    
    root = IPAddr("10.0.0.1")
    terminals = [IPAddr("10.0.0.2"),IPAddr("10.0.0.3"),IPAddr("10.0.0.4")]
    data = {"edges":primary_edges,"mcast_address":IPAddr("10.10.10.10"),"root":root,"terminals":terminals,"adjacency":None,"controller":None}   
    primary = PrimaryTree(**data)
    

    data = {"primary_tree":primary,"edges":backup_edges,"backup_edge":(1,2),"root":root,"terminals":terminals,"adjacency":None,"controller":None,"mcast_address":IPAddr("10.0.0.7")}    
    backup = BackupTree(**data)
    
    primary.backup_trees.append(backup)

    #result = backup.compute_nodes_to_signal((2,3))
    
    expected_result = [12,11,5]
    
    print "test_bottom_up_signal_trees1() result = %s" %(backup.nodes_to_signal)
    print backup.nodes_to_signal
    self.assertEquals(backup.nodes_to_signal, expected_result)

    
  def test_bottom_up_signal_trees2(self):
    
    # just a simple path
    primary_edges = [(1,2),(2,3),(3,4),(3,5),(4,6),(5,7),(5,8)]
    backup_edges = [(1,9),(9,10),(9,4),(10,7),(10,8),(4,6)]
  
    
    root = IPAddr("10.0.0.1")
    terminals = [IPAddr("10.0.0.6"),IPAddr("10.0.0.7"),IPAddr("10.0.0.8")]
    data = {"edges":primary_edges,"mcast_address":IPAddr("10.10.10.10"),"root":root,"terminals":terminals,"adjacency":None,"controller":None}   
    primary = PrimaryTree(**data)
    

    data = {"primary_tree":primary,"edges":backup_edges,"backup_edge":(1,2),"root":root,"terminals":terminals,"adjacency":None,"controller":None,"mcast_address":IPAddr("10.0.0.7")}    
    backup = BackupTree(**data)
    
    primary.backup_trees.append(backup)

    #result = backup.compute_nodes_to_signal((2,3))
    
    expected_result = [10,9,1]
    
    print "test_bottom_up_signal_trees2() result = %s" %(backup.nodes_to_signal)
    print backup.nodes_to_signal
    self.assertEquals(backup.nodes_to_signal, expected_result)
    
    
    
##############################################################   DEPRACTED TESTS BELOW    ######################################################################################
    
  def depracted_test_find_nodes_to_signal(self):
    
    primary_edges = [(1,2),(2,3),(3,4),(5,6)]
    backup_edges = [(1,2),(2,4),(4,5),(5,6),(6,7)]
    
    backup = BackupTree()
    backup.edges = backup_edges
    primary = PrimaryTree()
    primary.edges = primary_edges
    primary.backup_trees[(2,3)] = backup

    result = primary.find_nodes_to_signal((2,3))
    
    expected_result = [2,4,6]
    
    self.assertEquals(result, expected_result)
        
    
  def depracted_test_find_affected_trees(self):
    """ Find and return the multicast address associate with the primary trees using the failed link 
    
    Keyword Arguments:
    primary_trees -- dictionary: multicast_dst_address -> list of tuples (u,d), representing a directed edge from u to d, that constitute all edges in the primary tree
    failed_link -- tuple (upstream_switch_id,downstream_switch_id)
    
    """
    
    failed_link = (5,6)
    tree1 = PrimaryTree()
    tree2 = PrimaryTree()
    tree3 = PrimaryTree()
    
    tree1.edges = [(1,2),(2,3),(3,4),(5,6)]
    tree1.mcast_address = "10.10.10.10" 
    tree2.edges =  [(1,2),(2,4),(4,5),(5,6),(6,7)]
    tree2.mcast_address = "10.11.11.11"
    tree3.edges =  [(4,5),(6,5),(2,3),(7,9),(9,11),(11,4),(8,13)]
    tree3.mcast_address = "10.12.12.12"
    
    primary_trees = [tree1,tree2,tree3]
    
    expected_result = ["10.10.10.10","10.11.11.11"]
    
    result_trees = self.installer._find_affected_trees(primary_trees, failed_link)
    print result_trees
    result = [tree.mcast_address for tree in result_trees]

    for addr in result:
      self.assertTrue(addr in expected_result)
    
