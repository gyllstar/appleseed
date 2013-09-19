"""

Unit tests for backup_trees

@author: dpg
"""

import unittest
#from pox.ext.backup_trees import BackupTreeInstaller

#import BackupTreeInstaller
from trees import BackupTreeInstaller,PrimaryTree,Tree

#from pox.ext.backup_trees import BackupTreeInstallers 


class BackupTreeInstallerTests(unittest.TestCase):
  
  installer = BackupTreeInstaller()
  
  def setUp(self):
    unittest.TestCase.setUp(self)
    self.installer = BackupTreeInstaller()
  
  def test_find_nodes_to_signal(self):
    
    primary_edges = [(1,2),(2,3),(3,4),(5,6)]
    backup_edges = [(1,2),(2,4),(4,5),(5,6),(6,7)]
    
    backup = Tree()
    backup.edges = backup_edges
    primary = PrimaryTree()
    primary.edges = primary_edges
    primary.backup_trees[(2,3)] = backup

    result = primary.find_nodes_to_signal((2,3))
    
    expected_result = [2,4,6]
    
    self.assertEquals(result, expected_result)
    
        
    
  def test_find_affected_trees(self):
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
    
