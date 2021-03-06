#from sympy.utilities.iterables import permutations, multiset_partitions, partitions
import networkx as nx
import multicast
#import pydot as pydot
from pox.core import core
log = core.getLogger("steiner_arboresence")

class SteinerArborescence (object):

    """
    TODO: An instance of this class should compute a Steiner Arborescence (type DiGraph) and store it as a field
    Direct this via __init__
    """ 
    
    def compute_primary_tree(self,adjacency_list,root,terminals):
        # Initialize Network object from adj list
        Network = nx.DiGraph()
        for e in adjacency_list.keys():
            Network.add_edge(e[0],e[1])
        digraph = self.compute_steiner_arborescence(Network,root,terminals,adjacency_list)
        if digraph == None:
          return False,None
        return True,digraph.edges()
        
    def compute_backup_tree(self,adjacency_list,root,terminals,primary_tree_edges,backup_edge,verbose=False):
        # Initialize Network object from adj list
        Network = nx.DiGraph()
        for e in adjacency_list.keys():
            Network.add_edge(e[0],e[1])
        Network.remove_edge(backup_edge[0],backup_edge[1]) #removing the 'down' link
            
        primary_tree = nx.DiGraph()
        for e in primary_tree_edges: # Assuming tuples (keys) u,d from a dict of ({u,d}:p)
            primary_tree.add_edge(e[0],e[1])
        
        if verbose: print "Removing",backup_edge[0],backup_edge[1]
        if(backup_edge[1] in terminals and nx.has_path(Network,root,backup_edge[1]) or backup_edge[1] not in terminals):
            Network_with_Primary_Tree_Edges_Zeroed = self.primary_tree_weights_to_zero(Network,primary_tree,backup_edge)
            if verbose: print "Set all primary tree edges to 0, excluding the backup_edge",backup_edge

            backup_tree = self.compute_steiner_arborescence(Network_with_Primary_Tree_Edges_Zeroed,root,terminals,adjacency_list)
            
            if backup_tree == None:
              return False,None #do not have path to all terminals in backup tree
            if verbose: print "Computed back-up tree for a 'down' link",backup_edge
            if verbose: print "Backup Tree",backup_edge,":",backup_tree.edges(),"\n"
            
        else:
            print "Stopping. The backup tree for 'down' link",backup_edge,"can't be connected to all terminals."
            return
        
        return True,backup_tree.edges() # Return adjacency list

    def nx_copy_minus_nodes(self,exclude_nodes,root,v,orig_graph):
        #print '\t DPG: path from root to v = %s' %(exclude_nodes)
        nx_copy = nx.DiGraph()
        exclude_nodes.remove(root)
        exclude_nodes.remove(v)
        for e in orig_graph.edges(): 
          if e[0] in exclude_nodes or e[1] in exclude_nodes:
            if multicast.is_switch(e[0]) and multicast.is_switch(e[1]):
              #print "\t\t DPG excluding BT%s, e=(%s,%s)" %(root,e[0],e[1])
              continue
          
          nx_copy.add_edge(e[0],e[1])
        return nx_copy

    def compute_steiner_arborescence(self,Network,root,terminal_set,adjacency_list,verbose=False):
        def get_optimal_v_node():
                
            def average_density(node):
                total_cost = 0
                terminals_visited_yet = 0
                path_from_root_to_candidate = nx.shortest_path(Network)[root][node]
                
#                if node in path_from_root_to_candidate:
#                  return 999999
                
                #print 'DPG: density computation ---- about to Remove edges to each node on nx_path=%s' %(path_from_root_to_candidate)
                nx_copy = self.nx_copy_minus_nodes(path_from_root_to_candidate,root,node, Network)
                #edgelist_from_path = compute_edgelist_from_path(path_from_root_to_candidate)
                
                for t in terminal_set:
                    if(nx.has_path(nx_copy,node,t)):
                        if(verbose):
                            print "Distance to",t,"=",nx.shortest_path_length(nx_copy,source=node,target=t,weight='weight')
                        total_cost += nx.shortest_path_length(nx_copy,node,t)
                        terminals_visited_yet += 1
                        if(verbose):
                            print terminals_visited_yet,"Current Average Density:",(float(total_cost)/terminals_visited_yet)
                    else:
                        total_cost = 9999999
                # Casting numerator || denominator results in a float
                total_cost = (float(total_cost)/len(terminal_set))
                return total_cost
            
            cost = {}
            
            shortest_paths = nx.shortest_path_length(Network,weight='weight')
            # cost = shortest_paths['b'] #Get the shortest paths from the root.
            # del cost['b'] #Delete the root so that we don't consider the root-to-root path.
            cost = shortest_paths[root] #Get the shortest paths from the root.
            del cost[root] #Delete the root so that we don't consider the root-to-root path.
            for node in terminal_set:
                if cost.has_key(node):
                  del cost[node] #Don't consider any of the terminals for consideration as a v-node.
            
            # DPG additions
            for node in nx.nodes_iter(Network):   #remove any other hosts from consideration
                if not multicast.is_switch(node) and cost.has_key(node):
                  #print 'DPG Debug: removing id=%s node because its a host' %(node)
                  del cost[node]
                  
            for node in nx.nodes_iter(Network):
                is_not_terminal = node not in terminal_set
                is_not_root = node is not root
                is_switch = multicast.is_switch(node)
                
                #print 'before: r=%s,node=%s,term=%s \t\t N%s properities: is_not_term=%s,is_not_root=%s,is_switch=%s,is_not_neigh=%s' %(root,node,terminal_set,node,is_not_terminal,is_not_root,is_switch,is_not_root_neigh)
                if is_not_terminal and is_not_root and is_switch:  
                    #print 'after: r=%s,node=%s' %(root,node)
                    if(verbose):
                        print "v = " + node
                    if not cost.has_key(node):
                      continue #no path to node so skip
                    distance_from_root = cost[node]
                    cost[node] += average_density(node)
                    if(verbose):
                        print "Distance from Root =",distance_from_root,"| Final Steiner Score:", cost[node],"\n"
                    
                    # For some reason this throws an error here, so compute this in dict before the function
                    # print nx.shortest_path_length(root,node)
                    
            # Find the least value return the key
            optimal_v_node = min(cost, key=cost.get)
            if(verbose):
                print "Used v node: ",optimal_v_node,"\n"
            return optimal_v_node
            
        def compute_edgelist_from_path(path):
            edge_list = []
            node_a = None
            node_b = None
            for node in path:
                if(node_a is None):
                    node_a = node
                else:
                    node_b = node
                    edge_list.append((node_a,node_b))
                    node_a = node_b
                    node_b = None
            return edge_list
            
        SteinerTree = nx.DiGraph()
        optimal_v_node = get_optimal_v_node()
        path_from_root_to_v = nx.shortest_path(Network)[root][optimal_v_node]
        root2v_edges = compute_edgelist_from_path(path_from_root_to_v)
        SteinerTree.add_edges_from(root2v_edges)
        #print 'DPG Debug: computing path from v=%s to terminals. ' %(optimal_v_node)
        nx_copy = self.nx_copy_minus_nodes(path_from_root_to_v,root,optimal_v_node,Network)
        for t in terminal_set:
            log.debug('tree_id=%s,v=%s,dst=%s' %(root,optimal_v_node,t))
            
            if not nx.shortest_path(nx_copy)[optimal_v_node].has_key(t):
              log.debug('skipping backup tree creation because path to terminal does not exist')
              return None
            path_from_v_to_t = nx.shortest_path(nx_copy)[optimal_v_node][t]
            edgelist_from_path = compute_edgelist_from_path(path_from_v_to_t)
            SteinerTree.add_edges_from(edgelist_from_path)
        return SteinerTree
#        for t in terminal_set:
#            log.debug('tree_id=%s,v=%s,dst=%s' %(root,optimal_v_node,t))
#            path_from_v_to_t = nx.shortest_path(Network)[optimal_v_node][t]
#            edgelist_from_path = compute_edgelist_from_path(path_from_v_to_t)
#            SteinerTree.add_edges_from(edgelist_from_path)
#        return SteinerTree    
    def primary_tree_weights_to_zero(self,Network,Primary_Tree,backup_edge_to_exclude,verbose=False):
        """
        Input: A Network and a Primary Tree
        Output: A new Network with the Primary Tree edges set to 0
        This function preprocesses the Network graph to allow us to select a backup tree from.
        We can make the assumption that the Primary Tree is a subset of the Network graph,
        and therefore each edge in the Primary Tree is in the Network graph
        We should not re-add the backup_edge to the new Network
        """
        
        weight = 0
        for e in Primary_Tree.edges():
            if(e != backup_edge_to_exclude):
                Network.add_edge(e[0],e[1],weight=weight)
            else:
                if verbose: print "skipping",backup_edge_to_exclude
        return Network
        
    def kbin(self,l, k, ordered=True):
        """
        Return sequence ``l`` partitioned into ``k`` bins.

        Examples
        ========

        The default is to give the items in the same order, but grouped
        into k partitions:

        >>> for p in kbin(range(5), 2):
        ...     print p
        ...
        [[0], [1, 2, 3, 4]]
        [[0, 1], [2, 3, 4]]
        [[0, 1, 2], [3, 4]]
        [[0, 1, 2, 3], [4]]

        Setting ``ordered`` to None means that the order of the elements in
        the bins is irrelevant and the order of the bins is irrelevant. Though
        they are returned in a canonical order as lists of lists, all lists
        can be thought of as sets.

        >>> for p in kbin(range(3), 2, ordered=None):
        ...     print p
        ...
        [[0, 1], [2]]
        [[0], [1, 2]]
        [[0, 2], [1]]

        """

        def partition(lista, bins):
            #  EnricoGiampieri's partition generator from
            #  http://stackoverflow.com/questions/13131491/
            #  partition-n-items-into-k-bins-in-python-lazily
            if len(lista) == 1 or bins == 1:
                yield [lista]
            elif len(lista) > 1 and bins > 1:
                for i in range(1, len(lista)):
                    for part in partition(lista[i:], bins - 1):
                        if len([lista[:i]] + part) == bins:
                            yield [lista[:i]] + part
        if ordered:
            for p in partition(l, k):
                yield p
        else:
            for p in multiset_partitions(l, k):
                yield p
        
def main():
    
    #This will need to be automated.
    
    # adjacency = [(10,11,2), (9,8,2), (14,13,1), (10,12,3), (8,9,2), (13,14,3), (11,14,1), (15,12,1), (10,8,1),(11,10,2), 
    #             (8,10,3), (13,7,1), (12,10,2), (12,14,1), (7,1,1), (7,5,2), (8,7,1), (14,11,3), (9,13,1), (12,15,3), (9,2,3),
    #             (7,13,3), (11,3,3), (14,12,2), (15,6,2), (12,4,4), (13,9,2), (7,8,4)]
                
    test_adjacency = {(10, 11): 2, (9, 8): 2, (14, 13): 1, (10, 12): 3, (8, 9): 2, (13, 14): 3, (11, 14): 1, (15, 12): 1, (10, 8): 1, (11, 10): 2, 
         (8, 10): 3, (13, 7): 1, (12, 10): 2, (12, 14): 1, (7, 1): 1, (7, 5): 2, (8, 7): 1, (14, 11): 3, (9, 13): 1, (12, 15): 3, (9, 2): 
         3, (7, 13): 3, (11, 3): 3, (14, 12): 2, (15, 6): 2, (12, 4): 4, (13, 9): 2, (7, 8): 4}
         
    test_elist = {('a','b'): 2,('b','c'): 2,('d','e'): 2,('a','d'): 2,('a','e'): 2,
                    ('d','h'): 2,('h','n'): 2,('e','i'): 2,('d','i'): 2,('i','h'): 2,
                    ('i','j'): 2,('j','e'): 2,('e','b'): 2,('b','f'): 2,('f','j'): 2,
                    ('j','p'): 2,('j','k'): 2,('k','f'): 2,('f','c'): 2,('f','g'): 2,
                    ('g','m'): 2,('k','m'): 2,('m','r'): 2,('k','r'): 2,('k','q'): 2,
                    ('c','b'): 2,('e','d'): 2,('d','a'): 2,('e','a'): 2,('h','d'): 2,
                    ('i','e'): 2,('i','o'): 2,('i','d'): 2,('j','i'): 2,('e','j'): 2,
                    ('b','e'): 2,('f','b'): 2,('j','f'): 2,('k','j'): 2,('f','k'): 2,
                    ('c','f'): 2,('g','f'): 2,('g','c'): 2,('k','g'): 2,('m','g'): 2,
                    ('c','g'): 2,('g','k'): 2,('m','k'): 2,('b','a'): 2,('i','n'): 2}
                    
    test_elist_nums = {(1,2): 2,(2,3): 2,(4,5): 2,(1,4): 2,(1,5): 2,
                    (4,8): 2,(8,14): 2,(5,9): 2,(4,9): 2,(9,8): 2,
                    (9,10): 2,(10,5): 2,(5,2): 2,(2,6): 2,(6,10): 2,
                    (10,16): 2,(10,11): 2,(11,6): 2,(6,3): 2,(6,7): 2,
                    (7,13): 2,(11,13): 2,(13,18): 2,(11,18): 2,(11,17): 2,
                    (3,2): 2,(5,4): 2,(4,1): 2,(5,1): 2,(8,4): 2,
                    (9,5): 2,(9,15): 2,(9,4): 2,(10,9): 2,(5,10): 2,
                    (2,5): 2,(6,2): 2,(10,6): 2,(11,10): 2,(6,11): 2,
                    (3,6): 2,(7,6): 2,(7,3): 2,(11,7): 2,(13,7): 2,
                    (3,7): 2,(7,11): 2,(13,11): 2,(2,1): 2,(9,14): 2}
                    
    expected_edges1 = [(2, 5), (5, 10), (9, 14), (9, 15), (10, 16), (10, 9), (10, 11), (11, 17), (11, 18)]
    expected_edges2 = [(5, 10),(2, 5), (9, 14), (9, 15), (10, 16), (10, 9), (10, 11), (11, 17), (11, 18)]
    
    print expected_edges1 == expected_edges2
    
    # MyNet = nx.DiGraph()
    # for e in test_adjacency.keys():
    #     MyNet.add_edge(e[0],e[1])
        
    # print MyNet.edges()
       
    Network = nx.DiGraph()
    SteinerArb = SteinerArborescence()

    weight = 1

    #It's not necessary to give an explicit key as here, since we can key the edge dict by the in/out node.
    #This key would be lost when we produce a primary tree.

    # elist = [("a","b",weight,'a,b'),("b","c",weight,'b,c'),("d","e",weight,'d,e'),("a","d",weight,'a,d'),("a","e",weight,'a,e'),
    #         ("d","h",weight,'d,h'),("h","n",weight,'h,n'),("e","i",weight,'e,i'),("d","i",weight,'d,i'),("i","h",weight,'i,h'),
    #         ("i","j",weight,'i,j'),("j","e",weight,'j,e'),("e","b",weight,'e,b'),("b","f",weight,'b,f'),("f","j",weight,'f,j'),
    #         ("j","p",weight,'j,p'),("j","k",weight,'j,k'),("k","f",weight,'k,f'),("f","c",weight,'f,c'),("f","g",weight,'f,g'),
    #         ("g","m",weight,'g,m'),("k","m",weight,'k,m'),("m","r",weight,'m,r'),("k","r",weight,'k,r'),("k","q",weight,'k,q'),
    #         ("c","b",weight,'c,b'),("e","d",weight,'e,d'),("d","a",weight,'d,a'),("e","a",weight,'e,a'),("h","d",weight,'h,d'),
    #         ("i","e",weight,'i,e'),("i","o",weight,'i,o'),("i","d",weight,'i,d'),("j","i",weight,'j,i'),("e","j",weight,'e,j'),
    #         ("b","e",weight,'b,e'),("f","b",weight,'f,b'),("j","f",weight,'j,f'),("k","j",weight,'k,j'),("f","k",weight,'f,k'),
    #         ("c","f",weight,'c,f'),("g","f",weight,'g,f'),("g","c",weight,'g,c'),("k","g",weight,'k,g'),("m","g",weight,'m,g'),
    #         ("c","g",weight,'c,g'),("g","k",weight,'g,k'),("m","k",weight,'m,k'),("b","a",weight,'b,a'),("i","n",weight,'i,n')]
    
    elist = [("a","b",'a,b'),("b","c",'b,c'),("d","e",'d,e'),("a","d",'a,d'),("a","e",'a,e'),
            ("d","h",'d,h'),("h","n",'h,n'),("e","i",'e,i'),("d","i",'d,i'),("i","h",'i,h'),
            ("i","j",'i,j'),("j","e",'j,e'),("e","b",'e,b'),("b","f",'b,f'),("f","j",'f,j'),
            ("j","p",'j,p'),("j","k",'j,k'),("k","f",'k,f'),("f","c",'f,c'),("f","g",'f,g'),
            ("g","m",'g,m'),("k","m",'k,m'),("m","r",'m,r'),("k","r",'k,r'),("k","q",'k,q'),
            ("c","b",'c,b'),("e","d",'e,d'),("d","a",'d,a'),("e","a",'e,a'),("h","d",'h,d'),
            ("i","e",'i,e'),("i","o",'i,o'),("i","d",'i,d'),("j","i",'j,i'),("e","j",'e,j'),
            ("b","e",'b,e'),("f","b",'f,b'),("j","f",'j,f'),("k","j",'k,j'),("f","k",'f,k'),
            ("c","f",'c,f'),("g","f",'g,f'),("g","c",'g,c'),("k","g",'k,g'),("m","g",'m,g'),
            ("c","g",'c,g'),("g","k",'g,k'),("m","k",'m,k'),("b","a",'b,a'),("i","n",'i,n')]

    for e in elist:
        # Network.add_edge(e[0],e[1],weight=e[2],key=e[3])
          Network.add_edge(e[0],e[1],key=e[2])
        
    # nx.write_dot(test_adj_graph,"./myGraph.dot")

    # Assuming the root would be handed to this procedure
    root = "b"
    root_nums = 2

    terminals = ['o','p','n','q','r']
    terminals_nums = [15,16,14,17,18]

    """Find all combinations of terminals to put in k bins"""
    #bunched_terminals = []
    #k = 1
    #for l in SteinerArb.kbin(terminals,k,ordered=False):
    #    bunched_terminals.append(l)
        # i += 1
        
    """Remove each edge and compute a backup tree, then put it back"""

    # SteinerArb.get_optimal_v_node(Network,root,terminals,verbose=True)
    print "Initial Primary Tree:"
    primary_tree = SteinerArb.compute_primary_tree(test_elist_nums,root_nums,terminals_nums)
    # primary_tree = SteinerArb.compute_steiner_arborescence(Network,root,terminals,verbose=False)
    # primary_tree = SteinerArb.compute_primary_tree(Network,root,terminals,verbose=False)
    print "Finished computing initial primary tree.\n"
    # print primary_tree.edges()
    print "Computing backup trees for each edge in the primary tree using network nodes:\n"
    backup_trees = {}
    #Currently, we are checking to see if a node is reachable after we remove an edge. Actually, this is overkill.
    #We only need to not compute a backup tree if it's a terminal and then not reachable.
    
    for e in primary_tree.edges():
        SteinerArb.compute_backup_tree(test_elist_nums,root_nums,terminals_nums,primary_tree.edges(),e)
        # backup_edge is really e. This is just to match the method signature.
        # Network.remove_edge(e[0],e[1])
        # print "Removing",e,"\n"
        # if(e[1] in terminals and nx.has_path(Network,root,e[1]) or e[1] not in terminals):
        #     Network_with_Primary_Tree_Edges_Zeroed = SteinerArb.primary_tree_weights_to_zero(Network,primary_tree)
        #     #print "Network_with_Primary_Tree_Edges_Zeroed:",Network_with_Primary_Tree_Edges_Zeroed.edges(data=True)
        #     #print "Primary_Tree:",primary_tree.edges(data=True)
        #     print "Set all primary tree edges to 0"
        #     backup_trees[e] = SteinerArb.compute_steiner_arborescence(Network_with_Primary_Tree_Edges_Zeroed,root,terminals,verbose=False)
        #     #backup_trees[e] = SteinerArb.compute_steiner_arborescence(Network,root,terminals,verbose=True)
        #     print "Computed back-up tree for a down edge",e,"\n"
        #     print "Backup Tree",e,":",backup_trees[e].edges(),"\n"
        # Network.add_edge(e[0],e[1])
        # print "Put back",e,"\n"
    print "Finished computing all primary trees.\n"
            
if __name__ == "__main__":
    main()