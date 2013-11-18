from sympy.utilities.iterables import permutations, multiset_partitions, partitions
import networkx as nx

class SteinerArborescence (object):

    """
    TODO: An instance of this class should compute a Steiner Arborescence (type DiGraph) and store it as a field
    Direct this via __init__
    """
    # def __init__(self):
        
        
    # def compute_steiner_arborescence(self,Network,root,terminal_set,verbose=False):
    def compute_steiner_arborescence(self,adjacency_list,root_id,terminal_ids,verbose=False):
  
        def get_optimal_v_node():
            
            """
            AVG_DENSITY( Node v, Terminal Set t[ .. ] ):
                For each t(i) in Terminal Set:
                    if path(v,t(i)) exists:
                        Store the path length of the shortest such path
                    else:
                        exit since this bunch does not connect t(i) since it must at least connect to all terminals
                Compute the average density by averaging the path lengths

            OPTIMAL_VNODE ( Graph G, Terminal Set t[ .. ] ):
                Starting at G.root, BFS the Graph:
                For each node:
                    cost[i] = AVG_DENSITY( this node, Terminal Set ) + path_length(root, this node )
                return min(avg_density)
            """
            
            cost = {}
            
            def average_density(node):
                total_cost = 0
                terminals_visited_yet = 0
                for t in terminal_set:
                    if(nx.has_path(Network,node,t)):
                        if(verbose):
                            print "Distance to",t,"=",nx.shortest_path_length(Network,source=node,target=t,weight='weight')
                        total_cost += nx.shortest_path_length(Network,node,t)
                        terminals_visited_yet += 1
                        if(verbose):
                            print terminals_visited_yet,"Current Average Density:",(float(total_cost)/terminals_visited_yet)
                    else:
                        pass
                # Casting numerator || denominator results in a float
                total_cost = (float(total_cost)/len(terminal_set))
                return total_cost
            
            shortest_paths = nx.shortest_path_length(Network,weight='weight')
            cost = shortest_paths['b'] #Get the shortest paths from the root.
            del cost['b'] #Delete the root so that we don't consider the root-to-root path.
            for node in terminal_set:
                del cost[node] #Don't consider any of the terminals for consideration as a v-node.
            for node in nx.nodes_iter(Network):
                if node not in terminal_set and node is not root:
                    if(verbose):
                        print "v = " + node
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
        edgelist_from_path = compute_edgelist_from_path(path_from_root_to_v)
        SteinerTree.add_edges_from(edgelist_from_path)
        for t in terminal_set:
            path_from_v_to_t = nx.shortest_path(Network)[optimal_v_node][t]
            edgelist_from_path = compute_edgelist_from_path(path_from_v_to_t)
            SteinerTree.add_edges_from(edgelist_from_path)
        return SteinerTree
        
    def primary_tree_weights_to_zero(self,Network,Primary_Tree):
        """
        Input: A Network and a Primary Tree
        Output: A new Network with the Primary Tree edges set to 0
        This function preprocesses the Network graph to allow us to select a backup tree from.
        We can make the assumption that the Primary Tree is a subset of the Network graph,
        and therefore each edge in the Primary Tree is in the Network graph
        """
        
        weight = 0
        for e in Primary_Tree.edges():
            Network.add_edge(e[0],e[1],weight=weight)
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
       
    Network = nx.DiGraph()
    SteinerArb = SteinerArborescence()

    weight = 1

    #It's not necessary to give an explicit key as here, since we can key the edge dict by the in/out node.
    #This key would be lost when we produce a primary tree.

    elist = [("a","b",weight,'a,b'),("b","c",weight,'b,c'),("d","e",weight,'d,e'),("a","d",weight,'a,d'),("a","e",weight,'a,e'),
            ("d","h",weight,'d,h'),("h","n",weight,'h,n'),("e","i",weight,'e,i'),("d","i",weight,'d,i'),("i","h",weight,'i,h'),
            ("i","j",weight,'i,j'),("j","e",weight,'j,e'),("e","b",weight,'e,b'),("b","f",weight,'b,f'),("f","j",weight,'f,j'),
            ("j","p",weight,'j,p'),("j","k",weight,'j,k'),("k","f",weight,'k,f'),("f","c",weight,'f,c'),("f","g",weight,'f,g'),
            ("g","m",weight,'g,m'),("k","m",weight,'k,m'),("m","r",weight,'m,r'),("k","r",weight,'k,r'),("k","q",weight,'k,q'),
            ("c","b",weight,'c,b'),("e","d",weight,'e,d'),("d","a",weight,'d,a'),("e","a",weight,'e,a'),("h","d",weight,'h,d'),
            ("i","e",weight,'i,e'),("i","o",weight,'i,o'),("i","d",weight,'i,d'),("j","i",weight,'j,i'),("e","j",weight,'e,j'),
            ("b","e",weight,'b,e'),("f","b",weight,'f,b'),("j","f",weight,'j,f'),("k","j",weight,'k,j'),("f","k",weight,'f,k'),
            ("c","f",weight,'c,f'),("g","f",weight,'g,f'),("g","c",weight,'g,c'),("k","g",weight,'k,g'),("m","g",weight,'m,g'),
            ("c","g",weight,'c,g'),("g","k",weight,'g,k'),("m","k",weight,'m,k'),("b","a",weight,'b,a'),("i","n",weight,'i,n')]

    for e in elist:
        Network.add_edge(e[0],e[1],weight=e[2],key=e[3])

    # Assuming the root would be handed to this procedure
    root = "b"

    terminals = ['o','p','n','q','r']

    """Find all combinations of terminals to put in k bins"""
    bunched_terminals = []
    k = 1
    for l in SteinerArb.kbin(terminals,k,ordered=False):
        bunched_terminals.append(l)
        # i += 1
        
    """Remove each edge and compute a backup tree, then put it back"""

    # SteinerArb.get_optimal_v_node(Network,root,terminals,verbose=True)
    print "Initial Primary Tree:"
    primary_tree = SteinerArb.compute_steiner_arborescence(Network,root,terminals,verbose=False)
    print "Finished computing initial primary tree.\n"
    # print primary_tree.edges()
    print "Computing backup trees for each edge in the primary tree using network nodes:"
    backup_trees = {}
    #Currently, we are checking to see if a node is reachable after we remove an edge. Actually, this is overkill.
    #We only need to not compute a backup tree if it's a terminal and then not reachable.
    for e in primary_tree.edges():
        Network.remove_edge(e[0],e[1])
        print "Removing",e,"\n"
        if(e[1] in terminals and nx.has_path(Network,root,e[1]) or e[1] not in terminals):
            Network_with_Primary_Tree_Edges_Zeroed = SteinerArb.primary_tree_weights_to_zero(Network,primary_tree)
            #print "Network_with_Primary_Tree_Edges_Zeroed:",Network_with_Primary_Tree_Edges_Zeroed.edges(data=True)
            #print "Primary_Tree:",primary_tree.edges(data=True)
            print "Set all primary tree edges to 0"
            backup_trees[e] = SteinerArb.compute_steiner_arborescence(Network_with_Primary_Tree_Edges_Zeroed,root,terminals,verbose=False)
            #backup_trees[e] = SteinerArb.compute_steiner_arborescence(Network,root,terminals,verbose=True)
            print "Computed back-up tree for a down edge",e,"\n"
            print "Backup Tree",e,":",backup_trees[e].edges(),"\n"
        Network.add_edge(e[0],e[1])
        print "Put back",e,"\n"
    print "Finished computing all primary trees.\n"

            
if __name__ == "__main__":
    main()