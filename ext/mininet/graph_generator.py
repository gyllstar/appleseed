""" Generated graphs with the same degree distribution as the IEEE Bus system graphs """

import sys, os, time, random, copy,csv
from mininet.topo import Topo
#import algs
#import stats


class Node(object):
  def __init__(self, nodeid):
    self.id = nodeid
    self.neighbors_ = []
    self.edges = []
        
  def addNeighbor(self, neighbor):
    self.neighbors_.append(neighbor)  
        
  def getId(self):
    return self.id
    
  def getNeighbors(self):
    return self.neighbors_
    
  def getNeighborIds(self):
        
    neighborids = []
    for neigh in self.neighbors_:
        neighborids.append(neigh.getId())
        
    return neighborids

  def neighListContainsNodeId(self, nodeid):
        
    for node in self.neighbors_:
        if node.id == nodeid:
            return True
    
    return False
    
  ''' HACK: when parsing original IEEE graph, the adjacency list is initially nodeids (rather than objects).  this is when this method is callled'''
  def neighListContainsNodeIdAsInt(self, nodeid):
        
    for neighId in self.neighbors_:
        if neighId == nodeid:
            return True
    
    return False

  def convert_to_mn_format(self):
      
    for neigh in self.getNeighborIds():
      self.edges.append((self.id,neigh))
     
  def __str__(self):  
    return"id=%s;adj=%s" % (self.id, self.getNeighborIds()) 
   
   
    

class Graph(object):

  def __init__(self):
    self.nodes = []
    self.edges = [] # tuples
        
  ''' return a node object matching the id, if it exists.  otherwise create and return an new Node object'''
  def getNode(self, id):
      
    for node in self.nodes:
        
        if (node.getId() == id):
            return node
        
    node = Node(id)
    self.nodes.append(node)
    return node
        
  ''' update the adjacency list for Node objects for n1 and n2'''    
  def updateNodeAdjList(self, id1, id2):
      
      
    #check if object already exists for n1 and n2
    n1 = self.getNode(id1)
    n2 = self.getNode(id2)
    
    # check not adding self-loop or duplciate neighbor
    if n1.neighListContainsNodeIdAsInt(id1) or n1.neighListContainsNodeIdAsInt(id2) or n2.neighListContainsNodeIdAsInt(id2) or n2.neighListContainsNodeIdAsInt(id1):
        return

    n1.addNeighbor(id2)
    n2.addNeighbor(id1)
      
  def getNodeWithDegree(self, degree, nodeList, connectNode1, connectNode2):
      
    candidateNodes = list()
    
    # find a node with degree not in neighList
    for node in self.nodes:
        
        if len(node.neighbors_) == degree and node.id != connectNode1.id and not connectNode1.neighListContainsNodeId(node.id)  and node.id != connectNode2.id and not connectNode2.neighListContainsNodeId(node.id):
            candidateNodes.append(node)
    
    if len(candidateNodes) == 0:
        return -1, False
    
    indx = random.randint(0, len(candidateNodes) - 1)
    
    return candidateNodes[indx], True
      
      
  '''  (1) given node v.  pick a random x \in adj(v). find a node, y, such that y \notin adj(x) and degree(y) + 1 = degree(x) 
       (2) remove (v,x) and add (v,y)
  '''
  def swapEdge(self, node, neighList):

    if len(neighList) == 0:
      return False
    
    # pick a random x \in adj(v)
    indx = random.randint(0, len(neighList) - 1)
    neigh = neighList[indx]
    neighList.remove(neigh)
    degree = len(neigh.neighbors_)
    
    # find a node, y, such that y \notin adj(x) and degree(y) + 1 = degree(x) 
    newNeigh, foundNode = self.getNodeWithDegree(degree - 1, neigh.neighbors_, node, neigh)
    
    if not foundNode:
      self.swapEdge(node, neighList)
    else:
      # remove (v,x) and add (v,y) -- v=node. x=neigh, y = newNeigh
      node.neighbors_.remove(neigh)
      neigh.neighbors_.remove(node)
      node.neighbors_.append(newNeigh)
      newNeigh.neighbors_.append(node)
      
     # print "swapped (%s,%s) for (%s,%s)" %(node.id,neigh.id,node.id,newNeigh.id)
  
      return True
  
  def swapEdges(self):
      
    origGraphNodes = copy.deepcopy(self.nodes)
    
    
    numEdges = self.getNumEdges()
    cnt = 0
    numCommonElements = self.compareAdjLists(origGraphNodes, self.nodes)
    
    while numCommonElements > 10:
        
      randNodeNum = random.randint(0, len(self.nodes) - 1)
      node = self.nodes[randNodeNum]
      
      neighListCopy = node.neighbors_[:]
      if self.swapEdge(node, neighListCopy):
        cnt += 1
        numCommonElements = self.compareAdjLists(origGraphNodes, self.nodes)
      
    self.checkGenGraph()
    
    self.convert_to_mn_format()
     
    return cnt
      
  def convert_to_mn_format(self):
     
    if len(self.edges) >0:
      for e in self.edges:
        del e
    for node in self.nodes:
      node.convert_to_mn_format()
      self.edges = self.edges + node.edges
  
  def getNumEdges(self):
     
    cnt = 0
    
    for node in self.nodes:
        cnt += len(node.neighbors_)
        
    cnt = cnt / 2
    
    return cnt
      
  ''' return the number of common neighbors in the adjacency list ''' 
  def compareAdjLists(self, origGraphNodes, newGraph):
   
    cnt = 0
    for indx in range(len(origGraphNodes)):
        
      orig = origGraphNodes[indx]
      new = newGraph[indx]
      
      for neigh in orig.neighbors_:
        if new.neighListContainsNodeId(neigh.id):
          cnt += 1 
        

    return cnt / 2
  
  ''' check (1) no self-loops (2) no duplicates in adjacency list '''
  def checkGenGraph(self):
      
    for node in self.nodes:
        
      # check for self loops
      for neigh in node.neighbors_:
        if node.id == neigh.id:
            print "[ERROR] node %s has a self-loop as a result of the graph generation.  Exiting program." % (node.id)
            os._exit(0)
          
        cnt = 0
        for neigh2 in node.neighbors_:
            
          if neigh.id == neigh2.id:
              cnt += 1
          
          if cnt > 1:
              print "[ERROR] node %s has duplicate neighbor nodes.  node %s appears > 1 time in adjacency list.  Exiting program." % (node.id, neigh.id)
              os._exit(0)
            
    #print "produced a valid graph"
  
  def printDegreeDistribution(self):
      
    nodeDegrees = list()
    #temporary print node degree disitrubtion
    for node in self.nodes:
        nodeDegrees.append(len(node.neighbors_))
        
    nodeDegrees.sort()
    
    prevVal = nodeDegrees[0]
    cnt = 1
    print "Degree\tCount"
    for i in range(0, len(nodeDegrees)):

        curr = nodeDegrees[i]
        if curr == prevVal:
            cnt += 1
        else:
            print "%s\t%s" % (prevVal, cnt)
            cnt = 1
        
        prevVal = curr
    #os._exit(0 )
      
  
  ''' convert neighbor adjanency list to list of objects (rather than node ids) '''
  def convertNeighListToObj(self):
    #self.printDegreeDistribution()
    
    for node in self.nodes:
        
        neighObj = []
        for neighId in node.neighbors_:
            
            neigh = self.getNode(neighId)
            neighObj.append(neigh)
            
        del node.neighbors_[:]
        node.neighbors_ = neighObj
                  

  
  def parseGraphFile(self, graphTxtFile):
   # nodes = []
        
    FLAG_TEXT1 = "BRANCH"
    FLAG_TEXT2 = "DATA"
    FLAG_TEXT3 = "FOLLOWS"
    graphTxtFileName = ""

    parseFlag = False
    for line in graphTxtFile:
        
        parsed = line.split(" ")
        
        if(parsed[0] == FLAG_TEXT1 and parsed[1] == FLAG_TEXT2 and parsed[2] == FLAG_TEXT3):
            parseFlag = True
            continue
        
        # the parsing assumes that the first two non-blank entries make up (u,v)
        n1 = -1
        n2 = -1
        if(parseFlag):
            
          for val in parsed:
          
            if(val != ''):
              if(n1 == -1):
                n1 = int(val)
                if(n1 == -999):
                    parseFlag = False #done parsing at this point
                    break
              else:
                n2 = int(val)
                self.updateNodeAdjList(n1, n2)
                break
    
    
    self.convertNeighListToObj()
    
    self.checkGenGraph()
      
 
  def __str__(self):
      
    self.nodes.sort(key=compareKey)
   # sorted(nodes,key= node.id)
   
    output = "--" * 40 + "\n"
    
    for node in self.nodes:
        
        output = output + node.__str__() + "\n"

    output = output + "--" * 40  
    
    return output 


class IeeeMininetTopo ( Topo ):
  def __init__(self):
    # super
    super(IeeeMininetTopo, self).__init__()

  def convert_to_mn_graph(self, g):
    """ 
    1) Create switches, hosts...attach 
    2) Add one host to each switch (h0->s0, h1->s1, etc.)
    3) Add edges between switches
    """
    # create switches and attach a host to the switch
    # one host per switch
    for n in g.nodes:
      n = n.id
      self.addSwitch('s%d' % n)
      self.addHost('h%d' % n)
      self.addLink("s%d" % n, "h%d" % n)
    
    # link switches acording to topology
    for (n1, n2) in g.edges:
      #n1 = n1 + 1
      #n2 = n2 + 1
      self.addLink("s%d" % n1, "s%d" % n2)



#def gen_mcast_groups(mn_graph,group_size,num_groups=1):
#  """ mn_graph is IeeeMininetTopo instance"""
#  n = mn_graph.node_info
#  
#  mcast_group_hosts = random.sample(mn_graph.node_info,num_groups)
#  
#  # pick a random element to be the root, make sure this root element has not been 
  
def write_mcast_groups_to_file(mcast_groups):
  """ mcast_groups format [ (root_id, [terminal_host_ids]), ... ]"""
  w = csv.writer(open("/home/mininet/appleseed/ext/topos/mcast-groups.csv", "w"))
  for group in mcast_groups:
    all_hosts = [group[0]] + group[1]
    w.writerow(all_hosts)
  
  
def gen_single_mcast_group(node_ids,root_ids,mcast_groups,group_size):
  group_created = False
  
  mcast_group_hosts = random.sample(node_ids,group_size)
  random.shuffle(mcast_group_hosts)

  for root_candidate in mcast_group_hosts:
    if root_candidate not in root_ids:
      root_ids.append(root_candidate)
      mcast_group_hosts.remove(root_candidate)
      mcast_groups.append((root_candidate,mcast_group_hosts))
      return True
  
  return group_created  

def gen_mcast_groups(non_mn_graph,num_groups=1):
  """ non_mn_graph is local Graph instance"""
  n = len(non_mn_graph.nodes)
  
  mcast_groups = [] #tuple(root_id, [terminal_host_ids])
  root_ids = [] # used to make sure that we only create one multicast group rooted at any node
  node_ids=[]
  
  for node in non_mn_graph.nodes:
    node_ids.append(node.id)
  
  
  curr_num_groups = 0 
  group_size = (n/3) + 1
  while curr_num_groups < num_groups:
    group_created = gen_single_mcast_group(node_ids,root_ids,mcast_groups,group_size)
    if group_created: curr_num_groups+=1

  return mcast_groups

def gen_graph_and_mcast_groups(graph_txt_file_name,num_groups=1):
  non_mn_graph = Graph()
  
  graph_txt_file = open(graph_txt_file_name)
  non_mn_graph.parseGraphFile(graph_txt_file)
  non_mn_graph.convert_to_mn_format() 
  numSwaps = non_mn_graph.swapEdges()
  
  mcast_groups = gen_mcast_groups(non_mn_graph, num_groups)
  
  write_mcast_groups_to_file(mcast_groups)
  
  #print graph.edges
  mn_graph = IeeeMininetTopo()
  mn_graph.convert_to_mn_graph(non_mn_graph)
  
  return mn_graph,mcast_groups
def gen_graph(graph_txt_file_name):
  non_mn_graph = Graph()
  
  graph_txt_file = open(graph_txt_file_name)
  non_mn_graph.parseGraphFile(graph_txt_file)
  non_mn_graph.convert_to_mn_format() 
  numSwaps = non_mn_graph.swapEdges()
  
  #print graph.edges
  mn_graph = IeeeMininetTopo()
  mn_graph.convert_to_mn_graph(non_mn_graph)
  
  
  return mn_graph
    

if __name__ == "__main__":
  graph_file = "ieee-buses/ieee14.txt"
  gen_graph(graph_file)
