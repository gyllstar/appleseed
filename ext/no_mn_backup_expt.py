"""
DPG:  Run Backup Tree Experiment at the controller side (measurements are strictly based on the number of messages

"""

import appleseed,multicast,utils
from pox.core import core
from ext.mininet import local_graph_generator
import os,sys
import shutil,glob,time,datetime

#graph_files = {118:"ext/mininet/ieee-buses/ieee118.txt",300:"ext/mininet/ieee-buses/ieee300.txt"}

#graph_files = {30:"ext/mininet/ieee-buses/ieee30.txt",57:"ext/mininet/ieee-buses/ieee57.txt",
#               118:"ext/mininet/ieee-buses/ieee118.txt",300:"ext/mininet/ieee-buses/ieee300.txt"}

graph_files = {14:"ext/mininet/ieee-buses/ieee14.txt",30:"ext/mininet/ieee-buses/ieee30.txt",57:"ext/mininet/ieee-buses/ieee57.txt",
              118:"ext/mininet/ieee-buses/ieee118.txt",300:"ext/mininet/ieee-buses/ieee300.txt"}

#alg_modes = [multicast.Mode.MERGER,multicast.Mode.BASELINE]
alg_modes = [multicast.Mode.MERGER]

IS_REACTIVE_EXPT=True
COMPUTE_BACKUP_TREE_ONLY=False

max_num_groups = -1
max_num_graphs = -1
num_graph_reuses = -1  #how many different mcast groups are generated for a single graph
num_group_increment=-1
group_runs_quota = 50 #total simulation runs will be two times this value
#group_runs_quota = 15

def init_globals(graph_num):
  global max_num_groups
  global max_num_graphs
  global num_graph_reuses
  global num_group_increment
  #max_num_groups = graph_num/3+1
  max_num_groups = graph_num/2
  if graph_num == 14:
    num_group_increment = 1
  elif graph_num == 30:
    num_group_increment = 2
  elif graph_num == 57:
    num_group_increment = 3
  elif graph_num == 118:
    num_group_increment = 4
  elif graph_num == 300:
    num_group_increment = 10

#  max_num_graphs = 30
#  num_graph_reuses = graph_num 
  max_num_graphs = 50
  num_graph_reuses = 5 
  
  # up to n/2 multicast groups, each group has n/3 terminals

def init(num_switches,num_groups,alg_mode):
  
  utils.read_mcast_group_file= False
  controller = appleseed.fault_tolerant_controller()
  if IS_REACTIVE_EXPT:
    controller.backup_tree_mode = multicast.BackupMode.REACTIVE
  else:
    controller.backup_tree_mode = multicast.BackupMode.PROACTIVE
    
  controller.algorithm_mode = alg_mode
  #controller.algorithm_mode = multicast.Mode.BASELINE
  
  multicast.backup_expt_num_switches = num_switches
  multicast.backup_expt_num_groups = num_groups
  
  max_switch_num = int(2 * num_switches)
  list_of_switches = []
  for id in range(num_switches+1,max_switch_num+1):
    list_of_switches.append(id)
    
  core.openflow_discovery._dps = list_of_switches
  
  return controller

def archive_existing_data_files():
  
  return

  ts = time.time()
  st = datetime.datetime.fromtimestamp(ts).strftime('%m-%d--%H:%M')
  
  base_dir = "ext/results/current/"
  new_dir = 'ext/results/msgs/tstamp-dirs/msgs-tstamp-%s' %(st)
  os.mkdir(new_dir)
  file_names = glob.glob("ext/results/current/backup-*.csv")
  
  for f in file_names:
    shutil.move(f, new_dir)  

  new_dir = 'ext/results/preinstall/tstamp-dirs/preinstall-tstamp-%s' %(st)
  os.mkdir(new_dir)
  file_names = glob.glob("ext/results/current/preinstall-*.csv")
  
  for f in file_names:
    shutil.move(f, new_dir)    
  
#  for f in file_names:
#    base_name = f.split(".")[0]
#    base_name = base_name.split("/")[-1]
#    #print base_name
#    #new_name = base_name + "-h%s" %(hour) + "m%s"%(min) + ".csv"
#    new_name = base_name + "-tstamp-%s" %(st) + ".csv"
#    full_name = base_dir + 'archive-back-msgs/' + new_name
#    print 'archiving %s to %s' %(f,full_name)
#    #shutil.copy(f, full_name)
#    shutil.move(f, full_name)


def run_local_expts():
  
  archive_existing_data_files()
  
  for graph_num in sorted(graph_files.keys()):
    init_globals(graph_num)
    for mode in alg_modes:
      if IS_REACTIVE_EXPT:  
        local_single_graph_reactive_expt(graph_num, mode)
      else:
        local_single_graph_proactive_expt(graph_num,mode)
      #os._exit(0)
      
def local_single_graph_proactive_expt(graph_num,alg_mode):
  
  graph_file = graph_files[graph_num]
  num_groups =1
  total_group_runs=0
  
  print '------------------------------------------------------------'
  print 'Proactive Expt on IEEE Bus %s, Mode=%s' %(graph_num,alg_mode)
  print '  - expts on mcast_groups = 1 to %s' %(max_num_groups)
  print '  - generate %s graphs and generate %s groups per graph' %(max_num_graphs,num_graph_reuses)
  print '------------------------------------------------------------'
    
  while num_groups <= max_num_groups:
    
    controller = init(graph_num,num_groups,alg_mode)
    num_generated_graphs=0
    total_group_runs=0
    
    print '\t number of mcast groups = %s (iterate up to %s, incrementing by %s)' %(num_groups,max_num_groups,num_group_increment)
    
    while total_group_runs<group_runs_quota:
      #if num_generated_graphs == int(max_num_graphs/2): print '\t\t num generated graphs = %s' %(num_generated_graphs)
      adjacency = local_graph_generator.gen_graph_as_adjacency(graph_file)
      controller.adjacency = adjacency
      num_graph_uses=0
      print '\t\t tatal_group_runs = %s' %(total_group_runs)
      while num_graph_uses <= num_graph_reuses:
        #successful_run = multicast.bak_tree_expt_single_group(controller,skip_installation=True) 
        pt_comp_success,bt_comp_success = multicast.bak_tree_proactive_expt_single_group(controller,skip_installation=True,compute_lower_bound_only=COMPUTE_BACKUP_TREE_ONLY)  # run measurements over each link in the multicast group
        if pt_comp_success and bt_comp_success:
          total_group_runs+=1

        num_graph_uses+=1
      
      multicast.clear_all(controller)  
      num_generated_graphs+=1
      
#      if num_generated_graphs>=max_num_graphs:
#        break
      
    num_groups+=num_group_increment      
      
def local_single_graph_reactive_expt(graph_num,alg_mode):
  
  graph_file = graph_files[graph_num]
  num_groups =1
  total_group_runs=0
  
  print '------------------------------------------------------------'
  print 'Reactive Expt on IEEE Bus %s, Mode=%s' %(graph_num,alg_mode)
  print '  - expts on mcast_groups = 1 to %s' %(max_num_groups)
  print '  - generate %s graphs and generate %s groups per graph' %(max_num_graphs,num_graph_reuses)
  print '------------------------------------------------------------'
  
  while num_groups <= max_num_groups:
    controller = init(graph_num,num_groups,alg_mode)
    num_generated_graphs=0
    total_group_runs=0
    
    print '\t number of mcast groups = %s (iterate up to %s, incrementing by %s)' %(num_groups,max_num_groups,num_group_increment)
    
    while total_group_runs<group_runs_quota:
      #if num_generated_graphs == int(max_num_graphs/2): print '\t\t num generated graphs = %s' %(num_generated_graphs)
      adjacency = local_graph_generator.gen_graph_as_adjacency(graph_file)
      controller.adjacency = adjacency
      num_graph_uses=0
      print '\t\t tatal_group_runs = %s' %(total_group_runs)
      while num_graph_uses <= num_graph_reuses:
        #successful_run = multicast.bak_tree_expt_single_group(controller,skip_installation=True) 
        pt_comp_success,bt_comp_success = multicast.bak_tree_expt_single_group(controller,skip_installation=True,compute_lower_bound_only=COMPUTE_BACKUP_TREE_ONLY)  # run measurements over each link in the multicast group
        if pt_comp_success and bt_comp_success:
          total_group_runs+=1

        num_graph_uses+=1
      
      multicast.clear_all(controller)  
      num_generated_graphs+=1
      
#      if num_generated_graphs>=max_num_graphs:
#        break
      
    num_groups+=num_group_increment

def debug_local_single_graph_expt(graph_num,alg_mode):
  
  graph_num=30
  graph_file = graph_files[graph_num]
  num_groups = 3
  init_globals(graph_num)
  
  while num_groups <= max_num_groups:
    controller = init(graph_num,num_groups,alg_mode)
    adjacency = local_graph_generator.gen_graph_as_adjacency(graph_file)
    controller.adjacency = adjacency
    
    successful_run = multicast.bak_tree_expt_single_group(controller,skip_installation=True) 
    print 'debug_local_single_graph_expt() exiting after single run, successful run=%s' %(successful_run)
    os._exit(0)
    
      
#      if num_generated_graphs>=max_num_graphs:
#        break
      
    num_groups+=num_group_increment  
def launch ():
  if 'openflow_discovery' not in core.components:
    import pox.openflow.discovery as discovery
    discovery.LINK_TIMEOUT = 1000
    core.registerNew(discovery.Discovery)
    
  core.registerNew(appleseed.fault_tolerant_controller)
  
  #debug_local_single_graph_expt(30,multicast.Mode.MERGER)
  run_local_expts()