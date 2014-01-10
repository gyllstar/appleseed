import numpy as np
import matplotlib.pyplot as plt
import scipy as sp
import scipy.stats
import os, glob
#from argparse import ArgumentParser
#parser = ArgumentParser(description="plot_loss_rate PCount Results")
#parser.add_argument("--file", dest="data_file",type=str,help="data file to used to generate plot_loss_rate",default='pcount-results-l10-u5.csv ')
#args = parser.parse_args()

def compute_standard_deviation(error,n):
		
		zval=1.645
		n = n**0.5
		
		tmp = float(error) * n
		tmp = float(tmp)/zval
		
		return tmp

def mean_confidence_interval2(data, confidence=0.95):
	a = 1.0*np.array(data)
	n = len(a)
	m, se = np.mean(a), scipy.stats.sem(a)
	h = se * sp.stats.t._ppf((1+confidence)/2., n-1)
	return m, m-h, m+h	

def mean_confidence_interval(data, confidence=0.95):
	a = 1.0*np.array(data)
	n = len(a)
	m, se = np.mean(a), scipy.stats.sem(a)
	h = se * sp.stats.t._ppf((1+confidence)/2., n-1)
	return m,h

def compute_ptree_indices(basic_data,merger_data):
	all_ptrees=basic_data['ptrees']
	indx=0
	new_ptree_num=True
	prev_ptree_num=int(all_ptrees[0])
	ptree_indices=[]
	for data in range(0,len(all_ptrees)):
		curr_ptree_num = int(all_ptrees[indx])
		if curr_ptree_num != prev_ptree_num:
			ptree_indices.append(indx-1)
		prev_ptree_num = curr_ptree_num
		indx+=1
	ptree_indices.append(len(all_ptrees)-1)
	
	return ptree_indices
	
def plot_msgs(graph_num,basic_file,merger_file):
													#num_primary_trees,num_affected_trees,total_pt_nodes,total_bt_nodes,total_overlap_nodes,total_msgs,total_unique_edges,total_garbag
	basic_data = np.genfromtxt(basic_file, delimiter=',',names=['ptrees', 'num_affected','pt_nodes', 'bt_nodes','overlap','msgs','unique_edges', 'garbage' ])
	#merger_data = np.genfromtxt(merger_file, delimiter=',', names=['ptrees', 'num_affected','pt_nodes', 'bt_nodes','overlap','msgs','unique_edges', 'garbage' ])
	merger_data = np.genfromtxt(merger_file, delimiter=',', names=['ptrees', 'num_affected','pt_nodes', 'bt_nodes','overlap','msgs','unique_edges', 'garbage', 'num_edges','num_pt_edges','avg_pt_link_load','num_pt_reuses']) 
																																																#total_num_graph_edges,total_num_pt_edges,avg_ptree_link_load,num_pt_reuse_rules
	
	all_ptrees=basic_data['ptrees']
	all_affected_trees=basic_data['num_affected']
	all_b_msgs=basic_data['msgs']
	all_b_garbage=basic_data['garbage']
	all_m_msgs=merger_data['msgs']
	all_m_garbage=merger_data['garbage']
	all_pt_nodes = basic_data['pt_nodes']
	all_bt_nodes = basic_data['bt_nodes']

	ptree_indices=compute_ptree_indices(basic_data, merger_data)
	i=0
	b_msgs=[]
	m_msgs=[]
	b_garbage=[]
	m_garbage=[]
	b_msgs_error=[]
	m_msgs_error=[]
	b_garbage_error=[]
	m_garbage_error=[]
	num_affected_trees=[]
	num_affected_trees_error=[]
	num_pt_nodes=[]
	num_pt_nodes_error=[]
	num_bt_nodes=[]
	num_bt_nodes_error=[]
	num_ptrees=[]
	for j in ptree_indices:
		num_ptrees.append(all_ptrees[i])
		
		b_msg_tmp = all_b_msgs[i:j]
		m_msg_tmp = all_m_msgs[i:j]
		b_garbage_tmp = all_b_garbage[i:j]
		m_garbage_tmp = all_m_garbage[i:j]
		affected_trees_tmp = all_affected_trees[i:j]
		pt_nodes_tmp = all_pt_nodes[i:j]
		bt_nodes_tmp = all_bt_nodes[i:j]
		
		b_mn,b_err = mean_confidence_interval(b_msg_tmp)
		b_msgs.append(b_mn)
		b_msgs_error.append(b_err)
		m_mn,m_err = mean_confidence_interval(m_msg_tmp)
		m_msgs.append(m_mn)
		m_msgs_error.append(m_err)

		b_mn,b_err = mean_confidence_interval(b_garbage_tmp)
		b_garbage.append(b_mn)
		b_garbage_error.append(b_err)
		m_mn,m_err = mean_confidence_interval(m_garbage_tmp)
		m_garbage.append(m_mn)
		m_garbage_error.append(m_err)		
		
		mn,err = mean_confidence_interval(affected_trees_tmp)
		num_affected_trees.append(mn)
		num_affected_trees_error.append(err)
	
		mn,err = mean_confidence_interval(pt_nodes_tmp)
		#mn=mn/float(num_ptrees[-1])
		#err=err/float(num_ptrees[-1])
		mn=mn/float(num_ptrees[-1])
		err=err/float(num_ptrees[-1])
		num_pt_nodes.append(mn)
		num_pt_nodes_error.append(err)	
		
		mn,err = mean_confidence_interval(bt_nodes_tmp)
		mn=mn/float(num_affected_trees[-1])
		err=err/float(num_affected_trees[-1])
		num_bt_nodes.append(mn)
		num_bt_nodes_error.append(err)	
		
		i=j+1
		
	plt.clf()
	print '\n\t experiment stats'
	print '\t ---------------------------------------------------------------------------------------------------------------'
	print '\t\t debugging: data file ptrees indices: %s' %(ptree_indices)
	print '\t\t number of ptrees=%s' %(num_ptrees)
	print '\t\t number of basic msgs=%s'%(b_msgs)
	print '\t\t number of merger msgs=%s' %(m_msgs)
	avg_gap=[]
	percent_pt_node_reuse=[]
	for cnt in range(0,len(b_msgs)):
		gap = b_msgs[cnt] - m_msgs[cnt]
		avg_gap.append(gap)
		
		msgs_per_bt = b_msgs[cnt]/float(num_affected_trees[cnt])
		avg_pt_reuses = num_bt_nodes[cnt] - msgs_per_bt
		percent_pt_node_reuse.append(avg_pt_reuses/float(num_bt_nodes[cnt]))
	
	print '\t\t basic - merger = %s' %(avg_gap)
	print '\t\t number of affected trees = %s' %(num_affected_trees)
	print '\t\t mean # nodes in PT tree = %s' %(num_pt_nodes)
	print '\t\t mean # nodes in BT tree = %s' %(num_bt_nodes)
	print '\t\t mean percent of PT node reuse = %s, + individual results=%s' %(np.mean(percent_pt_node_reuse),percent_pt_node_reuse)
	print '\t ---------------------------------------------------------------------------------------------------------------\n'
	
	x_upper_bound = int(graph_num)/2+1
	plt.errorbar(num_ptrees, b_msgs, yerr=b_msgs_error, linewidth=1, marker="o", color='black',label="basic")
	plt.errorbar(num_ptrees, m_msgs, yerr=m_msgs_error, linewidth=1, marker="o", color='blue',label="merger")
	plt.xlabel("Number of Primary Trees",fontsize=14)
	plt.ylabel("Number of Control Messages",fontsize=14)
	plt.xlim(0,x_upper_bound)
	plt.legend(loc='upper left')
	#plt.show()
	
	fig_name = figs_folder + 'msgs-ieee%s' %(graph_num)	+ ".pdf"
	print "\t writing results to %s" %(fig_name)
	plt.savefig(fig_name,bbox_inches='tight')	
	
	plt.clf()
	plt.errorbar(num_ptrees, b_garbage, yerr=b_garbage_error, linewidth=1, marker="o", color='black',label="basic")
	plt.errorbar(num_ptrees, m_garbage, yerr=m_garbage_error, linewidth=1, marker="o", color='blue',label="merger")
	plt.xlabel("Number of Primary Trees",fontsize=14)
	plt.ylabel("Number of Stale Flow Entries",fontsize=14)
	plt.xlim(0,x_upper_bound)
	plt.legend(loc='upper left')
	#plt.show()
	
	fig_name = figs_folder + 'garbage-ieee%s' %(graph_num)	+ ".pdf"
	print "\t writing results to %s" %(fig_name)
	plt.savefig(fig_name,bbox_inches='tight')	

	plt.clf()
	plt.errorbar(num_ptrees, num_affected_trees, yerr=num_affected_trees_error, linewidth=1, marker="o", color='red')
	plt.xlabel("Number of Primary Trees",fontsize=14)
	plt.ylabel("Number of Affected Trees",fontsize=14)
	plt.legend(loc='upper left')
	#plt.show()
	
	fig_name = figs_folder + 'affected-trees-ieee%s' %(graph_num)	+ ".pdf"
	print "\t writing results to %s" %(fig_name)
	plt.savefig(fig_name,bbox_inches='tight')	
	
	plt.clf()
	plt.scatter(all_ptrees,all_b_msgs,marker='x',color='black',s=40,label="basic")
	plt.scatter(all_ptrees,all_b_msgs,marker='o',color='blue',s=10,label="merger")
	plt.xlabel("Number of Primary Trees",fontsize=14)
	plt.ylabel("Number of Control Messages",fontsize=14)
	plt.legend(loc='upper left')
	fig_name = figs_folder + 'scatter-msgs-ieee%s' %(graph_num)	+ ".pdf"
	print "\t writing results to %s" %(fig_name)
	plt.savefig(fig_name,bbox_inches='tight')	
	#os._exit(0)
 
def get_graph_num(file_name):
	# input: 'backup-msg-merger-ieee30 
 	substr = file_name.split("-")[-1]
 	num_as_str = substr.lstrip('ieee')
 	return int(num_as_str)
 
def plot_graph_num(graph_num,file_names):
	
	basic_file=None
	merger_file = None
	for f in file_names:
		base_name = f.split(".")[0]
		base_name = base_name.split("/")[-1]
		file_num = get_graph_num(base_name)
		
		if file_num == graph_num:
			if 'basic' in f:
				basic_file = f
			elif 'merger' in f:
				merger_file = f
	if basic_file == None or merger_file == None:
		print '\n skipping IEEE %s because missing data files' %(graph_num)
		return
	
	print '\n\n plotting IEEE %s with files %s %s' %(graph_num,merger_file,basic_file)
	plot_msgs(graph_num,basic_file,merger_file)  #maybe # of affected trees
msgs_folder = 'msgs/'
figs_folder = 'msgs/figs/'
base_file_pattern = 'backup-msg-*'
ieee_graph_nums = [14,30,57,118,300]	

file_names = glob.glob(msgs_folder + base_file_pattern +  '.csv')

for graph_num in ieee_graph_nums:
	plot_graph_num(graph_num, file_names)