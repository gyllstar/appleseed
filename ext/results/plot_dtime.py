import numpy as np
import matplotlib.pyplot as plt
import os
#from argparse import ArgumentParser
#parser = ArgumentParser(description="plot_loss_rate PCount Results")
#parser.add_argument("--file", dest="data_file",type=str,help="data file to used to generate plot_loss_rate",default='pcount-results-l10-u5.csv ')
#args = parser.parse_args()

print "here \n"

def compute_standard_deviation(error,n):
    
    zval=1.645
    n = n**0.5
    
    tmp = float(error) * n
    tmp = float(tmp)/zval
    
    return tmp
   
def plot_detect_time_vs_num_monitor(data_file,sd_flag=False):
	#elf.window_size,self.num_monitored_flows,num_runs,detect_time_mean,detect_time_conf_interval[0],detect_time_conf_interval[1],loss_ratio_mean,loss_ratio_conf_interval[0],loss_ratio_conf_interval[1]
	data = np.genfromtxt(dtime_folder + data_file, delimiter=',', names=['w', 'mf', 'samples','mean_time','ci1_time','ci2_time','mean_loss','ci1_loss','ci2_loss']) 
	
	max_mf=0
	for row in data:
		mf = int(row[1])
		if mf > max_mf:
			max_mf = mf
	
	colors=['blue','green','red','magenta','cyan','yellow']
	indx=-1
	
	plt.clf()
	print "Generating PCount Detection Time vs Num Monitored Flows plot using data_file %s ..." %(data_file)
	max_window=4.5
	for i in range(1,max_mf+1):
		x = list()
		y = list()
		y_error = list()
		for row in data:
			if int(row[1]) == i and float(row[0]) <= max_window:
				x.append(row[0])
				mean_time = float(row[3]) - float(row[0]) - 1  #subtract window size and propogation delay
				y.append(mean_time)
				error = float(row[3]) - float(row[4])
				if sd_flag:
					num_samples = int(row[2])
					sd = compute_standard_deviation(error,num_samples)
					#print "f=%s,w=%s,sd=%s" %(i,row[0],sd)
					y_error.append(sd)
				else:
					y_error.append(error)
				
		if len(x) == 0:
			#print "%s no results for f=%s, skipping" %(data_file,i)
			continue
		indx+=1
		
			
		#plt.scatter(x,y, marker='o',color=colors[indx],label="f=%i" %(i))
		#plt.plot_loss(x,y, marker='o',linestyle='None',color=colors[indx])#,label="f=%i" %(i))
		#plt.errorbar(x, y, yerr=y_error, fmt=None,capsize=8,linewidth=2, color=colors[indx],label="f=%i" %(i))
		plt.errorbar(x, y, yerr=y_error, linewidth=1.5, marker="o", color=colors[indx],label="f=%i" %(i))
		
	type_str = "sd"	
	if sd_flag:	
		plt.title("Processing Time (Standard Deviation)")
		type_str = "sd"
	else:
		plt.title("Processing Time (90% Confidence Interval)")
		type_str = "ci"
	plt.xlabel("Windows Size (seconds)")
	plt.ylabel("Processing Time (seconds)")
	plt.xlim(0,5)
	plt.legend(loc='upper left')
	#plt.show()
	
	fig_name = data_file.split("-")
	fig_name = figs_folder + 'pcount-time' + "-%s-" %(type_str) + fig_name[2] + "-" + fig_name[3].split(".")[0]  + ".pdf"
	plt.savefig(fig_name,bbox_inches='tight')	
	#os._exit(0)
			
def plot_all_loss_rate(sd_flag):
	for data_file in data_files:
		l_str = data_file.split("-")[2]
		ratio_str = l_str[1:]
		base_loss_ratio = float(ratio_str)/100
		plot_loss_rate(data_file,base_loss_ratio,sd_flag)
		
def plot_all_detect_time(sd_flag=False):
	for data_file in data_files:
		plot_detect_time_vs_num_monitor(data_file, sd_flag)

dtime_folder = 'dtime/'
figs_folder = 'dtime/figs/'
data_files = ['pcount-dtimes-w2-f300.csv'] 


plot_all_detect_time(sd_flag=True)
plot_all_detect_time(sd_flag=False)
	

