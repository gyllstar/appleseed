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
	 
def plot_detect_time_vs_num_monitor(data_file,color_indx=0,sd_flag=False,):

	print "Generating PCount Detection Time vs Num Monitored Flows plot using data_file %s ..." %(data_file)
	data = np.genfromtxt(dtime_folder + data_file, delimiter=',', names=['w', 'mf', 'samples','mean_time','ci1_time','ci2_time','mean_loss','ci1_loss','ci2_loss']) 
	
	colors=['blue','green','red','magenta','cyan','yellow']
	#data = data[0]
	#print data['mf']
	num_monitors = data['mf']
	mean_total_times = data['mean_time']
	ci_lows = data['ci1_time']
	mean_proc_times=[]  
	cis = []
	
	window_size = int(data['w'][0])
	indx=0
	for t in mean_total_times:
		ci = t - ci_lows[indx]
		cis.append(ci)
		t = t - window_size -1 #
		mean_proc_times.append(t)
		indx+=1
	
	print len(num_monitors), len(mean_proc_times), len(cis)
	plt.errorbar(num_monitors, mean_proc_times, yerr=cis, linewidth=1.5, marker="o", color=colors[color_indx],label="empty")
	#plt.clf()
	
	type_str = "sd"	
	if sd_flag:	
		plt.title("Processing Time (Standard Deviation)")
		type_str = "sd"
	else:
		plt.title("Processing Time (90% Confidence Interval)")
		type_str = "ci"
	plt.xlabel("Number of Monitored Flows")
	plt.ylabel("Processing Time (seconds)")
	#plt.xlim(0,5)
	plt.legend(loc='upper left')
	#plt.show()
	
	fig_name = data_file.split("-")
	fig_name = figs_folder + 'pcount-dtime' + "-%s-" %(type_str) + fig_name[2] + "-" + fig_name[3].split(".")[0]	+ ".pdf"
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

plot_all_detect_time()
#plot_all_detect_time(sd_flag=True)
#plot_all_detect_time(sd_flag=False)
	
