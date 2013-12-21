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
   
def plot_loss_rate(data_file,base_loss_ratio,sd_flag=False):
	#elf.window_size,self.num_monitored_flows,num_runs,detect_time_mean,detect_time_conf_interval[0],detect_time_conf_interval[1],loss_ratio_mean,loss_ratio_conf_interval[0],loss_ratio_conf_interval[1]
	data = np.genfromtxt(rate_folder + data_file, delimiter=',',names=['w', 'mf', 'samples','mean_time','ci1_time','ci2_time','mean_loss','ci1_loss','ci2_loss']) 
	
	max_mf=0
	for row in data:
		mf = int(row[1])
		if mf > max_mf:
			max_mf = mf
	#'orange'                 : '#ffa500',     # 255, 165,   0
	colors=['blue','green','red','magenta','cyan','yellow']
  #colors=['blue','green','#ffa500','red','magenta','cyan','yellow']
	#alphas=['0.2','0.3','0.4','0.5','0.6','0.7'] 
	alphas=['0.3','0.4','0.5','0.6','0.7','0.8'] 
	#alphas=['0.1','0.3','0.5','0.7','0.9','1'] 
	indx=-1
	
	plt.clf()
	print "Generating PCount Loss Rate plot using data_file %s ..." %(data_file)
	max_window=7 
  #max_window=7
	for i in range(1,max_mf+1):
		x = list()
		y = list()
		y_error = list()
		sd_low = list()
		sd_high= list()
		first_call=True
		for row in data:
			if int(row[1]) == i and float(row[0]) <= max_window:
				x.append(row[0])
				y.append(row[6])
				error = float(row[6]) - float(row[7])
				if sd_flag:
					num_samples = int(row[2])
					sd = compute_standard_deviation(error,num_samples)
					#print "f=%s,w=%s,y=%s,sd1=%s" %(i,row[0],row[6],(row[6]-sd))
					y_error.append(sd)
					sd_high.append(row[6] + sd)
					sd_low.append(row[6] - sd)
					y_error.append(sd)
				else:
					y_error.append(error)
				
		if len(x) == 0:
			print "\t %s no results for f=%s, skipping" %(data_file,i)
			continue
		indx+=1
		
		if i == 1:
			base_y = []
			full_x = [0]
			for val in x:
				full_x.append(val)
			full_x.append(max_window+.5)
			for val in full_x:
				base_y.append(base_loss_ratio)
			plt.plot(full_x,base_y,color='black',linewidth=1.5,label="ground truth")
			
		if sd_flag and False:
			plt.plot(x,y, marker='o',linestyle='-',color=colors[indx],label="f=%i mean" %(i))
			plt.plot(x,sd_high, marker='x',linestyle='--',color=colors[indx],label="f=%i mean+sd" %(i))
			plt.plot(x,sd_low, marker='x',linestyle='--',color=colors[indx],label="f=%i mean-sd" %(i))
		if sd_flag:
			plt.plot(x,y, marker='o',linestyle='-',color=colors[indx],label="f=%i mean" %(i))
			plt.fill_between(x,sd_low,sd_high,alpha=alphas[indx],edgecolor=colors[indx],color=colors[indx])
			#plt.plot(x,sd_high, marker='x',linestyle='--',color=colors[indx],label="f=%i mean+sd" %(i))
			#plt.plot(x,sd_low, marker='x',linestyle='--',color=colors[indx],label="f=%i mean-sd" %(i))
		if not sd_flag:
			plt.scatter(x,y, marker='o',color=colors[indx],label="f=%i" %(i))
			plt.errorbar(x, y, yerr=y_error, fmt=None,capsize=8,linewidth=2, color=colors[indx],label="f=%i" %(i))
		#plt.errorbar(x, y, yerr=y_error, linewidth=1.5, capsize=8, marker="o", color=colors[indx],label="f=%i" %(i))
		
	type_str = "sd"	
	if sd_flag:	
		plt.title("Estimated Loss Ratios (Standard Deviation)")
		type_str = "sd-alt"
	else:
		plt.title("Estimated Loss Ratios (90% Confidence Interval)")
		type_str = "ci"
	plt.xlabel("Windows Size (in seconds)")
	plt.ylabel("Estimated Loss Ratio (seconds)")
	plt.xlim(0.5,7)
	plt.legend(loc='lower right')
	#plt.show()
	
	#fig_name = data_file.split(".")
	#fig_name = "figs/" + fig_name[0] + "-%s" %(type_str) + ".pdf"
	fig_name = data_file.split("-")
	fig_name = figs_folder + 'pcount-loss' + "-%s-" %(type_str) + fig_name[2] + "-" + fig_name[3].split(".")[0]  + ".pdf"
	plt.savefig(fig_name,bbox_inches='tight')	
   

def plot_detection_time(data_file,sd_flag=False):
	#elf.window_size,self.num_monitored_flows,num_runs,detect_time_mean,detect_time_conf_interval[0],detect_time_conf_interval[1],loss_ratio_mean,loss_ratio_conf_interval[0],loss_ratio_conf_interval[1]
	data = np.genfromtxt(rate_folder + data_file, delimiter=',', names=['w', 'mf', 'samples','mean_time','ci1_time','ci2_time','mean_loss','ci1_loss','ci2_loss']) 
	
	max_mf=0
	for row in data:
		mf = int(row[1])
		if mf > max_mf:
			max_mf = mf
	
	colors=['blue','green','red','magenta','cyan','yellow']
	indx=-1
	
	plt.clf()
	print "Generating PCount Detection Time plot using data_file %s ..." %(data_file)
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
		l_str = data_file.split("-")[2]
		plot_detection_time(data_file, sd_flag)

rate_folder = 'loss/'
figs_folder = 'loss/figs/'
#data_files = ['pcount-loss-l10-u5.csv','pcount-loss-l5-u5.csv','pcount-loss-l1-u5.csv']
data_files = ['pcount-loss-l5-u10.csv']
plot_loss_flag = True
plot_detect_time_flag = False
if plot_loss_flag:
	plot_all_loss_rate(sd_flag=True)
	#plot_all_loss_rate(sd_flag=False)

if plot_detect_time_flag:
	#plot_all_detect_time(sd_flag=True)
	plot_all_detect_time(sd_flag=False)
	

