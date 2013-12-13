'''
Created on Apr 7, 2011

@author: dpg
'''

zValueMap_={80:1.282,90:1.645,95:1.960,98:2.326,99:2.576,99.8:3.090,99.9:3.291}
    
def computeMean(array):
    """ compute and return the mean for the given array """ 
    total = 0
    numSamples=0
    for i in array:
        total+=float(i)
        numSamples+=1
        
    return total/float(numSamples)

def computeStandDev(array,mean):
    """ compute the standard deviation for the array with the given mean, use N-1 for unbiased sample """
    
    prob = 1.0/(len(array)-1)
          
    variance=0
    deviation=0
    for i in range(0,len(array)):
        
        if float(array[i])==-1:
            continue
        
        currVal = float(array[i])
        variance += float((currVal- mean)**2)
      
    variance = prob * variance
    deviation = variance ** 0.5        
    
    return deviation



def computeConfInterval(array,percent):
    """ compute the 'percent' confidence interval for the given array, return as a tuple"""
    
    zVal=zValueMap_.get(percent)
    
    # compute the mean
    mean = computeMean(array)

    # compute the standard deviation
    dev = computeStandDev(array, mean)
    
    
    n = len(array)
    #n = getArrayLength(array)
    
    dev = float(dev)
    n = float(n)
    n = n**0.5
    
    temp = dev/n
    temp = temp * zVal
    
    upper = mean + temp
    lower = mean - temp
    
    return lower,upper

def computeConfIntervalVal(array,percent):
    """ compute the 'percent' confidence interval +- value
    for the given array, return value"""
    
    zVal=zValueMap_.get(percent)
    
    # compute the mean
    mean = computeMean(array)
    
    # compute the standard deviation
    dev = computeStandDev(array, mean)
    
    
   # print mean,dev
    
    
    n = len(array)-1
    #n = getArrayLength(array)
    
    dev = float(dev)
    n = float(n)
    n = n**0.5
    
    temp = dev/n
    temp = temp * zVal
    
    return temp
