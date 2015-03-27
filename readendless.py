#!/usr/bin/env python
#-*- coding: utf-8 -*-
import numpy
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties

def getslot():
    fslot = open('/home/momo/digital_withonly_yuyue/reservation_slot.txt','r')
    true_slot = []
    for readline in fslot:
        true_slot.append(int(readline))
    fslot.close()
    return true_slot
def gettime():
    true_time = []
    ftime = open('/home/momo/digital_withonly_yuyue/reservation_time.txt','r')
    for readline in ftime:
        try:
            ele = float(readline)
        except (ValueError,NameError),e:
            print e
	if ele > 0:
            true_time.append(ele)	    
    ftime.close()
    return true_time
    
def mymean(numlist):
    return sum(numlist)/len(numlist)


    

