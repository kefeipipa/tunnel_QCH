#!/usr/bin/env python
import os
import re
import time
import numpy
import matplotlib.pyplot as plt

def mean_com(numlist):
    _sum = numlist.sum()
    return _sum/len(numlist)
def Var_com(numlist,mean,have_mean = True):
    if not have_mean:
        _mean = mean_com(numlist)
    else:
        _mean = mean
    return (numlist*numlist).sum()/len(numlist) - _mean**2

for i in range(20):
    #print 'after sleep'
    print 'ping for %d times' %(i+1)
    output = os.popen('/bin/ping 192.168.200.2 -c 10')
    for line in output:
	print line,
    time.sleep(3)

f1 = open('/home/momo/digital_withonly_yuyue/reservation_time.txt','r')
re_time = []
i = 0
for readline in f1:
    try:
        ele = float(readline)
    except (ValueError,NameError),e:
        print e
        raise ValueError
    if 0 == i%5:
        re_time.append([])
    re_time[i/5].append(ele)
    i += 1
    
f1.close()
f2 = open('/home/momo/digital_withonly_yuyue/reservation_slot.txt','r')
re_slot = []
i = 0
for readline in f2:
    try:
        ele = float(readline)
    except (ValueError,NameError),e:
        print e
        raise ValueError
    if 0 == i%5:
        re_slot.append([])
    re_slot[i/5].append(ele)
    i += 1

true_slot = []
for readline in f2:
    try:
        ele = float(readline)
    except (ValueError,NameError),e:
        print e
        raise ValueError
    true_slot.append(ele)

plt.figure(3)
xlist = range(len(true_slot))
plt.plot(xlist,true_slot)


f2.close()
f3 = open('/home/momo/digital_withonly_yuyue/result_timeslot.txt','w')
meantime = []
vartime = []
meanslot = []
varslot = []
for i in range(len(re_time)):
    re_time_ele = map(lambda x: float(x), re_time[i])
    retime = numpy.array(re_time_ele)
    meantime.append(mean_com(retime))
    vartime.append(Var_com(retime,meantime[i]))

    re_slot_ele = map(lambda x: float(x), re_slot[i])
    reslot = numpy.array(re_slot_ele)
    meanslot.append(mean_com(reslot))
    varslot.append(Var_com(reslot,meanslot[i]))

    print meantime[i],vartime[i],meanslot[i],varslot[i]

    f3.write("%.4f\t%.4f\t%d\t%.4f\n" %(meantime[i],vartime[i],meanslot[i],varslot[i]))

f3.close()
plt.figure(4)
xlist = range(len(re_time))
plt.plot(xlist,meantime)    

f4 = open('/home/momo/digital_withonly_yuyue/Qlearn.txt','r')
plt.figure(1)
ymatrix = [[0] for i in range(10)]
xlist = range(10)
ylist = 10*[0]
plt.plot(xlist,ylist)
#i = 0
for readline in f4:
#    print readline
    Qlist = readline.split(',')
    for j in range(len(Qlist)):
	ymatrix[j].append(Qlist[j])

    ylist = Qlist
#    i += 1
    plt.plot(xlist,ylist)
    
Qlen = len(ymatrix[0])
xlist = range(Qlen)
plt.figure(2)
for i in range(len(ymatrix)):
    plt.plot(xlist,ymatrix[i])

f4.close()
plt.show()


