#!/usr/bin/env python
#-*- coding: utf-8 -*-
import readendless
import myonlyping
#import mycom

myonlyping.pingtimes(80)
slot = readendless.getslot()
time = readendless.gettime()
argslot = float(sum(slot))/len(slot)
argtime = sum(time)/len(time)
print 'arg of slot is %.4f\n arg of time is %.4f' %(argslot,argtime)
#mycom.quit_pro("tunnel")
