#!/usr/bin/env python
import os
import re
import time

def pingtimes(num):
    pingend = 0
    packet_loss = [0,]
    
    for i in range(num):
	if 3 == pingend:
	    break
        print 'ping for %d times' %(i+1)
        output = os.popen('/bin/ping 192.168.200.2 -c 10')
	for line in output:
	    print line,
	    loss = re.findall(r'\d*%',line)
	    if len(loss) != 0:
		print loss
		loss_str = loss[0][:-1]
		packet_loss.append(int(loss_str))

		if 100 == packet_loss[i] and 100 == packet[i-1]:
		    pingend += 1
                else:
		    pingend = 0
		   
	time.sleep(3)
        print 'after sleep'
    arg_loss = sum(packet_loss[1:])/len(packet_loss[1:])
    print 'ping for %d times ,and average of packet loss is %.4f' %(i , arg_loss)
    return arg_loss
