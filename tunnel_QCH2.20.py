
# Copyright 2005,2006,2009 Free Software Foundation, Inc.
# 
# This file is part of GNU Radio
# 
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 


# /////////////////////////////////////////////////////////////////////////////
#
#    This code sets up up a virtual ethernet interface (typically gr0),
#    and relays packets between the interface and the GNU Radio PHY+MAC
#
#    What this means in plain language, is that if you've got a couple
#    of USRPs on different machines, and if you run this code on those
#    machines, you can talk between them using normal TCP/IP networking.
#
# /////////////////////////////////////////////////////////////////////////////


from gnuradio import gr, gru, modulation_utils
from gnuradio import usrp
from gnuradio import eng_notation
from gnuradio.eng_option import eng_option
from optparse import OptionParser

import random
import time
import struct
import sys
import os
import platform
import socket
import thread
import pdb
import threading

# from current dir
import usrp_transmit_path
import usrp_receive_path
from mac_utils import *
from framing3 import *


#print os.getpid()
#raw_input('Attach and press enter')


# /////////////////////////////////////////////////////////////////////////////
#
#   Use the Universal TUN/TAP device driver to move packets to/from kernel
#
#   See /usr/src/linux/Documentation/networking/tuntap.txt
#
# /////////////////////////////////////////////////////////////////////////////

# Linux specific...
# TUNSETIFF ifr flags from <linux/tun_if.h>

IFF_TUN		= 0x0001   # tunnel IP packets
IFF_TAP		= 0x0002   # tunnel ethernet frames
IFF_NO_PI	= 0x1000   # don't pass extra packet info
IFF_ONE_QUEUE	= 0x2000   # beats me ;)

#frame type define
TYPE_MAG = 0x00
TYPE_CTL = 0x01
TYPE_DAT = 0x02

SUBTYPE_RTS = 0x0B
SUBTYPE_CTS = 0x0C
SUBTYPE_DATA = 0x00
SUBTYPE_ACK = 0x0D


#res = 1   #ZLM: res is reservation for short ,and 1 represent we need a reservation for transsmition
mac_addr_local = "\0\0\0\0\0\11"



def open_tun_interface(type,tun_device_filename):
    from fcntl import ioctl
    
   # mode = IFF_TAP | IFF_NO_PI
   # TUNSETIFF = 0x400454ca

   # tun = os.open(tun_device_filename, os.O_RDWR)
   # ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "gr%d", mode))
   # ifname = ifs[:16].strip("\x00")
   # return (tun, ifname)
    mode = IFF_TUN
    ifname = 'tun0'

    if type == 'tap':
       mode = IFF_TAP | IFF_NO_PI
       ifname = 'tapxx'

    TUNSETIFF = 0x400454ca
    TAPGIFNAME = 0x40206500
    tun = os.open(tun_device_filename, os.O_RDWR)
    if platform.system() == 'Linux':
        ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "gr%d", mode))
        ifname = ifs[:16].strip("\x00")
    if platform.system() == 'NetBSD':
        ifs = ioctl(tun, TAPGIFNAME, struct.pack("16sH", "gr%d", mode))
        ifname = ifs[:16].strip("\x00")
    return (tun, ifname)
 

# /////////////////////////////////////////////////////////////////////////////
#                             the flow graph
# /////////////////////////////////////////////////////////////////////////////

class my_graph(gr.top_block):

    def __init__(self, mod_class, demod_class,
                 rx_callback, options):

        gr.top_block.__init__(self)
        self.txpath = usrp_transmit_path.usrp_transmit_path(mod_class, options)
        self.rxpath = usrp_receive_path.usrp_receive_path(demod_class, rx_callback, options)
        self.connect(self.txpath)
        self.connect(self.rxpath)

    def send_pkt(self, payload='', eof=False):
        return self.txpath.send_pkt(payload, eof)

    def carrier_sensed(self):
        """
        Return True if the receive path thinks there's carrier
        """
        return self.rxpath.carrier_sensed()


# /////////////////////////////////////////////////////////////////////////////
#                           Carrier Sense MAC
# /////////////////////////////////////////////////////////////////////////////

class cs_mac(object):
    """
    Prototype carrier sense MAC

    Reads packets from the TUN/TAP interface, and sends them to the PHY.
    Receives packets from the PHY via phy_rx_callback, and sends them
    into the TUN/TAP interface.

    Of course, we're not restricted to getting packets via TUN/TAP, this
    is just an example.
    """
   
    def __init__(self, tun_fd, mac_addr, pkttype, bssid, cache, DC, QCH, verbose=False):
        self.tun_fd = tun_fd       # file descriptor for TUN/TAP interface
        self.verbose = verbose
        self.fg = None             # flow graph (access to PHY)
        self.sender = None
        self.mac_addr = mac_addr
        self.pkttype = pkttype
        self.bssid = bssid
        self.cache = cache
        self.receiver = packet_receiver(mac_addr, bssid, \
                        self.mac_rcv_callback, verbose)

        #self.receive_lock = False   #receive_lock stay in receiver

        self.send_state = 0
        #send_state  0:idle, 1:send J2DC, 2:send RTS, 3:send data
        self.receive_state = 0
        #receive_state  0:idle,receive J2DC, 2:receive RTS

        #self.CC = True             #state in the CC
        self.payload = False
        #self.CC_freq = CC
        self.DC_freq = DC
        self.QCH = QCH
        self.DCnumber = 0
        self.QCH_num = 8  # (QCH_num + 1)%9 is 0


        self.rev_timeout = 0 #??
        self.send_count = 0
        self.org_time = time.time()  #system begin time,can`t change
        #self.beg_time = time.time()
        #self.end_time = time.time()
	self.last_send = self.org_time
	self.last_receive = self.org_time
	self.first_data = 0
	self.first_ack = 1


        self.jumplast_time = 0
        self.reservation = 1
        self.peer_addr = "\0\0\0\0\0\0"
        self.data_channel = -1
        self.time_slot = 0.05


	self.mycon = threading.Condition()
        self.wait_ack = threading.Condition()
        self.srlock = threading.Lock()
        self.sendstate_lock = threading.Lock()


        self.mutilcast = True
        self.reservation_time = self.org_time
        self.reservation_slot = 0
        self.rts_slot =0

        self.reser_time_file = None
        self.reser_slot_file = None
        self.Qfile = None
        self.Qlearn = [0,0,0,0,0,0,0,0,0,0] #fix me
        self.lasta = 5
	self.alpha = 0.3
        self.slotcell = (self.time_slot - 0.002 - 0.005)/10

    def set_flow_graph(self, fg):
        self.fg = fg
        self.sender = packet_sender(self.pkttype, self.mac_addr, self.bssid, \
                               self.fg.send_pkt, self.cache, self.verbose)


    def channeljump(self, channel):
        """
        channel jump function
        """
        self.fg.txpath.u.set_center_freq(channel)
        self.fg.rxpath.u.set_center_freq(channel)

    def usual_channel_jump(self):
	self.jumplast_time = time.time()
        while 1:
	    last_time = time.time()
	    self.QCH_num += 1
	    self.DCnumber = self.QCH[(self.QCH_num)%9]
    
            if random.randint(1,10) < 8:
                maxQ = max(self.Qlearn)
#               minQindex = filter(lambda x: self.Qlearn[x] == minQ, range(10))
#                self.lasta = random.choice(minQindex)
                self.lasta = self.Qlearn.index(max(self.Qlearn))
            else:
                self.lasta = random.choice(range(10))

    
            """
            mytime = 0.002 + self.jumplast_time - time.time()
            #print "first protect time 0.002 ",mytime
	    if mytime > 0:
                time.sleep(mytime) #protect time 

            mytime = self.lasta * self.slotcell + 0.002 + self.jumplast_time - time.time()
            #print "first lasta is %d" %self.lasta ,mytime
            if mytime > 0:
	        time.sleep(self.lasta * self.slotcell + 0.002 + self.jumplast_time - time.time())

	    if not self.mutilcast:   #ZLM Fixme   
	        if self.mycon.acquire():
	 	    self.mycon.notify()
		    self.mycon.release()

            mytime = self.time_slot + self.jumplast_time - 0.005 - time.time()
            #print "seconed lasta is %d" %self.lasta ,mytime
	    if mytime >0:
	        time.sleep( self.time_slot + self.jumplast_time - 0.005 - time.time() )

            mytime = self.time_slot + self.jumplast_time - time.time()
            #print "last protect time 0.005 ",mytime
            if mytime > 0:
	        time.sleep(self.time_slot + self.jumplast_time - time.time() ) #save time


            """

            time.sleep(0.002) #protect time 
            time.sleep( self.lasta * self.slotcell)
            if not self.mutilcast:   #ZLM Fixme   
                if self.mycon.acquire():
                    self.mycon.notify()
                    self.mycon.release()
            time.sleep( (9 - self.lasta) * self.slotcell )
            time.sleep(0.005) #save time

	      
	    if (time.time() - self.last_send > 2) and (time.time() - self.last_receive > 2):  #
		if not self.reservation:
		    
		    print "send or receive end, return to channel jump"
	            self.reservation = True 

	    if self.reservation:
		self.channeljump(self.DC_freq[self.DCnumber])
		print "jump to channel %d" %self.DCnumber
                print "Jump Time is %.4f" %(time.time()-self.org_time)		
		self.jumplast_time = time.time()
                self.data_channel = self.DCnumber



    def sleep_after_jump(self):
	time_diff = time.time()- self.jumplast_time
        if time_diff < 0.002:
            time.sleep(0.002-time_diff)
		
    def CSMA(self):
        # CSMA/CA function
        delay = 0.001
        times = 0
        while self.fg.carrier_sensed():
            sys.stderr.write('B')
            time.sleep(random.uniform(2**times*delay,2**(times+1)*delay))
#           if delay < 0.010:
#               delay = delay * 2       # exponential back-off until 0.010s
            times += 1
            if times >= 10:             #10 times
                return
    
    def mac_rcv_callback(self, packet):  #ZLM copyed from chenlong ,this used to received packet from channel and passed to phy_rx_callback to analyse
        """ 
        Invoked by packet_receiver.receive when it has a complete
        packet to pass up to the OS.
        """
        if self.verbose:
            print "Pkt Rx: pkt len = %4d" % (len(packet))

        os.write(self.tun_fd, packet)
        print "pkt success"


    def phy_rx_callback(self, ok, payload):
        """
        Invoked by thread associated with PHY to pass received packet up.

        @param ok: bool indicating whether payload CRC was OK
        @param payload: contents of the packet (string)
        """
	first_cts = 1
	#first_data = 0
	Q_r = -1
        if self.verbose:
            print "Rx: ok = %r  len(payload) = %4d" % (ok, len(payload))
            rec_diff_time = time.time() - self.jumplast_time
        if ok: #and (rec_diff_time > 0.002): #
            (pkttype,pktsubtype,pktpayload) = self.receiver.receive(payload)
            print "pkttype:%X   pktsubtype:%X" %(pkttype,pktsubtype)
            self.last_receive = time.time()
            #self.CSMA()
            #self.srlock.acquire()
            if pkttype == TYPE_CTL and pktsubtype == SUBTYPE_RTS:
                print"received RTS frame,time is %.4f ,and the channel is %d" %(time.time()-self.org_time, self.data_channel)
                #self.receive_lock = True
                self.reservation = 0
                #after jump we must sleep 0.002
                #self.sleep_after_jump()
                #time.sleep(0.001)
		self.CSMA()
                self.sender.send_CTS(self.peer_addr)
                print"After send CTS frame,time is %.4f ,and the channel is %d" %(time.time()-self.org_time, self.data_channel)
		self.last_send = time.time()
                self.receive_state = 2
                self.send_state = 0
		#self.srlock.release()
                #self.timer = False
                #self.t.exit() 
                


            elif pkttype == TYPE_CTL and pktsubtype == SUBTYPE_CTS: #and self.send_state == 2:
	      
	        self.sendstate_lock.acquire()
                print"received CTS frame,time is %.4f ,and the channel is %d" %(time.time()-self.org_time,self.data_channel)
                self.receive_state = 2
		if 1 == self.reservation:
		    first_cts = 1
                    self.reservation = 0
                    self.send_state = 3
                    print "reservation success"
		    print "reservation_slot is %d, channel is %d" %(self.rts_slot, self.data_channel)
		else:
		    first_cts = 0

		self.sendstate_lock.release()
                #pdb.set_trace()
		#self.srlock.release()
                if first_cts: #
                    self.reservation_time = time.time() - self.org_time
                    self.reservation_slot = self.rts_slot
		    """
                    if self.reservation_slot > 9:
                        Q_r = 1
                    else:
                        Q_r = -1
                    self.Qlearn[self.lasta] = (1-self.alpha)*self.Qlearn[self.lasta] + self.alpha*Q_r
                    Qstr = str(self.Qlearn)
                    Qstr = Qstr.replace('[','')
                    Qstr = Qstr.replace(']','')
                    Qstr = Qstr.replace(' ','')

                    self.Qfile.write(Qstr + '\n')
                    self.Qfile.flush()

                    self.reser_time_file.write("%.4f\n" %(self.reservation_time-self.rts_time))
                    self.reser_slot_file.write("%d\n" %(self.reservation_slot) )

                    self.reser_time_file.flush()
                    self.reser_slot_file.flush()
                    
                    print "After write into file"
                    """

            elif pkttype == TYPE_DAT and pktsubtype == SUBTYPE_DATA: #and self.receive_state == 2:
                print"received DATA frame,time is %.4f ,and the channel is %d" %(time.time()-self.org_time, self.data_channel)
                #after jump we must sleep 0.002
                self.sleep_after_jump()
                self.reservation = 0
		#self.srlock.release()
                #print "reservation success"
                self.CSMA()
                self.sender.send_ACK(self.peer_addr)
                print"send ACK frame,time is %.4f ,and the channel is %d" %(time.time()-self.org_time, self.data_channel)
		self.last_send = time.time()
                self.receive_state = 0
                self.mac_rcv_callback(pktpayload)  #write to hos  #write to hostt
                #self.receive_lock = False
                print "data receiver is finished,time is %.4f" %(time.time()-self.org_time)
                #self.timer = False
                #self.t.exit()

            elif pkttype == TYPE_CTL and pktsubtype == SUBTYPE_ACK: #and self.send_state == 3:
	        self.srlock.acquire()
                print"received ACK frame,DATA sending success ,time is %.4f, and the channel is %d" %(time.time()-self.org_time, self.data_channel)
                self.payload = False
                self.send_state = 0
		self.srlock.release()
                self.wait_ack.acquire()
                self.wait_ack.notify()
                self.wait_ack.release()
                if self.first_data:
                    print "###############################first data send success############################################"
                    if self.reservation_slot > 9:
                        Q_r = -1
                    else:
                        Q_r = 1
                    self.Qlearn[self.lasta] = (1-self.alpha)*self.Qlearn[self.lasta] + self.alpha*Q_r
                    Qstr = str(self.Qlearn)
                    Qstr = Qstr.replace('[','')
                    Qstr = Qstr.replace(']','')
                    Qstr = Qstr.replace(' ','')

                    self.Qfile.write(Qstr + '\n')
                    self.Qfile.flush()

                    self.reser_time_file.write("%.4f\n" %(self.reservation_time-self.rts_time))
                    self.reser_slot_file.write("%d\n" %(self.reservation_slot) )

                    self.reser_time_file.flush()
                    self.reser_slot_file.flush()
                    print "After write into file"

                    self.first_data = 0
                    self.first_ack = 1
                    
		    

                #self.receive_lock = False
                #self.timer = False
                #self.t.exit()
                #print "data sending success,time is %.4f" %(time.time()-self.org_time)

                
        #if ok:    
        #    os.write(self.tun_fd, payload)



    def main_loop(self,f1,f2,f3,f4):
        """
        Main loop for MAC.
        Only returns if we get an error reading from TUN.

        FIXME: may want to check for EINTR and EAGAIN and reissue read
        """
        self.reser_time_file = f1
        self.reser_slot_file = f2
        self.Qfile = f3
	self.re_channel = f4

        min_delay = 0.001               # seconds
# thread.start_new_thread(self.usual_channel_jump,())
	t = threading.Thread(target = self.usual_channel_jump)
        t.start()
        time_count = 0
        east_send = 0
        data_count = 0
	rts_count = 0 #its seems useless to count how many rts we send
        while 1:

            if not self.payload:
                self.payload = os.read(self.tun_fd, 10*1024)
                #print "data read from system,payload = %5d"%len(self.payload)
                (mac_add,) = struct.unpack('B',self.payload[0:1])
                if (mac_add & 0x1) == 0x1 and mac_add != 0xFF:
                    self.payload = False
                    print"mutilcast discard"
                    #res = 1 #when start we need the reservation
                    continue
            #pdb.set_trace()
            self.mutilcast = False  #first the notify need not to run


            if not self.payload:
                self.fg.send_pkt(eof=True)
                print "self.payload is error"
                break   # error
                        
            if not self.reservation:    #do not need reservation, send DATA
                print "do not need reservation"
		self.srlock.acquire()
                #after jump we must sleep 0.002
                #self.sleep_after_jump()
		if not self.payload:
                    print "got ACK, and last DATA received"
		    self.srlock.release()
                    continue
                self.CSMA()
         	print "Before send DATA,time is %.4f" %(time.time()-self.org_time)
                self.sender.send_DATA(self.payload)
                print "After send DATA,time is %.4f ,and the channel is %d" %(time.time()-self.org_time , self.data_channel)
		self.last_send = time.time()
                print "the send state is %d" %self.send_state
                if 3 == self.send_state:
                    self.send_state = 4                                  
		    self.first_data = 1
                    print "------------------------------set first data flag-----------------------------------"

		data_count = 1
		self.srlock.release()

                #time.sleep(0.05)
		self.wait_ack.acquire()
                self.wait_ack.wait(0.1)
                self.wait_ack.release()

            else:    #need reservation,send RTS
	        #self.srlock.acquire()
                print "need reservation"       
                #time_count = 0
                #print "self.send_state is %d" %self.send_state
		#if self.send_state == 0:
                #after jump we must sleep 0.002
                #self.sleep_after_jump()
                if self.mycon.acquire():
 		    self.mycon.wait()

		    self.CSMA()
                    self.rts_time = time.time() - self.org_time
                    print "Before send RTS,time is %.4f" %(time.time()-self.org_time)
		    self.sender.send_RTS(self.payload)
                    print "After send RTS,time is %.4f ,and the channel is %d" %(time.time()-self.org_time , self.data_channel)
                    self.last_send = time.time()
                    self.mycon.release()
                    
                    if self.sendstate_lock.acquire(False): #only acquire lock can change the send_state ,if not then cannot change it
                        self.send_state = 2
			self.sendstate_lock.release()

                    if self.first_ack:
                        self.rts_slot = 1
		        rts_count = 1
                        self.first_ack = 0
                    else:
                        print "==================================first data send failed====================================="
                        self.rts_slot += 9
		        rts_count += 9

                    print "RTS count is %d" %rts_count
		#self.srlock.release()
                    #continue
                #time.sleep(self.time_slot)
                #print "not get mycon"
                    #self.send_state = 2
                    #continue
                    
            while self.payload:# and self.send_state == 3:
                #self.sleep_after_jump()
                #if not self.payload:
                #    print "got ACK, and last DATA received"
                #    break
	        #self.srlock.acquire()
                if data_count > 5:
                    self.reservation = 1 #need reservation
                    print "DATA resend upto %d times, need reservation agian" %data_count
                    data_count = 0
                    break

                if rts_count > 30:
                    #rts_count = 0 
                    self.payload = False
                    self.reservation = 1
                    self.first_ack = 1
                    print 'Dst note not online and quit  tttttttttttttttttttttttttttttttttttttttttttttttttttttttt'
		    break


                if 2 == self.send_state:
		    if self.mycon.acquire():
			self.mycon.wait()
         		#print "Before repeat send RTS,time is %.4f , and the channel is %d" %(time.time()-self.org_time, self.data_channel)
			if 2 != self.send_state: #After wait we should check
			    self.mycon.release()
			    break #not use continue because we must make first data different

			#if not self.payload:
			#    print "got ACK, and last DATA received"
			#    self.mycon.release()
			#    break 
                        self.CSMA()
                        print "Before repeat send RTS,time is %.4f" %(time.time()-self.org_time)
			self.sender.send_RTS(self.payload)
                        print "After repeat send RTS,time is %.4f ,and the channel is %d" %(time.time()-self.org_time , self.data_channel)
                        rts_count += 1
			self.rts_slot += 1
			self.last_send = time.time()
			#print "the channel is %d" %self.data_channel
			self.mycon.release()
                        print "RTS count is %d" %rts_count
               
                elif 4 == self.send_state:
                    #print "In repeat send DATA"
                    #if not self.payload:
                    #    print 'got ACK and last DATA received'
                    #    break
	            self.srlock.acquire()
                    if not self.payload:
                        print "got ACK, and last DATA received"
			self.srlock.release()
                        continue
                    self.CSMA()
         	    print "Before repeat send DATA,time is %.4f" %(time.time()-self.org_time)
                    self.sender.send_DATA(self.payload)
                    print "After repeat send DATA,time is %.4f ,and the channel is %d" %(time.time()-self.org_time , self.data_channel)
		    self.last_send = time.time()
                    self.srlock.release()
		    #print "the channel is %d" %self.data_channel
		    data_count += 1
		    #time.sleep(0.05)
                    self.wait_ack.acquire()
                    self.wait_ack.wait(0.1)
                    self.wait_ack.release()

                else: #send_state == 0
		    #self.srlock.release()
		    break

		#self.srlock.release()

# /////////////////////////////////////////////////////////////////////////////
#                                   main
# /////////////////////////////////////////////////////////////////////////////

def main():

    mods = modulation_utils.type_1_mods()
    demods = modulation_utils.type_1_demods()

    parser = OptionParser (option_class=eng_option, conflict_handler="resolve")
    expert_grp = parser.add_option_group("Expert")
    expert_grp.add_option("", "--rx-freq", type="eng_float", default=None,
                          help="set Rx frequency to FREQ [default=%default]", metavar="FREQ")
    expert_grp.add_option("", "--tx-freq", type="eng_float", default=None,
                          help="set transmit frequency to FREQ [default=%default]", metavar="FREQ")
    parser.add_option("-m", "--modulation", type="choice", choices=mods.keys(),
                      default='gmsk',
                      help="Select modulation from: %s [default=%%default]"
                            % (', '.join(mods.keys()),))
    parser.add_option("-b","--bssid", default="00:00:00:00:00:00",
                    help="set bssid for network in the form xx:xx:xx:xx:xx:xx") #ZLM copy form chenlong



    parser.add_option("-v","--verbose", action="store_true", default=False)
    expert_grp.add_option("-c", "--carrier-threshold", type="eng_float", default=30,
                          help="set carrier detect threshold (dB) [default=%default]")
    parser.add_option("","--tun", action="store_true", default=False,
                    help="use tun device instead of tap to pass packets.") #ZLM copy form chenlong
    expert_grp.add_option("","--tun-device-filename", default="/dev/net/tun",
                          help="path to tun device file [default=%default]")

    usrp_transmit_path.add_options(parser, expert_grp)
    usrp_receive_path.add_options(parser, expert_grp)

    for mod in mods.values():
        mod.add_options(expert_grp)

    for demod in demods.values():
        demod.add_options(expert_grp)

    (options, args) = parser.parse_args ()
    if len(args) != 0:
        parser.print_help(sys.stderr)
        sys.exit(1)

    bssid = validate_mac_addr(options.bssid)
    if bssid == 0:
        print "Invalid BSSID ", options.bssid
        parser.print_help()
        sys.exit(1)

    mod_kwargs = {
        'bt' : options.bt,
        }

    pkttype = 'eth'
    tuntype = 'tap'
    mcache = None
    if options.tun:
        pkttype = 'ip'
        tuntype = 'tun'
    # open the TUN/TAP interface
    (tun_fd, tun_ifname) = open_tun_interface(tuntype, options.tun_device_filename)
    tun_mac = get_mac_for_interface(tun_ifname)
    mac_addr = validate_mac_addr(tun_mac)
    if mac_addr == 0:
        print "Invalid MAC address ", tun_mac, " for interface ", tun_ifname
        print "exiting."
        sys.exit(1)
    if options.verbose:
        print "Using MAC address ", tun_mac, " for interface ", tun_ifname


    # Attempt to enable realtime scheduling
    r = gr.enable_realtime_scheduling()
    if r == gr.RT_OK:
        realtime = True
    else:
        realtime = False
        print "Note: failed to enable realtime scheduling"


    # If the user hasn't set the fusb_* parameters on the command line,
    # pick some values that will reduce latency.

    if options.fusb_block_size == 0 and options.fusb_nblocks == 0:
        if realtime:                        # be more aggressive
            options.fusb_block_size = gr.prefs().get_long('fusb', 'rt_block_size', 1024)
            options.fusb_nblocks    = gr.prefs().get_long('fusb', 'rt_nblocks', 16)
        else:
            options.fusb_block_size = gr.prefs().get_long('fusb', 'block_size', 4096)
            options.fusb_nblocks    = gr.prefs().get_long('fusb', 'nblocks', 16)
    
    #print "fusb_block_size =", options.fusb_block_size
    #print "fusb_nblocks    =", options.fusb_nblocks

    # instantiate the MACi
    DC = [2.810e9, 2.812e9,2.814e9]
    QCH = [1,0,2,0,2,1,2,1,0]
#    QCH = [1,1,1,1,1,1,1,1,1]
    mac = cs_mac(tun_fd, mac_addr, pkttype, bssid, mcache, DC, QCH, verbose=True)

    # build the graph (PHY)
    fg = my_graph(mods[options.modulation],demods[options.modulation],
                  mac.phy_rx_callback, options)


    mac.set_flow_graph(fg)    # give the MAC a handle for the PHY

    if fg.txpath.bitrate() != fg.rxpath.bitrate():
        print "WARNING: Transmit bitrate = %sb/sec, Receive bitrate = %sb/sec" % (
            eng_notation.num_to_str(fg.txpath.bitrate()),
            eng_notation.num_to_str(fg.rxpath.bitrate()))
             
    print "modulation:     %s"   % (options.modulation,)
    print "freq:           %s"      % (eng_notation.num_to_str(options.tx_freq))
    print "bitrate:        %sb/sec" % (eng_notation.num_to_str(fg.txpath.bitrate()),)
    print "samples/symbol: %3d" % (fg.txpath.samples_per_symbol(),)
    #print "interp:         %3d" % (tb.txpath.interp(),)
    #print "decim:          %3d" % (tb.rxpath.decim(),)

    fg.rxpath.set_carrier_threshold(options.carrier_threshold)
    print "Carrier sense threshold:", options.carrier_threshold, "dB"
    
    print
    print "Allocated virtual ethernet interface: %s" % (tun_ifname,)
    print "You must now use ifconfig to set its IP address. E.g.,"
    print
    print "  $ sudo ifconfig %s 192.168.200.1" % (tun_ifname,)
    print
    print "Be sure to use a different address in the same subnet for each machine."
    print


    fg.start()    # Start executing the flow graph (runs in separate threads)
    f1 = open('reservation_time.txt','w')
    f2 = open('reservation_slot.txt','w')    
    f3 = open('Qlearn.txt','w')
    f4 = open('channel.txt','w')
#    mac.main_loop(f1,f2,f3)  
    mac.main_loop(f1,f2,f3,f4)    # don't expect this to return...
    
    f1.close()
    f2.close()
    f3.close()    

    fg.stop()     # but if it does, tell flow graph to stop.
    fg.wait()     # wait for it to finish
                

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
