#!/usr/bin/env python
#Brett and Carrie
#project 04

'''
Basic IPv4 router (static routing) in Python, stage 1.
'''

import sys
import os
import os.path
sys.path.append(os.path.join(os.environ['HOME'],'pox'))
sys.path.append(os.path.join(os.getcwd(),'pox'))
import pox.lib.packet as pktlib
from pox.lib.packet import ethernet,ETHER_BROADCAST,IP_ANY
from pox.lib.packet import arp
from pox.lib.addresses import EthAddr,IPAddr, netmask_to_cidr
from srpy_common import log_info, log_debug, log_warn, SrpyShutdown, SrpyNoPackets, debugger
from math import floor
from time import time

#to do: build static forwarding table, forward packets appropriately, make ARP requests
#for other hosts to get their MAC address (so basically the flip side of part 1 of this
#project)

class Router(object):
	def __init__(self, net):
		self.net = net
		#part 2: building forwarding table
		#forwarding_table = []
		fwd = []
		my_intfs = []
		for intf in self.net.interfaces(): #getting immediate neighbor info
			my_intfs.append((intf.ipaddr, IPAddr('255.255.255.255'), intf.ipaddr, intf.name))
			neighborIP = IPAddr(intf.netmask.toUnsigned()&intf.ipaddr.toUnsigned())
			fwd.append((neighborIP,intf.netmask, IPAddr('0.0.0.0'), intf.name))
		f = open('forwarding_table.txt', 'r') #getting not immediate neighbors from file
		for line in f:
			info = line.split(' ')
			interface = info[3]
			interface = interface[:len(interface)-1]
			print interface
			fwd = fwd + [(IPAddr(info[0]), IPAddr(info[1]), IPAddr(info[2]), interface)]
			#mask = self.net.interface_by_name(interface).netmask
			#fwd = fwd + [(IPAddr(info[2]), mask, IPAddr(info[2]), interface)]
		f.close()

		self.fwd = fwd
		self.my_intfs = my_intfs
		self.forwarding_table = my_intfs + fwd 
		print self.forwarding_table
		self.queue = [] #a list of tuples for storing ARP requested packets
		self.macaddrs = {} #cache of {IP:addr} mappings to cut down ARP requests
	def router_main(self):    
		while True:
			self.check_queue_times()
			try:
				dev,ts,pkt = self.net.recv_packet(timeout=1.0)
			except SrpyNoPackets:
				# log_debug("Timeout waiting for packets")
				continue
			except SrpyShutdown:
				return      
			#part 2: forwarding packets and making ARP_request to obtain MAC address
			if pkt.type == pkt.IP_TYPE: #!!!!if just a packet to be forwarded.  Not sure about this...
				pkt = pkt.payload
				destIP = pkt.dstip
				matches = []
				cidrlen = 0
				for i in self.forwarding_table:
					netmask = i[1]
					length = netmask_to_cidr(netmask)
					forwardIP = i[0]
					nexthop = i[2] if i[2] != IPAddr('0.0.0.0') else destIP
					ifname = i[3]
					print 'FIP: '+str(forwardIP)+', destIP: '+str(destIP)+', mask: '+str(netmask)+', hop: '+str(nexthop)
					print (forwardIP.toUnsigned() & netmask.toUnsigned())
					print (destIP.toUnsigned() & netmask.toUnsigned())
					if((forwardIP.toUnsigned()) == (destIP.toUnsigned() & netmask.toUnsigned())): #got rid of forwardIP & netmask.toUnsigned()
						matches.append((length, destIP, nexthop, ifname))  #length, net_prefix, next hop, eth#
				
				if len(matches)!=0: #if we have at least one match 
					#finding MAC address -> SENDING ARP_REQUEST
					low = 0
					match = ()
					for i in matches:
						if(i[0]>low):
							match = i
							low = i[0]
					if match[2] in [str(x[2]) for x in self.my_intfs]: #packet for us, drop it on the floor
						continue;
					if match[2] not in self.macaddrs:
						self.queue.append([match, floor(time()), pkt, 0])
						self.send_arp_request(match)
					else:
					    self.send_packet(match, pkt)
						
			#part 1: responding to ARP request
			elif pkt.type == pkt.ARP_TYPE:
				arp = pkt.payload
				if (arp.opcode == pktlib.arp.REPLY): #if it is a reply to own request
					for elem in self.queue:
						nexthop = elem[0][2]
						ippkt = elem[2]
						if(arp.protosrc == nexthop): #we found our guy    ------------changed nexthop to pktdst
							self.macaddrs[nexthop] = arp.hwsrc
							self.queue.remove(elem)
							self.send_packet(elem[0],ippkt)
							
				else:
					for intf in self.net.interfaces(): #if request from someone else/ need reply
						if (intf.ipaddr==arp_request.protodst):
						    arp = pktlib.arp()
						    arp.protodst = arp_request.protosrc
						    arp.protosrc = inf.ipaddr
						    arp.hwsrc = intf.ethaddr
						    arp.hwdst = arp_request.hwsrc
						    arp.opcode = pktlib.arp.REPLY
						    ether = pktlib.ethernet()
						    ether.type = ether.ARP_TYPE
						    ether.src = intf.ethaddr
						    ether.dst = arp_request.hwsrc
						    ether.set_payload(arp)
						    self.net.send_packet(dev, ether)
						    #self.net.send_packet(dev, arp_reply)
						    break

	#tup = (prefixlength, destIP, nexthop, ifname)
	def send_arp_request(self, tup):
		preflen = tup[0]
		destIP = tup[1]
		nexthop = tup[2]
		ifname = tup[3]
		intf = self.net.interface_by_name(ifname)
	
		arp_pkt = pktlib.arp()
		arp_pkt.protosrc = intf.ipaddr #the ip address of the interface we're sending the request out
		arp_pkt.protodst = nexthop 
		arp_pkt.hwsrc = intf.ethaddr
		arp_pkt.hwdst = ETHER_BROADCAST
		arp_pkt.opcode = pktlib.arp.REQUEST

		ether = pktlib.ethernet()
		ether.type = ether.ARP_TYPE
		ether.src = intf.ethaddr
		ether.dst = ETHER_BROADCAST
		ether.payload = arp_pkt
		self.net.send_packet(ifname, ether)
	#isn't this so pretty?  Functions are our FRIENDS :)



	#tup is a FT match tuple, like above
	#tup = (prefixlength, destIP, nexthop, ifname)
	def send_packet(self, tup, pkt):
		preflen = tup[0]
		destIP = tup[1]
		nexthop = tup[2]
		ifname = tup[3]
		intf = self.net.interface_by_name(ifname)
		
		pkt.ttl = pkt.ttl-1
		ether = pktlib.ethernet()
		ether.type = ether.IP_TYPE
		ether.src = intf.ethaddr
		ether.dst = self.macaddrs[nexthop]
		ether.payload = pkt
		self.net.send_packet(ifname, ether)

	def check_queue_times(self):
		timenow = floor(time())
		print self.queue
		for elem in self.queue:
			time_added = elem[1]
			arpcount = elem[3]
			index = self.queue.index(elem)
			if arpcount==5:
				self.queue.remove(elem)
				continue
				#timeout :(
			if timenow-time_added>=1: # if one or more seconds has elapsed since last sending an ARP request
				self.send_arp_request(elem[0])
				self.queue[index][1] = timenow
				self.queue[index][3] = arpcount+1

def srpy_main(net):
	'''
	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
	
