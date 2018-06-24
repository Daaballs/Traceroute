# Davis Dinh
# Traceroute Tool

from scapy.all import *
import socket
import sys
import time
import argparse

def construct(dstIP, ttl):
	packet_h = IP()
	packet_h.dst = dstIP
	packet_h.ttl = ttl

	packet = packet_h/ICMP()

	return packet

def send_packet(packet, hops):
	complete = 0
	noResolve = 0

	rtt = time.time()	
	reply = sr1(packet, timeout = 3, verbose=0)
	rtt = (time.time() - rtt)*1000

	try:
		reverse_dns = socket.gethostbyaddr(reply.src)
	except socket.error:
		noResolve = 1
		pass
	except AttributeError:
		pass

	if reply is None:
		print("%d	 *" %hops)

	elif reply.type == 0:
		if noResolve == 0:
			print("%d	%d ms		%s [%s]\n" %(hops, rtt, reply.src, reverse_dns[0]))
		else:
			print("%d	%d ms		%s\n" %(hops, rtt, reply.src))

		print("Trace complete.")
		complete = 1

	else:
		if noResolve == 0:
			print("%d	%d ms		%s [%s]" %(hops, rtt, reply.src, reverse_dns[0]))
		else:
			print("%d	%d ms		%s" %(hops, rtt, reply.src))

	return complete

def info():
	parser = argparse.ArgumentParser()
	parser.add_argument("dstIP", help="Add Destination Address here")
	parser.add_argument("maxhops", type=int, help="set the maximum TTL")
	args = parser.parse_args()
	
	dstIP = args.dstIP
	maxhops = args.maxhops + 1
	return dstIP, maxhops

def main():
	targetIP, hops = info()
	print("[*] Tracing route to [%s] over a maximum of %d hops\n" %(targetIP, hops-1))

	for i in range(1,hops):
		tracertPacket = construct(targetIP, i)
		done = send_packet(tracertPacket, i)
		
		if done == 1:
			break	
			
main()
