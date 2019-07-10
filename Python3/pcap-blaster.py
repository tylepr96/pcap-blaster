import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try: from scapy.all import *
except: from scapy import *
from subprocess import Popen, PIPE
from time import sleep
import sys
import os
import signal
import argparse
import binascii

radamsa_bin = "/usr/local/Cellar/radamsa/0.5/bin/radamsa" # radamsa path

NAME = "PCAP-BLASTER"
VERSION = "2.0"
AUTHORS = "Author: Tyler Price"

global args

parser = argparse.ArgumentParser(
formatter_class = argparse.RawDescriptionHelpFormatter,
description = "%s - v%s\n%s\n" %(NAME, VERSION, AUTHORS),
epilog = """
Usage:
./%(prog)s -i input.pcap [-d 0.2] [-ip 127.0.0.1] [-port 80]
""")

if len(sys.argv) == 1:   	
	parser.print_help()
	sys.exit(1)
	
parser.add_argument("-i", default=True, metavar="", help="pcap input")
parser.add_argument("-d", default=True, metavar="0.1", help="delay")
parser.add_argument("-ip", default=True, metavar="127.0.0.1", help="ip address")
parser.add_argument("-port", default=True, metavar="80", help="port address")

args = parser.parse_args()

def Fuzz():
	try:
		print("[!] Fuzzer Starting!")
		print("[*] Fuzzing IP: %s on Port: %s" % (str(args.ip),str(args.port)))
		print("[*] Loading PCAP...")
		pcap = rdpcap(args.i)
		sessions = pcap.sessions()
		print("[*] Loading...Done")
		while True:
			for session in sessions:
				for packet in sessions[session]:
					try:
						parse = packet[TCP]
						mutate_me = bytes(parse)
						radamsa = [radamsa_bin, "-n",'1']
						p = Popen(radamsa, stdin=PIPE, stdout=PIPE)
						mutated_data = p.communicate(mutate_me)[0] # Pipe raw packet data into radamsa
						new_packet = binascii.hexlify(mutated_data)
						print("[*] Packet: %s" % str(new_packet.decode("utf-8")))
						SendFuzz(new_packet) # Sending muated packet
						sleep(float(args.d)) # Delay
					except Exception as e:
						pass
	except KeyboardInterrupt:
		print("\n[!] Exiting...\n")
		os.kill(os.getpid(), signal.SIGUSR1)

def SendFuzz(packet):
	try:
		sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(.5)
		connect = sock.connect((str(args.ip), int(args.port)))
		sock.send(binascii.unhexlify(packet))
		print("[*] Packet Sent")
		try:
			data = sock.recv(1024)
			print("[*] Recieved:", data)
		except:
			pass
		sock.close()
	except Exception as e:
		print("[!] Server is down...")
		print("[!] Check Packet...")
		os.kill(os.getpid(), signal.SIGUSR1)
Fuzz()
