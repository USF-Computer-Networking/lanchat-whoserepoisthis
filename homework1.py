import sys
from datetime import datetime
from scapy.all import srp,Ether,ARP,conf
import socket
import select
import argparse

def lanScanner():
	print "----------Lan Scanner----------"
	print "Press CTRL + 'c' to exit at anytime."
	try:
		status = True
		interface = raw_input("Enter network interface: ")
		ips = raw_input("Enter range of IPs to scan for: ")
		print "Scanning IPs: \n"

		start_time = datetime.now()
		conf.verb = 0
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface = interface, inter = 0.1)

		print "MAC - IP\n"
		for snd, rcv in ans:
			print rcv.sprintf(r"%Ether.src% - %ARP.psrc%\n")
		stop_time = datetime.now()
		total_time = stop_time - start_time

		print "Scan Complete!\n"
		print ("Scan Duration: %s" %(total_time))
		
	except KeyboardInterrupt:
		print "\nUser shutdown.."
		print "Quitting Lan Scanner.."
		sys.exit(1)

def getLine():
	messages, o, e = select.select([sys.stdin], [], [], 0.0001)

	for message in messages:
		if message == sys.stdin:
			line = sys.stdin.readline()
			return line

	return False


def udpChatSender():
	print "----------UDP Chat----------"
	print "Press CTRL + 'c' to exit at anytime."

	try:
		host = raw_input("Enter IP: ")
		user_port = raw_input("[Optional][Defaulted to 1027] Enter Port: ")

		if user_port == "":
			port = int("1027", 16)
		else:
			port = int(user_port, 16)

		send_address = (host, port)

		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		s.setblocking(False)
		s.bind(('', port))

		print "Port %i is now accepting connections. Please type your message:" % port

		while 1:
			try:
				message, address = s.recvfrom(8192)
				if message:
					print address, "> ", message
			except:
				pass

			line = getLine()
			if line is not False:
				s.sendto(line, send_address)
	except KeyboardInterrupt:
		print "\nUser shutdown.."
		print "Quitting UDP Chat.."
		sys.exit(1)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-l", "--lan", help="Use the LAN Scanner to find IPs on your network.", action="store_true")
	parser.add_argument("-u", "--udp", help="Use the UDP Chatter to send messages to designated IPs via sockets.", action="store_true")
	args = parser.parse_args()
	try:
		if args.lan:
			lanScanner()
		if args.udp:
			udpChatSender()
		return
	except KeyboardInterrupt:
		print "\nUser shutdown.."
		print "Quitting Application.."
		sys.exit(1)

main()