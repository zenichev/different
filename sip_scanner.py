#!/usr/bin/python
# Imports
import nmap
import sys
import os
import pip

try:
	import nmap
except ImportError:
	print("WARNING: moudle nmap is not installed, please install it first.");

#################################################
# This is a sip scanner that uses nmap library  #
# to check an availability of a remote sip host,#
# and its opened UPD or TCP port, to use this   #
# you need to use the following syntax:         #
# ./sip_scanner <host> <port>                   #
#################################################

def main():
	global host
	global port
	global nm
	global udpIsOpened

	# check if python-nmap is installed
	isPackageInstalled("nmap");

	try:
		host = sys.argv[1]
		port = sys.argv[2]
	except IndexError:
		print("WARNING: You have to follow this syntax: ./sip_scanner.py <host> <port>");
		sys.exit(1);

	if os.geteuid()!=0:
		print("NOTICE: You should run as root if you want to scan UDP ports (ICMP requires root).");

	print("NOTICE: Processing your request..");
	
	# initialize port scanner
	nm = nmap.PortScanner();

	# check if TCP port opened
	result = scanTCP(host, port);
	# check if host is down not to process any other checks further
	ifHostDown(result);

	# get host state
	hostIsUP = nm['{0}'.format(host)].state()
	# get hostname
	hostname = nm['{0}'.format(host)].hostname()
	# check if TCP port is opened
	tcpIsOpened = nm['{0}'.format(host)]['tcp'][int(port)]
	tcpIsOpened = tcpIsOpened.get("state", "none");
	
	# check if UDP port is opened
	if os.geteuid()==0:
		udpIsAvailable = scanUDP(host, port) # check if UDP port opened
		udpIsOpened = nm['{0}'.format(host)]['udp'][int(port)]
		udpIsOpened = udpIsOpened.get("state", "none");
	else:
		udpIsOpened = "Not scanned"

	print("\nHostname: {0}\nHost state: {1}\nTCP {2} opened: {3}\nUDP {4} opened: {5}".format(hostname,hostIsUP,port,tcpIsOpened,port,udpIsOpened) );

	sys.exit(0);

def scanUDP(hostToScan,portToScan):
	result = nm.scan('{0}'.format(hostToScan), arguments="-sU -p {0}".format(portToScan))
	return result

def scanTCP(hostToScan,portToScan):
	result = nm.scan('{0}'.format(hostToScan), arguments="-p {0}".format(portToScan))
	return result

def ifHostDown(result):
	hostIsDown = result.get("nmap", "none").get("scanstats", "none").get("downhosts", "none")
	if "1" in hostIsDown:
		hostname = "Unknown"
		hostIsUP = "Host is down"
		tcpIsOpened = "Not scanned"
		udpIsOpened = "Not scanned"
		print("\nHostname: {0}\nHost state: {1}\nTCP {2} opened: {3}\nUDP {4} opened: {5}".format(hostname,hostIsUP,port,tcpIsOpened,port,udpIsOpened) );
		sys.exit(0);

def install(package):
	if hasattr(pip, 'main'):
		pip.main(['install', package])
	else:
		pip._internal.main(['install', package])

def isPackageInstalled(package):
	if not ('{0}'.format(package) in sys.modules):
		print("WARNING: python-{0} package is not installed, please install it first.".format(package));

		result = raw_input("Do you want me to install this for you? (You should run as root)\nType (yes/no) :");
		while( (not "yes" in result) and (not "no" in result) ):
			result = raw_input("Just type (yes/no) :");

		if result == "no":
			print("NOTICE: please install python-{0} and get back to us!".format(package));
			sys.exit(1);
		if result == "yes":
			install("python-{0}".format(package));

if __name__ == "__main__":
	main()
