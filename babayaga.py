import threading
import urllib.request
import http.client
import argparse
import socket
from dns import reversename
import dns.name
import dns.query
import dns.zone
import dns.resolver
import linecache
import time
#from cymruwhois import Client
from colorama import init
init()

##############################
#TBD:
#Use Robtex
#do a traceroute to each ip, build a network architecture map
#Extract emails
#take snapshots of port 80,443,8080
##############################

#Colors
white = '\e[1;37m'
dgray = '\x1b[90m'
DGRAY = '\x1b[100m'
lred = '\x1b[91m'
LRED = '\x1b[101m'
lgreen = '\x1b[92m'
LGREEN = '\x1b[102m'
lyellow = '\x1b[93m'
LYELLOW = '\x1b[103m'
lblue = '\x1b[94m'
LBLUE = '\x1b[104m'
lmagenta = '\x1b[95m'
LMAGENTA = '\x1b[105m'
lcyan = '\x1b[96m'
LCYAN = '\x1b[106m'
lgray = '\x1b[97m'
LGRAY = '\x1b[107m'

#Create a list that holds ALL unique sub-domains
glob_domain_list = list()
glob_ip_list = list()
glob_domain = ''
glob_subnets = list()

print (lgreen + '''
AUTHOR IS NOT RESPONSIBLE TO ANY DAMAGE CAUSED BY THIS TOOL
PLEASE USE WITH CAUTION AND ONLY IF YOU HAVE AUTHORIZATION

                                 Baba-Yaga
                                 Sub Domain Extractor
               (       "     )   and Passive Information
                ( _  *           Gathering Tool V1.0 by KittySec(C)
                   * (     /      \    ___
                      "     "        _/ /
                     (   *  )    ___/   |
                       )   "     _ o)'-./__
                      *  _ )    (_, . $$$
                      (  )   __ __ 7_ $$$$
                       ( :  { _)  '---  $\ 
       		   ______'___//__\   ____,\ 
		   )           ( \_/ _____\_
                 .'             \   \------"".
                 |="           "=|  |         )
                 |               |  |  .    _/
                  \    (. ) ,   /  /__I_____/
                   '._/_)_(\__.'   (__,(__,_]
                  @---()_.'---@"" "" `""
		''')
	

#def netcraft(domain,orgName):
#try:
#	print ('[!] Trying to establish a connection with NetCraft...')
#	conn = http.client.HTTPConnection('searchdns.netcraft.com')
#	conn.request('GET', '/')
#	response = conn.getresponse()
#	data1 = response.read()
#	print (data1)
#xcept:
#	print (lred + '[-] Something went wrong while trying to connect to NetCraft')


#This method uses a Brute-Force technique in order to find subdomains and map them to their ip.
def bruteForce(x,y):
	resolver = dns.resolver.Resolver()
	string = '.' + glob_domain
	#need to check if theres a wildcard DNS...
	for i in range(1,(y-x)):
		line = linecache.getline('domains.txt', x).strip('\n') + string
		try:
			result = resolver.query(line, 'A')
			for rdata in result:
				print (lgreen + '[+] FOUND using Brute-Force technique ' + line + '\t' + str(rdata) + '\n')
				checkUnique(line)
				addtoglobiplist(domain2ip(str(line)))
			x += 1
		except:	
			x += 1
			continue

#Makes a list of unique IP lists			
def addtoglobiplist(ip):
	try:
		if ip in glob_ip_list:
			return
		else:
			glob_ip_list.append(ip)
			return
	except:
		print (lred + '[-] Something went wrong while trying to build the global IP list')
		
#Converts a domain name to IP		
def domain2ip(domain):
	try:
		result = socket.gethostbyname(domain)
		return result
	except:
		return

#Converts an IP to a hostname
def ip2domain(subnet, orgName):
	try:
		r = dns.resolver.Resolver()
		for x in range(1,255):
			newSubnet = subnet + str(x)
			rev_name = reversename.from_address(newSubnet)
			try:
				reversed_dns = str(r.query(rev_name,"PTR")[0])
			except:
				continue
			if orgName in reversed_dns:
				print (lgreen + '[+] FOUND! Using reverse DNS technique ' + reversed_dns[:-1])
				checkUnique(reversed_dns[:-1])
			else:
				continue
	except:
		print (lred + '[-] Something went wrong while trying to convert IP to hostname')

#Gets the name of the target
def getName(domain):
	orgName = str(domain.split('.')[:1])
	orgName = orgName.strip('[]\'') #example
	return orgName

#reverse DNS lookup
def reverseDNS(subnet, orgName,counter):
	print (lyellow + '[!] Now scanning subnet ' + lmagenta + str(counter) + ' out of ' + lmagenta + str(len(glob_subnets)) + lyellow + ' using reverse DNS lookup, this may take a while...')
	subnet += '.'
	ip2domain(str(subnet), orgName)
		
#make a list of unique hostnames
def checkUnique(domain):
	try:
		if domain in glob_domain_list:
			return
		else:
			glob_domain_list.append(domain)
			return
	except:
		return

#make a list of unique subnets		
def checkUniqueSubnets(ip):
	try:
		if ip in glob_subnets:
			return
		else:
			glob_subnets.append(ip)
			return
	except:
		return

def axfr(nameserver):
	global glob_domain
	try:
		print (lgray + '[!] Attempting a Zone Transfer on ' + lred + nameserver)
		zone = dns.zone.from_xfr(dns.query.xfr(nameserver, glob_domain))
		names = zone.nodes.keys()
		if names:
			print (lgreen + '[+] Zone Transfer Succeeded!!!')
			for n in names:
				#print (lgray + zone[n].to_text(n))
				n = str(n) + '.' + glob_domain
				checkUnique(n)
	except:
		print (lgray + '[-] Zone Transfer failed')
		
def getauth(domain,orgName):
	
	try:
		boolexternal = False
		boolinternal = False
		ownsubdomains = list()
		externaldomains = list()
		print (lgray + '[*] Trying to extract Authorative nameservers for ' + lred + domain + lgray)
		for x in dns.resolver.query(domain, 'NS'):
		
		#Check if the target manages their DNS by their own...
			x = str(x)
			x = x[:-1]
			if orgName in str(x):
				boolinternal = True	
				ownsubdomains.append(x)
				checkUnique(x)
			else:
				boolexternal = True
				externaldomains.append(x)
		if boolexternal is True and boolinternal is True:
			print ('[!] It seems that the target has DNS servers both internally and externally...')
			for i in ownsubdomains:
				print (lgreen + '[+]' + ' FOUND! ' + i + ' ' + domain2ip(i))
				checkUnique(i)

			for i in externaldomains:
				print (lmagenta + '[-] ' + lgray + 'External NS Found ' + i + ' ' + domain2ip(i))
				
		elif boolinternal is True and boolexternal is False:
			for i in ownsubdomains:
				print (lgreen + '[+]' + ' FOUND! ' + i + ' ' + domain2ip(i))
				checkUnique(i)
		
		elif boolinternal is False and boolexternal is True:
			print (lyellow + '[?]' + lgray + ' It appears that the target ' + lred + domain + lgray +' manages their DNS services in an external source... print anyways just to make sure?(Y/N)')
			userAnswer = input()
			if userAnswer == 'y':
				for i in externaldomains:
					print (lmagenta + '[-] ' + lgray + 'External NS Found ' + i + ' ' + domain2ip(i))
			
		for i in externaldomains:
			axfr(i)
		for i in ownsubdomains:
			checkUniqueSubnets(".".join(domain2ip(domain).split('.')[:3]))
			axfr(i)
	except:
		print ("Couldn't extract Authorative Nameservers for " + domain)
	
#Find MX Servers	
def getmx(domain,orgName):
	try: 
		bool = False
		ownsubdomains = list()
		externaldomains = list()
		print (lgray + '[*] Trying to extract MX servers for ' + lred + domain + lgray)

		for x in dns.resolver.query(domain, 'MX'):
			#Check if the target manages their mail by their own...
			x = str(x)
			x = " ".join(x.split()[1:])
			if orgName in str(x):
				bool = True
				ownsubdomains.append(x)
				checkUnique(x)
			else:
				externaldomains.append(x)
					
		#print all MX sub-domains found
		if bool == True:
			for i in ownsubdomains:
				print (lgreen + '[+]' + ' FOUND! ' + i + ' ' + domain2ip(str(i)[:-1]))
		
		#if mail services are being managed externally...
		else:
			print (lyellow + '[?]' + lgray + ' It appears that the target ' + lred + domain + lgray +' manages their mail services in an external source... print anyways just to make sure?(Y/N)')
			userAnswer = input()
			if userAnswer == 'y':
				for i in externaldomains:
					print (lmagenta + '[-] ' + lgray + i + ' ' + domain2ip(str(i)[:-1]))
			else:
				return
	except:
		print (lred + "[-] Couldn't convert domain name to IP " + domain)

def main():		
	#argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('domain', metavar='Domain', type=str, nargs='+', help='Target domain, for example: kittysec.com')
	args = parser.parse_args()
		
	domain = str(args.domain).strip('[]\'') #example.com
	global glob_domain
	glob_domain = domain
	orgName = getName(domain)
	print (lgray + '[*] Trying to convert domain name to IP...')
	print (lgreen + '[+]' + lgray + ' Successfully converted ' + lred + domain + lgray + ' to IP ' + domain2ip(domain))
	
	domainSubnet = ".".join(domain2ip(domain).split('.')[:3])
	checkUniqueSubnets(domainSubnet)
	
	getmx(domain,orgName)
	getauth(domain,orgName)
	
	#Setting up brute-force
	print (lgray + '\n[*] Now using a Brute-Force in order to find more sub-domains. This might take a while...')
	x = 1
	y = 20
	threads = list()
	for i in range(1700):
		try:
			t = threads.append(threading.Thread(target=bruteForce, args=(x,y)).start())
			x = y+1
			y += 20
		except:
			continue
	#END of Brute-Force

	#robtex(domain,orgName)
	
	time.sleep(60)
	#build a list of all unique IPs found
	for i in glob_domain_list:
		addtoglobiplist(domain2ip(str(i)))
		
	#build a list of unique subnets
	for i in glob_ip_list:
		s = str(i)
		s = ".".join(s.split('.')[:3])
		checkUniqueSubnets(s)
	
	#reverse DNS Lookup
	print (lgreen + '[+] Found the following subnets:')
	print (lgreen + '================================')
	for i in glob_subnets:
		print ('[+] ' + i + '.0/24')
	
	counter = 1
	for i in glob_subnets:
		reverseDNS(i,orgName, counter)
		counter += 1

	#Print a list of all the results	
	print (lgray + '\n[+] Compiling a list of all sub-domains harvested...')
	print (lgray + '====================================================')
	for i in glob_domain_list:
		print (lgreen + i, end='\t')
		print (domain2ip(str(i)))
	
if __name__ == '__main__':
	main()