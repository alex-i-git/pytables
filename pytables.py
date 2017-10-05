#!/usr/bin/python3

import re
import subprocess

IPTABLES = '/sbin/iptables'
MAILLOG = '/var/log/maillog'
SECURELOG = '/var/log/secure'
IGNOREIP = '195.2.64.18'

#block address by iptables
def iptables_add(ip_address):
		cmd = IPTABLES + ' -A INPUT -s ' + ip_address + ' -j DROP'
		#cmd = 'echo -A INPUT -s ' + ip_address + ' -j DROP'
		subprocess.Popen(cmd, shell = True)
		print(ip_address)

#clear iptables rules
def iptables_flush():
		cmd = IPTABLES + ' -F'


#ip address list
ip_list=[]

#search in mail log
with open(MAILLOG, 'r') as f:
		for line in f:
				if line.find('unknown user') != -1:
						ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
						if ip != IGNOREIP:
								if (str(ip)[2:-2]) not in ip_list:
										ip_list.append(str(ip)[2:-2])
						#print(str(ip)[2:-2])

#search in secure log
with open(SECURELOG, 'r') as seclog:
		for line in seclog:
				if line.find('Failed') != -1:
						ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}',line)
						if ip != IGNOREIP:
								if (str(ip)[2:-2]) not in ip_list:
										ip_list.append(str(ip)[2:-2])


iptables_flush()

for i in ip_list:
		iptables_add(i)
		#print(i)
