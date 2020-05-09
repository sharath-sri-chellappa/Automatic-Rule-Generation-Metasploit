import math
import pymetasploit3
import os
import pexpect
import json
import re
from pymetasploit3.msfrpc import MsfRpcClient
import collections
import binascii
from scapy.all import *
from os import listdir
from os.path import isfile, join
#from metaspolit.msfconsole import MsfRpcConsole


rule_set = {"cve_2003_0719":[" tcp $EXTERNAL_NET any -> $HOME_NET 993 (msg:\"IMAP SSLv3 invalid data version attempt\"; flow:to_server,established; content:\"|16 03|\"; depth:2; content:\"|01|\"; depth:1; offset:5; content:!\"|03|\"; depth:1; offset:9; reference:bugtraq,10115; reference:cve,2004-0120; reference:nessus,12204; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:attempted-dos; sid:2497; rev:8;)", " tcp $EXTERNAL_NET any -> $HOME_NET 993 (msg:\"IMAP PCT Client_Hello overflow attempt\"; flow:to_server,established; content:\"|01|\"; depth:1; offset:2; byte_test:2,>,0,6; byte_test:2,!,0,8; byte_test:2,!,16,8; byte_test:2,>,20,10; content:\"|8F|\"; depth:1; offset:11; byte_test:2,>,32768,0,relative; reference:bugtraq,10116; reference:cve,2003-0719; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:attempted-admin; sid:2517; rev:10;)"," tcp $EXTERNAL_NET any -> $HOME_NET 993 (msg:\"IMAP SSLv3 Client_Hello request\"; flow:to_server,established; flowbits:isnotset,sslv3.client_hello.request; content:\"|16 03|\"; depth:2; content:\"|01|\"; depth:1; offset:5; flowbits:set,sslv3.client_hello.request; flowbits:no; reference:cve,2004-0120; reference:nessus,12204; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2529; rev:5;)", " tcp $HOME_NET 993 -> $EXTERNAL_NET any (msg:\"IMAP SSLv3 Server_Hello request\"; flow:to_client,established; flowbits:isset,sslv3.client_hello.request; content:\"|16 03|\"; depth:2; content:\"|02|\"; depth:1; offset:5; flowbits:set,sslv3.server_hello.request; flowbits:no; reference:cve,2004-0120; reference:nessus,12204; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:protocol-command-decode; sid:2530; rev:5;)", " tcp $EXTERNAL_NET any -> $HOME_NET 993 (msg:\"IMAP SSLv3 invalid Client_Hello attempt\"; flow:to_server,established; flowbits:isset,sslv3.server_hello.request; content:\"|16 03|\"; depth:2; content:\"|01|\"; depth:1; offset:5; reference:cve,2004-0120; reference:nessus,12204; reference:url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx; classtype:attempted-dos; sid:2531; rev:5;)"], "ms17_010_eternalblue":[" tcp any 445 -> any any (sid:2024218; rev:3; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; classtype:attempted-admin;)"], "ms17_010_psexec":[" tcp any 445 -> any any (sid:2024218; rev:3; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; classtype:attempted-admin;)"], "ms09_050_smb2_negotiate_func_index":[" tcp any 445 -> any any (sid:26643; rev:1; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2009-2532; reference:cve,2009-3103;)"], "cve_2020_0796_smbghost":[" tcp any any -> any 445 (msg:\"Claroty Signature: SMBv3 Used with compression - Client to server\"; content:\"|fc 53 4d 42|\"; offset: 0; depth: 10; sid:1000001; rev:1; reference:url,//blog.claroty.com/advisory-new-wormable-vulnerability-in-microsoft-smbv3;)", " tcp any 445 -> any any (msg:\"Claroty Signature: SMBv3 Used with compression - Server to client\"; content:\"|fc 53 4d 42|\"; offset: 0; depth: 10; sid:1000002; rev:1; reference:url,//blog.claroty.com/advisory-new-wormable-vulnerability-in-microsoft-smbv3;)"]}

only_files = [f for f in listdir("/root/Downloads/snort-rules/snortrules-snapshot-3000/rules") if isfile(join("/root/Downloads/snort-rules/snortrules-snapshot-3000/rules", f))]
# cve_dict = collections.defaultdict(list)
cve_dict = {}
reverse_dict = {}

def write_to_snort(version, rules):
  f = open("/etc/snort/local_test.rules", "a+")
  for i, CVE_rules in enumerate(rules):
    f.write("# "+vulnerability_dict[version][i]+"\n")
    for rule in CVE_rules:
      f.write(rule + "\n")
    f.write("\n")
  f.close()


def vulnerability_mapper(action, version):
  res = []
  if version in vulnerability_dict.keys():
    for CVE in vulnerability_dict[version]:
      res.append(snort_gen(action, CVE))
  return res


def snort_gen(action, CVE):
  return_list = []
  if CVE in rule_set.keys():
    for item in rule_set[CVE]:
      return_list.append(action + " " + item)
  return return_list


#from metaspolit.msfrpc import MsfRpcClient
print("running script")
#client = MsfRpcClient('',port=55553);
#lines = os.popen('msfconsole -q -x \"search type:exploit platform:windows target:Windows Server 2008 R2 description:smb rank:excellent rank:good rank:average\"')
#print(lines.read())


# 	child = pexpect.spawn('msfconsole -q -x \"search type:exploit platform:windows target:Windows Server 2008 R2 description:smb rank:excellent rank:good rank:average\"')
def create_vulnerabilty_dict(platform, target, module):
	print("msfconsole -q -x \"search type:exploit platform:" +platform + " target:"+target+" rank:excellent rank:good rank:average\"")
	if platform != ' ':
		if target != ' ':
			if module != ' ':
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit platform:'+platform+ ' target:'+target+' description:'+module+' rank:excellent rank:good rank:average\"')
			else:	
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit platform:'+platform+ ' target:'+target+' rank:excellent rank:good rank:average\"')
		else:
			if module != ' ':
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit platform:'+platform+ ' description:'+module+' rank:excellent rank:good rank:average\"')
			else:	
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit platform:'+platform+ ' rank:excellent rank:good rank:average\"')
	else:
		if target != ' ':
			if module != ' ':
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit target:'+target+' description:'+module+' rank:excellent rank:good rank:average\"')
			else:	
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit target:'+target+' rank:excellent rank:good rank:average\"')
		else:
			if module != ' ':
				print("msfconsole -q -x \"search type:exploit description:"+module+" rank:excellent rank:good rank:average\"")
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit description:'+module+' rank:excellent rank:good rank:average\"')
			else:	
				child = pexpect.spawn('msfconsole -q -x \"search type:exploit rank:excellent rank:good rank:average\"')
	child.expect('msf5')
	cmd_show_data = child.before
	output = cmd_show_data.decode('utf-8').split('\r\n')
	output = output[15:]
	output = list(filter(('').__ne__, output))
	vulnerabilities = []
	for data in output:
		found = re.findall(r'exploit/\w*/\w*/(\w*)',data)
		entire_vuln = re.findall(r'(exploit/\w*/\w*/\w*)',data)
		if found:
			vulnerabilities.append(found[0])
			child.sendline('info '+entire_vuln[0])
			child.expect('msf5')
			reverse_dict[found[0]] = entire_vuln[0]
			cve_number = child.before
			cve_list = []
			for line in cve_number.decode('utf-8').split('\r\n'):
				if re.findall(r'cve/(\w*-\w*-\w*)/', line):
					cve_list.append(re.findall(r'cve/(\w*-\w*-\w*)/', line)[0])
			cve_dict[found[0]] = cve_list
	child.sendline('exit')
	return vulnerabilities

def create_rule_set(target):
	print("Creating Rule Sets for the vulnerabilities from the Snort Rule Set")
	fline = open("/root/Downloads/snort3-community-rules/snort3-community.rules", "r").readlines()
	if target in vulnerability_dict.keys():
		# print("Target is ", target)
		for vuln_module in vulnerability_dict[target]:
			# print("Vuln Module is ",vuln_module)
			if vuln_module in cve_dict.keys():
				if vuln_module not in rule_set.keys():
					rule_set[vuln_module] = []
				for cve in cve_dict[vuln_module]:
					# print("CVE is ",'-'.join(cve.split('-')[1:]))
					for line in fline:
						if '-'.join(cve.split('-')[1:]) in line or ','+cve.split('-')[2] in line or '/'+cve.split('-')[2] in line:
							line = line.replace('# ','')
							# print("Line is ",line)
							if line.split(' ', 1)[1].replace("$HOME_NET", "any").replace("$EXTERNAL_NET", "any") not in rule_set[vuln_module]:
								rule_set[vuln_module].append(line.split(' ', 1)[1].replace("$HOME_NET", "any").replace("$EXTERNAL_NET", "any"))
								# print("rule_set[vuln_module] = ",rule_set[vuln_module])
			# print("=================")
		# print("++++++++++++++++")
#	print(json.dumps(rule_set, indent = 1))


def create_rule_set_github_repo(target):
	print("Creating Rule Sets for the vulnerabilities from the Custom Github Repositories")
	for filename in only_files:
#		print("Going through : "+filename)
		fline = open("/root/Downloads/snort-rules/snortrules-snapshot-3000/rules/"+filename, "r").readlines()
		if target in vulnerability_dict.keys():
			# print("Target is ", target)
			for vuln_module in vulnerability_dict[target]:
				# print("Vuln Module is ",vuln_module)
				if rule_set[vuln_module] == []:
					for cve in cve_dict[vuln_module]:
						# print("CVE is ",'-'.join(cve.split('-')[1:]))
						for line in fline:
							if '-'.join(cve.split('-')[1:]) in line or ','+cve.split('-')[2] in line or '/'+cve.split('-')[2] in line:
								line = line.replace('# ','')
								# print("Line is ",line)
								if line.split(' ', 1)[1].replace("$HOME_NET", "any").replace("$EXTERNAL_NET", "any") not in rule_set[vuln_module]:
									rule_set[vuln_module].append(line.split(' ', 1)[1].replace("$HOME_NET", "any").replace("$EXTERNAL_NET", "any"))
									# print("rule_set[vuln_module] = ",rule_set[vuln_module])
				# print("=================")
			# print("++++++++++++++++")
#	print(json.dumps(rule_set, indent = 1))

empty_list = []
def coverage_count(dictionary):
	empty = total = 0
	for item in dictionary.keys():
		if dictionary[item] == []:
			empty += 1
			empty_list.append(reverse_dict[item])
		total += 1
	empty_percent = (empty / total) * 100
	print("Total number of exploits in the search command", total)
	print("Total number of exploits which have a Snort Rule in the Community Ruleset", (total - empty))
	print("Total number of exploits which do not have a Snort Rule in the Community Ruleset", (empty))
	return empty_percent


def read_pcap(filename):
	a = rdpcap(filename)
	f = open("/etc/snort/local_test.rules", "a+")
	sessions = a.sessions()
	for session in sessions:
		http_payload = ""
		cmd = ""
		for packet in sessions[session]:
			try:
				if packet[TCP].sport == 4444 and packet[TCP].payload:
					hexd = binascii.hexlify(bytes(packet[TCP].payload))
					cmd = "alert tcp any "+str(packet[TCP].sport)+" any any (msg: \"Possible attack on port 4444\"; payload: "+str(hexd)+"; classtype: attempted-admin; reference: url, github.com/ptresearch/AttackDetection; metadata: Open Ptsecurity.com ruleset; sid: 120020; rev: 3;)\n"
				elif packet[TCP].dport == 4444 and packet[TCP].payload:
					hexd = binascii.hexlify(bytes(packet[TCP].payload))
					cmd = "alert tcp any any any "+str(packet[TCP].dport)+" (msg: \"Possible attack on port 4444\"; payload: "+str(hexd)+"; classtype: attempted-admin; reference: url, github.com/ptresearch/AttackDetection; metadata: Open Ptsecurity.com ruleset; sid: 120020; rev: 3;)\n"
				f.write(str(cmd))
			except Exception as e:
				print(e)
	f.close()
	
platform = ' '
target = ' '
description = 'HTTP'

vulnerability_list = create_vulnerabilty_dict(platform, target, description)
vulnerability_dict = {target: vulnerability_list}
# print("Vulnerability Dictionary is ",vulnerability_dict)
# print("CVE Dictionary is ",cve_dict)
create_rule_set(target)
print("Percentage of Modules which don't have CVE Mapping : ", coverage_count(cve_dict))
empty_list = []
print("Percentage of CVEs which don't have Rule Mapping : ", coverage_count(rule_set))
print("List OF CVEs throwing the problem ", empty_list)
pre_github_list = empty_list
create_rule_set_github_repo(target)
empty_list = []
print("Percentage of CVEs which don't have Rule Mapping post Github Repository: ", coverage_count(rule_set))
print("List OF CVEs throwing the problem post Github Repository", empty_list)

print("--------------------------------------")
print("List of exploits present on Github Repository but not the Community Ruleset")
exploit_difference = list(set(pre_github_list) - set(empty_list))
cnt = 0
for item in exploit_difference:
	cnt += 1
	print("Count is : ",cnt," and item is : ",item)
#for item in exploit_difference:
#	cnt += 1
#	print("Count is : ",cnt," and item is : ",reverse_dict[item])
#	print(reverse_dict[item])
print("--------------------------------------")

#rules = vulnerability_mapper("pass", "Windows Server 2008 R2")
rules = vulnerability_mapper("pass", target)
#write_to_snort("Windows Server 2008 R2", rules)
write_to_snort(target, rules)


read_pcap("/root/Downloads/EXPLOIT_metasploit-itunes-m3u-CVE-2012-0677_EmergingThreats.pcap")

