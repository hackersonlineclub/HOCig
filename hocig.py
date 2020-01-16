import os
import re
import sys
import time
import math
import copy
import datetime
try:
    import ssl
except ImportError:
    print ('ssl isn\'t installed, installing now.')
    os.system('pip install ssl')
    print ('ssl has been installed.....')
try:
    import nmap
except ImportError:
    print ('nmap isn\'t installed, installing now.')
    os.system('pip install python-nmap')
    print ('python-nmap has been installed.....')
try:
    import socket
except ImportError:
    print ('socket isn\'t installed, installing now.')
    os.system('pip install socket')
    print ('socket has been installed.....')
try:
    import requests
except ImportError:
    print ('requests isn\'t installed, installing now.')
    os.system('pip install requests')
    print ('requests has been installed.....')
try:
    import ipwhois
except ImportError:
    print ('ipwhois isn\'t installed, installing now.')
    os.system('pip install ipwhois')
    print ('ipwhois has been installed.....')
try:
    import urllib2
except ImportError:
    print ('urllib2 isn\'t installed, installing now.')
    os.system('pip install urllib2')
    print ('urllib2 has been installed.....')
try:
    import signal
except ImportError:
    print ('signal isn\'t installed, installing now.')
    os.system('pip install signal')
    print ('signal has been installed.....')
try:
    import urlparse
except ImportError:
    print ('urlparse isn\'t installed, installing now.')
    os.system('pip install urlparse')
    print ('urlparse has been installed.....')
try:
    import lxml
except ImportError:
    print ('lxml isn\'t installed, installing now.')
    os.system('pip install lxml')
    print ('lxml has been installed.....')
try:
    from cgi import escape
except ImportError:
    print ('required from cgi import escape')
try:
    from traceback import format_exc
except ImportError:
    print ('required from traceback import format_exc ')
try:
    from Queue import Queue, Empty as QueueEmpty
except ImportError:
    print ('required from Queue import Queue, Empty as QueueEmpty')
try:
    from bs4 import BeautifulSoup
except ImportError:
    print ('BeautifulSoup isn\'t installed, installing now.')
    os.system('pip install BeautifulSoup')
    print ('BeautifulSoup has been installed.....')
try:
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print ('error on requests.packages.urllib3.disable_warnings()')

#----------------------------------lib imported end-----------------------------------

#----------------------------------Pre-define TXT Output------------------------------
class Log:
    	@classmethod
	def info(self,text):
        	print(N + " #> " + G +  text)
	@classmethod
	def info1(self,text):
 		print(G + " [>] " + N + text)
	@classmethod
	def info2(self,text):
		print(Y + " [!] " + Y + text)
	@classmethod
	def info3(self,text):
 		print(R + " [!] " + R + text)	
intro = '''
        --------------------------------------------------
            		#    #   ####    #####      
            		#    #  #    #  #
            		######  #    #  #
            		#    #  #    #  #
            		#    #  #    #  #
            		#    #   ####    #####
            
            Version : 1.2
            Team Hackersonlineclub
            Website : https://hackersonlineclub.com
        --------------------------------------------------
    '''

#-----------------------------------color code------------------------------------------
N = '\033[0m'
W = '\033[1;37m' 
B = '\033[1;34m' 
M = '\033[1;35m' 
R = '\033[1;31m' 
G = '\033[1;32m' 
Y = '\033[1;33m' 
C = '\033[1;36m'
underline = "\033[4m" 
log=False
finderurl = 'https://www.pagesinventory.com/search/?s='
errormsgreq = 'Error on getting request '
match = '/domain/(.*?).html(.*?)'
WHAT = 'WHAT YOU WANT TO DO?'
keybordexcpt = 'Keyboard Interruption! Exiting... '
exit = 'Press CTRL + C for EXIT'
retrypls ='Wrong target not able to get IP address Please retry '
sslnotfound = 'SSL is not Present on Target URL...Skipping... '
msgsinfo = 'This website have references to the following websites: '
presskey='Press a key to continue '
ABC = 'User-Agent'
BCD = 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
linkregex = re.compile('[^>](?:href\=|src\=|content\=\"http)[\'*|\"*](.*?)[\'|\"].*?>',re.IGNORECASE)
linkredirect = re.compile('(?:open\\(\"|url=|URL=|location=\'|src=\"|href=\")(.*?)[\'|\"]')
linksrobots = re.compile('(?:Allow\:|Disallow\:|sitemap\:).*',re.IGNORECASE)
information_disclosure = re.compile('(?:<address>)(.*)[<]',re.IGNORECASE)
def IPchk():
	os. system('clear')
        print(R + intro + '\n' + '\n' + W)
	target = raw_input('Enter target Website : >')#enter website domain name
	if 'http' in target:
		hostname = target.split('//')
		hostname = hostname[1]
	elif 'http' not in target:
		hostname = target
		target = 'http://{}'.format(target)
	elif ':' in hostname:
		hostname = hostname.split(':')
		hostname = hostname[0]
	else:
		Log.info3(' Error : Invalid URL / IP Entered'+ W)
		sys.exit(1)
	try:
		ip = socket.gethostbyname(hostname)
        	RECO(hostname,target,ip)
	except Exception as e:
        	Log.info3(retrypls)
        	sys.exit(1)
#-----------------------------------RECO MENU function------------------------------------------
def RECO(hostname,target,ip):
	print('\n')
	Log.info2(' Hostname :'+ hostname)
	Log.info2(' Target protocal :'+ target)
	Log.info2(' Target IP address :'+ ip)
	print('\n')
	Log.info(WHAT)
	Log.info(' 1.  Header Information')
	Log.info(' 2.  SSL Certificate Information')
	Log.info(' 3.  Whois Lookup')
	Log.info(' 4.  Sub-domain Website')
	Log.info(' 5.  Robots.txt')
	Log.info(' 6.  Honeypot Detector using Shodan')
	Log.info(' 7.  Port Scanner using SYN ACK Scan')
	Log.info(' 8.  OS Finger Printing')
	Log.info(' 9.  Crawl Target Website (includes Email, Sub-Domain, File Type )')
	Log.info(' 10. Test All Available Options')
    	Log.info(' 0.  Change Target')
	Log.info(exit)	
	print('\n')
	RECO_var = raw_input('Enter your choice: >')
	Log.info3(' TARGET :' + target)
	if(RECO_var=="1"):
		RECO1(target) #Header
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)
	if(RECO_var=="2"):
		RECO2(hostname) #SSL certificate
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)
	if(RECO_var=="3"):
		RECO3(ip) #Whois lookup
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)        
	if(RECO_var=="4"):
		RECO5(hostname) #sub domain
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)     
	if(RECO_var=="5"):
		RECORobot(target) #Robots.txt
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)
	if(RECO_var=="6"):
		RECOHoneypot(ip) #Honeypot Detector
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)  
	if(RECO_var=="9"):
		RECO4(target) #crawl target
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)
	if(RECO_var=="8"):
		RECOOSprinting(ip) #OS Fingerprinting
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)
	if(RECO_var=="7"):
		RECOPortScanner(ip) #Port Scanner
		a = raw_input('Press enter for continue')
        	RECO(hostname,target,ip)
	if(RECO_var=="10"):
	 # Test all the avaible option
 		RECO1(target) #Header
		RECO2(hostname) #SSL certificate
		RECO3(ip) #Whois lookup
		RECO5(hostname) #Sub domain
		RECORobot(target) #Robots.txt
		RECOHoneypot(ip) #Honeypot Detector
		RECOOSprinting(ip) #OS Fingerprinting
		RECOPortScanner(ip) #Port Scanner
		RECO4(target) #Crawl target
        	RECO(hostname,target,ip) #Change target
	if(RECO_var=="0"):
        	IPchk() #Change target
	if(RECO_var !="1" and RECO_var !="2" and RECO_var !="3" and RECO_var !="4" and RECO_var !="5" and RECO_var !="6" and RECO_var !="8" and RECO_var !="9" and RECO_var !="10" and RECO_var !="7" and RECO_var !="0"):
		print(R + 'Wrong Key Enter Retry...' + presskey)
        	raw_input()
		RECO(hostname,target,ip)
		
#----------------------------------- RECO Header------------------------------------
def RECO1(target):
	print(R + '---------------------------------------------------')
	Log.info('Headers :'+ W)
	print(R + '---------------------------------------------------')
	ReQ = requests.get(target, verify=False, timeout=10)
	for k, v in ReQ.headers.items():
		Log.info1('{} : '.format(k) + v)
#-----------------------------------RECO SSL ---------------------------------------
def RECO2(hostname):
	print(R + '---------------------------------------------------')
	Log.info('SSL Certificate Information : '+W)
    	print(R + '---------------------------------------------------')
	ctx = ssl.create_default_context()
	s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
	try:
		try:
			s.connect((hostname, 443))
			info = s.getpeercert()
			subject = dict(x[0] for x in info['subject'])
			issuer = dict(y[0] for y in info['issuer'])
		except:
			ctx = ssl._create_unverified_context()
			s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
			s.connect((hostname, 443))
			info = s.getpeercert(True)
			info = ssl.get_server_certificate((hostname, 443))
			f = open('{}.pem'.format(hostname), 'w')
			f.write(info)
			f.close()
			cert_dict = ssl._ssl._test_decode_cert('{}.pem'.format(hostname))
			subject = dict(x[0] for x in cert_dict['subject'])
			issuer = dict(y[0] for y in cert_dict['issuer'])
			info = cert_dict
			os.remove('{}.pem'.format(hostname))
		try:
			for k, v in subject.items():
				Log.info1('{} : '.format(str(k)) + W + str(v))
			for k, v in issuer.items():
				Log.info1('{} : '.format(str(k)) + W + str(v))
			Log.info1('Version : ' + W + str(info['version']))
			Log.info1('Serial Number : ' + W + str(info['serialNumber']))
			Log.info1('Not Before : ' + W + str(info['notBefore']))
			Log.info1('Not After : ' + W + str(info['notAfter']))
			Log.info1('OCSP : ' + W + str(info['OCSP']))
			Log.info1('subject Alt Name : ' + W + str(info['subjectAltName']))
			Log.info1('CA Issuers : ' + W + str(info['caIssuers']))
			Log.info1('CRL Distribution Points : ' + W + str(info['crlDistributionPoints']))
		except KeyError:
			pass

	except:
		Log.info3(sslnotfound)
#-----------------------------------RECO Whois -------------------------------------
def RECO3(ip):
	print(R + '---------------------------------------------------')
	Log.info('Whois Lookup : ' + W)
    	print(R + '---------------------------------------------------')
	try:
		Lookup = ipwhois.IPWhois(ip)
		results = Lookup.lookup_whois()
		Log.info1('NIR : ' + W + str(results['nir']))
		Log.info1('ASN Registry : ' + W + str(results['asn_registry']))
		Log.info1('ASN : ' + W + str(results['asn']))
		Log.info1('ASN CIDR : ' + W + str(results['asn_cidr']))
		Log.info1('ASN Country Code : ' + W + str(str(results['asn_country_code'])))
		Log.info1('ASN Date : ' + W + str(results['asn_date']))
		Log.info1('ASN Description : ' + W + str(results['asn_description']))
		for k, v in results['nets'][0].items():
			Log.info1('{} : '.format(str(k)) + W + str(v))
	except Exception as e:
		Log.info3(' Error : ' + C + str(e) + W)
		pass
    	#keyboardinterrrupt handler
    	except KeyboardInterrupt:
    	    Log.info3(keybordexcpt)
    	    sys.exit(1)
    	except Exception as inst:
            Log.info1( 'Exception in RECO3() function')
            sys.exit(1)
            
#-----------------------------------Getting urls------------------------------------
def geting_url(url, host, username, password):
	handler=""
	try:
		try:
			request = urllib2.Request(url)
			request.add_header(ABC,BCD)
			request.get_method = lambda : 'GET'
			if handler:
				opener_web = urllib2.build_opener(handler)
			else: 
				opener_web = urllib2.build_opener()
			response = opener_web.open(request)
			opener_web.close()
			return [request,response]
                except urllib2.HTTPError,error_code:
			return [request,error_code.getcode()]
		except urllib2.URLError,error_code:
			error = error_code.args[0]
			return [request,error[0]]
		except socket.error,error_code:
			error = error_code.args[0]
			try:
				error = error[0]
			except:
				pass
			return [request,error]
	except KeyboardInterrupt:
		try:
			Log.info3(presskey)
			raw_input()
			return ["",1]
		except KeyboardInterrupt:
			return ["",0]
        except Exception as inst:
		Log.info2('Exception in geting_url() function')
		Log.info1(inst)
		return -1	

#-----------------------------------Getting links-----------------------------------
def geting_links(link_host, link_path, content):
	global linkregex
	try:
		links = linkregex.findall(content)
		for link in links:
			try:
				link_cln = link.strip(' ')
			except:
				Log.info3('Error')
			prsd_link = urlparse.urlparse(link_cln)
			if not prsd_link.scheme and not prsd_link.netloc:
				if link_cln.startswith('/'):
					if link_host.endswith('/'):
						links[links.index(link)] = link_host.rstrip('/')+link_cln
					else:
						links[links.index(link)] = link_host+link_cln
				elif link_cln.startswith('./'):
						links[links.index(link)] = link_host+link_cln
				else:
					links[links.index(link)] = link_path+link_cln
			else:
				links[links.index(link)] = link_cln

		for link in links:
			links[links.index(link)] = link.split('#')[0]

		return links

        except Exception as inst:
		Log.info2(inst)          
		return -1

#-----------------------------------Getting crawl-----------------------------------
def crawl(url,usuario,password,output_filename,crawl_limit=0, crawl_depth=0):
	log=False
	urls_to_crawl = []
	urls_not_crawled = []
	links_crawled = []
	links_extracted = []
	files=[]
	crawl_limit_flag=False
	urls_to_crawl.append(url)
	if (crawl_limit>0):
		crawl_limit_flag=True
	if crawl_depth > 0:
		crawl_depth = crawl_depth + 3
	try:
		while urls_to_crawl:
			if crawl_limit_flag:
				if (len(links_crawled) >= crawl_limit):
					break
			try:
				url = urls_to_crawl[0]
				urls_to_crawl.remove(url)
				if crawl_depth > 0:
					if url.endswith('/'):
						if url.rpartition('/')[0].count('/') >= crawl_depth:
							continue
					elif url.count('/') >= crawl_depth:
							continue
				links_crawled.append(url)
				Log.info1(str(url))	
				parsed_url = urlparse.urlparse(url)
				host = parsed_url.scheme + '://' + parsed_url.netloc

				if parsed_url.path.endswith('/'):
					link_path = host + parsed_url.path
				else:
					link_path = host + parsed_url.path.rpartition('/')[0] + '/'
				[request,response] = geting_url(url,host,usuario, password)
				if response:
					if not isinstance(response, int):
						content = response.read()
						if response.headers.typeheader:
							if 'text/html' not in response.headers.typeheader:
								if url not in files:
									files.append([url,str(response.headers.typeheader.split('/')[1].split(';')[0])])
							else:
								links_extracted = geting_links(host, link_path, content)
								links_extracted.sort()
								for link in links_extracted:
									parsed_link= urlparse.urlparse(link)
									link_host = parsed_link.scheme + '://' + parsed_link.netloc
									if link_host == host:
										if link not in links_crawled and link not in urls_to_crawl:
											urls_to_crawl.append(link)
									elif link not in urls_not_crawled:
										urls_not_crawled.append(link)
					else:
						Log.info2('Error on this link')
				else:
					if response==1:
						continue
					if response==0:
						Log.info2( ' Skypping the rest of the urls')
						break
			except KeyboardInterrupt:
				try:
					Log.info3(presskey) 
					raw_input()
					continue
				except KeyboardInterrupt:
					Log.info1(keybordexcpt)
					break	
			except Exception as inst:
				Log.info2('Exception inside crawl() function. While statement rise the exception.')
				break
		Log.info(' Total urls crawled: '+str(len(links_crawled)))
		return [links_crawled,urls_not_crawled,files]
	except KeyboardInterrupt:
		try:
			Log.info1(presskey) 
			raw_input()
			return 1
		except KeyboardInterrupt:
			Log.info3(keybordexcpt)
			return 1
	except Exception as inst:
		Log.info2('Exception in crawl() function')
		return -1

#-----------------------------------Getting external links--------------------------
def external_links(root_url,external_vector,output_filename):
	external_websites = []
	try:
		parsed_url = urlparse.urlparse(root_url)
		link_host = parsed_url.scheme + '://' + parsed_url.netloc
		domain = parsed_url.netloc.split('www.')[-1]
		Log.info('Related subdomains found: ')
		tmp=[]
		for link in external_vector:
			parsed = urlparse.urlparse(link)
			if domain in parsed.netloc:
				subdomain = parsed.scheme+'://'+parsed.netloc
				if subdomain not in tmp:
					tmp.append(subdomain)
					Log.info1(subdomain)
		Log.info('Total:  '+str(len(tmp)))
		Log.info('Email addresses found: ')
		for link in external_vector:
			if 'mailto' in urlparse.urlparse(link).scheme:
				Log.info1(link.split(':')[1].split('?')[0])
		Log.info(msgsinfo)
		for link in external_vector:
			parsed = urlparse.urlparse(link)
			if parsed.netloc:
				if domain not in parsed.netloc:
					external_domain = parsed.scheme+'://'+parsed.netloc 
					if external_domain not in external_websites:
						external_websites.append(external_domain)
		external_websites.sort()
		for link in external_websites:
			Log.info1(link)
		Log.info(' Total:  '+str(len(external_websites)))
	except Exception as inst:
		Log.info1(' Exception in external_links() function')          
		return -1

#-----------------------------------Getting external links--------------------------
def indexing_search(usuario, password,links_vector,output_filename):
	directories=[]
	indexing=[]
	request=""
	response=""
	title_start_position = -1
	title_end_position = -1
	title=""
	try:
		for i in links_vector:# Identifying directories
			while ( len(i.split('/')) > 4 ):
				i=i.rpartition('/')[0]
				if ( ( i+'/' )  not in directories ):
					directories.append(i+'/')
		directories.sort()
		Log.info('Directories found:')
		for directory in directories:
			Log.info1(directory)
		Log.info('Total directories: '+str(len(directories)))
		Log.info('Directory with indexing')
		dots='.'
		for directory in directories:
			sys.stdout.flush()
			sys.stdout.write('\r\x1b'+dots)
			if len(dots)>30:
				dots='.'
			dots=dots+'.'
			try:
				parsed_url = urlparse.urlparse(directory)
				host = parsed_url.scheme + '://' + parsed_url.netloc
				[request,response] = geting_url(directory, host, usuario, password)                			
				if response:					      		
					if not isinstance(response, int):#If the server didn't return an HTTP Error
						content = response.read()
						title_start_position = content.find('<title>')
						if title_start_position != -1:
							title_end_position = content.find('</title>', title_start_position+7)
						if title_end_position != -1:
							title = content[title_start_position+7:title_end_position]
						if title:
							if title.find('Index of') != -1:
								Log.info1(directory)
								indexing.append(directory)
				else:
					if response==1:
						continue
					if response==0:
						Log.info2('Skipping.... the rest of the directories')
						break
			except KeyboardInterrupt:
				try:
					Log.info3(presskey)
					raw_input()
					pass
				except KeyboardInterrupt:
					Log.info2(keybordexcpt)
					break	

		Log.info1('\nTotal directories with indexing: '+str(len(indexing)))
		return [directories,indexing]

	except Exception as inst:
		Log.info2('Exception in indexing_search() function')         
		return 1

#-----------------------------------Getting external links--------------------------
def statistics(directories, indexing, links_crawled, files, extensions_found, output_filename):
	amt_files_per_extension = {}
	try:
		if len(links_crawled) > 1:
			for [link,extension] in files:
				amt_files_per_extension[extension] = 0
			for [link,extension] in files:
				amt_files_per_extension[extension] += 1
			Log.info('Total found files\t{0}'.format(str(len(files))))
			for key in amt_files_per_extension.keys():
				Log.info1("\t"+key+" ~"+str(amt_files_per_extension[key]))
	except Exception as inst:
		Log.info1(inst)           
		return -1

#-----------------------------------RECO web crawl ---------------------------------
def RECO4(target):
    	print(R + '---------------------------------------------------')
	Log.info('Web Crawler :' + W )
	print(R + '---------------------------------------------------')
    	global log
	global output_name
    	try:
	 	req = requests.get(target)
	 	url_to_crawl = req.url
        	print(url_to_crawl)
    	except:
        	info2('Error on getting responce')
        	sys.exit(1)
	usuario = "admin"
	password = "password"
	crawl_limit = 0
	#Data lists
	directories = []
	indexing = []
	links_crawled = []
	externals_url_vector = []
	files_vector = []
	extensions_found = []
	crawl_depth = 50
	output_name = ""
	output_file = ""
    	try:
        	output_name = ""
        	[links_crawled,externals_url_vector, files_vector] = crawl(url_to_crawl, usuario, password, output_file, crawl_limit, int(crawl_depth))
        	[directories, indexing] = indexing_search(usuario, password,links_crawled,output_file)
        	external_links(url_to_crawl,externals_url_vector,output_file)
        	statistics(directories,indexing,links_crawled,files_vector,extensions_found,output_name)
        	try:
        	    output_file.close()
        	except:
        	    pass       
    #keyboardinterrrupt handler
    	except KeyboardInterrupt:
    	    Log.info3(keybordexcpt)
    	    sys.exit(1)
    	except Exception as inst:
    	    Log.info1( 'Exception in RECO4() function')
    	    sys.exit(1)
#-----------------------------------RECO subdomain ---------------------------------
def RECO5(target):
    print(R + '---------------------------------------------------')
    Log.info('SubDomain Finder :' + W )
    print(R + '---------------------------------------------------')
    try:
    	uRl = finderurl + target
    	requ = requests.get(uRl)
    except:
    	Log.info3(errormsgreq)
    try:
    	response = requ.content.decode('utf-8')
    except:
    	Log.info3(errormsgreq)
    if 'Search result for' in response:
	    if re.search(match, response):
	        for i in re.findall(match, response):
	            Log.info1(i[0])
    elif 'Nothing was found' in response:
	    Log.info2('No Subdomains Found For This : '+ target)
    else:
	    Log.info3('No Subdomains Found For This : '+ target)


#-----------------------------------RECO RobotTxt ---------------------------------
def RECORobot(target):
    	print(R + '---------------------------------------------------')
    	Log.info('Robots.txt Finder :' + W )
    	print(R + '---------------------------------------------------')
	try:
	 	req = requests.get(target)
	 	UTC = req.url
    	except:
        	Log.info2('Error on getting responce')
        	sys.exit(1)
        url_ = UTC + "/robots.txt" 
	try:
		requ = requests.get(url_)
		request = requ.content.decode('utf-8')
	except:
	    	Log.info3(errormsgreq)
        try:
		if 'User-agent' in request:
			if len(request) != 5:
		            list = request.strip("").split("\n")
		            for inks in list:
		                if len(inks) != 0:
		                    Log.info1(inks)
		else:
			Log.info3('No Robots.txt Found For This : '+ target)
        except:
            Log.info3(errormsgreq)

#-----------------------------------RECO Honeypot Detector----------------------------
def RECOHoneypot(ip):
    	print(R + '---------------------------------------------------')
    	Log.info('Honeypot Detector :' + W )
    	print(R + '---------------------------------------------------')
	URLINK = "https://api.shodan.io/labs/honeyscore/" + ip + "?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by"
	try:
		requ = requests.get(URLINK)
		request = requ.content.decode('utf-8')
	except:
	    	Log.info3(errormsgreq)	
        try:	
		probability = str(float(request) * 10)
		if float(request) < 0.5:
			Log.info1("Honeypot Percent : " + probability)
		else:
			Log.info3("Honeypot Percent : " + probability)
        except:
            Log.info3(errormsgreq)
#-----------------------------------OS Finger Printing-------------------------------
def RECOOSprinting(ip):
	print(R + '---------------------------------------------------')
    	Log.info('OS Finger Printing :' + W )
    	print(R + '---------------------------------------------------')
	try:	
		nm_scanner=nmap.PortScanner()
		nm_scan=nm_scanner.scan(ip,'80',arguments='-O')	
        except Exception as e:
		Log.info3(errormsgreq + str(e)) 
	try:
		Log.info1("The host is : "+ nm_scan['scan'][ip]['status']['state'])
	except:
		Log.info3("errormsgreq")
	try:
		Log.info1("Port 80 is : "+ nm_scan['scan'][ip]['tcp'][80]['state'])
	except:
		Log.info3("errormsgreq")
	try:
		Log.info1("Scanning method is : "+nm_scan['scan'][ip]['tcp'][80]['reason'])
	except:
		Log.info3("errormsgreq")
	
	try:
		Log.info1("Predicted Operating System is : "+nm_scan['scan'][ip]['osmatch'][0]['osclass'][0]['osfamily'])
	except:
		Log.info3("Predicted Operating System is : No OS matches for host")
	
	try:
		Log.info1("OS Prediction percentage is : "+nm_scan['scan'][ip]['osmatch'][0]['accuracy'])
	except:
		Log.info3("OS Prediction percentage is : Null because No OS matches for host")


#-----------------------------------Port Scanner --------------------------------------
def RECOPortScanner(ip):
	nm_scanner = nmap.PortScanner()
	print(R + '---------------------------------------------------')
    	Log.info('Port Scanner :' + W )
    	print(R + '---------------------------------------------------')
	try:
            nm_scanner.scan(ip)
            ports = nm_scanner[ip]['tcp'].keys()
            for port in ports:
                state = nm_scanner[ip]['tcp'][port]['state']
                service = nm_scanner[ip]['tcp'][port]['name']
                product = nm_scanner[ip]['tcp'][port]['product']
		name = nm_scanner[ip]['tcp'][port]['name']
		extrainfo = nm_scanner[ip]['tcp'][port]['extrainfo']
		reason = nm_scanner[ip]['tcp'][port]['reason']
		version = nm_scanner[ip]['tcp'][port]['version']
		conf = nm_scanner[ip]['tcp'][port]['conf']
                if state == 'open':
                    	Log.info1("Open port : "+str(port))
			Log.info1("State : "+str(state))
			Log.info1("Service : "+str(service))
			Log.info1("Product : "+str(product))
			Log.info1("Name : "+str(name))
			Log.info1("Extrainfo : "+str(extrainfo))
			Log.info1("Reason : "+str(reason))
			Log.info1("Version : "+str(version))
			Log.info1("Conf : "+str(conf)+"\n")		
        except:
            Log.info3(errormsgreq) 
#-----------------------------------main start --------------------------------------
if __name__ == '__main__':
    try:
        IPchk()       
    #keyboardinterrrupt handler
    except KeyboardInterrupt:
        Log.info3(keybordexcpt)
        sys.exit(1)
    except Exception as inst:
            Log.info1( 'Exception in __name__ == __main__ function')
            sys.exit(1)
    
