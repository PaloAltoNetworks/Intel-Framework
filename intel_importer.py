#!/home/blevene/anaconda/bin/python

#Intel Puller + Loader Script, to be run daily as a cronjob
#by: Brandon Levene
#Version: 2

from pyes import *
from datetime import datetime
import re
import json
import os
import sys
import urllib
import os.path
import pandas as pd
import numpy as np
from elasticsearch import Elasticsearch
from tld import get_tld
import logging

#Logging
logging.basicConfig(level=logging.INFO, 
    format='%(asctime)s %(message)s', 
    filename='/home/blevene/intel_import.log')

#My directory for raw intel
os.chdir(os.path.expanduser("~") + "/Documents/IntelAnalysis/")

# regex for functions
ip_match = re.compile(r'^[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}$')
md5_match = re.compile(r'^[0-9A-Fa-f]{32}$')

# ES Data
index_name = "threat-intel"
conn = ES('127.0.0.1:9200', timeout=20.0)

# Loader for ES Data
def data_loader(tipe, column, source, category):
    #format = "%Y-%m-%dT%H:%M:%S%z"
    counter = 0
    for row in column:
        if bool(re.findall(ip_match, str(row))):
            data = {
                    "@timestamp":datetime.utcnow(),
                    "_type":tipe,
                    "ip addresses": {
                                    "ip":column[counter],
                                    "feeds": {
                                            "source":source,
                                            "category":category
                                                }
                                         }
                        }    
            counter += 1
            conn.index(data,"function-test",tipe, bulk=False)
            
            #[debug]print data
        elif bool(re.findall(md5_match, str(row))):
            data = {
                    #"@timestamp":datetime.utcnow().strftime(format)
                    "@timestamp":datetime.utcnow(),
                    "_type":tipe,
                    "hashes": {
                                "domain":column[counter],
                                "feeds": {
                                        "source":source,
                                        "category":category
                                        }
                                }
                        }
            counter += 1
            conn.index(data,"function-test",tipe, bulk=False)
            
            #[debug]print data
        else:
            data = {
                    "@timestamp":datetime.utcnow(),
                    "_type":tipe,
                    "domains": {
                                "domain":column[counter],
                                "feeds": {
                                        "source":source,
                                        "category":category
                                         }
                                }
                    }
            counter += 1
            conn.index(data,"function-test",tipe, bulk=False)
            #[debug]print data
			#try:
			# push the data to ES
			
			#except:
				#print "There was an error importing this data."
				#pass

def clean_mx_data_loader(tipe, column, source, category, uri):
    #format = "%Y-%m-%dT%H:%M:%S%z"
    counter = 0
    for row in column:
        if bool(re.findall(ip_match, str(row))):
            data = {
                    "@timestamp":datetime.utcnow(),
                    "_type":tipe,
                    "ip addresses": {
                                    "ip":column[counter],
                                    "feeds": {
                                            "source":source,
                                            "category":category
                                                }
                                         }
                        }    
            counter += 1
            conn.index(data,"function-test",tipe, bulk=False)
            
            print data
        elif bool(re.findall(md5_match, str(row))):
            data = {
                    #"@timestamp":datetime.utcnow().strftime(format)
                    "@timestamp":datetime.utcnow(),
                    "_type":tipe,
                    "hashes": {
                                "domain":column[counter],
                                "feeds": {
                                        "source":source,
                                        "category":category
                                        }
                                }
                        }
            counter += 1
            conn.index(data,"function-test",tipe, bulk=False)
            
            print data
        else:
            data = {
                    "@timestamp":datetime.utcnow(),
                    "_type":tipe,
                    "domains": {
                                "domain":column[counter],
                                "feeds": {
                                        "source":source,
                                        "category":category,
                                        "uri":uri[counter]
                                         }
                                }
                    }
            counter += 1
            #[debug]print data
            conn.index(data,"function-test",tipe, bulk=False)
				
# if an input doesn't have shitty formatting, I can just use this.
def into_pandas(infile, df):
	df = pd.read_csv(infile, header=None)
	df.columns = ['Indicator']
	df['Indicator_Type'] = ""
	df['Source'] = np.nan
	frame = df
	return frame 
    
#zeustracker domains
#https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
zeusURL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"

zeusData = "data/zeusdomains"
urllib.urlretrieve(zeusURL, filename=zeusData)

zeusdomains = pd.read_csv(zeusData, header=None, skiprows=6)

#I want to organize by Indicator, Indicator_Type, and Source so I'll need to create these columns + headers
zeusdomains.columns = ['Indicator']

#zeustracker IPs 
#https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist

zeusIP = "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
zeusIPdata = "data/zeusips"
urllib.urlretrieve(zeusIP, zeusIPdata)

zeusips = pd.read_csv(zeusIPdata, header=None, skiprows=6)

zeusips.columns = ['Indicator']

#blocklist.de ips
Downloads_Dir = 'data'

for url in open('tmp/blocklistde'):
    name = url.rsplit('/', 2)[2].rsplit('.',1)[0]
    
    filename = os.path.join(Downloads_Dir, name)
    #[debug]print filename
    
    urllib.urlretrieve(url, filename)
#import the blocklist.de ips into pandas
bots = into_pandas('data/bots', "bots")
ftp = into_pandas('data/ftp', "ftp")
imap = into_pandas('data/imap', "imap")
pop3 = into_pandas('data/pop3', "pop3")
ssh = into_pandas('data/ssh', "ssh")

#ciarmy.com ips
#http://www.ciarmy.com/list/ci-badguys.txt

url = "http://www.ciarmy.com/list/ci-badguys.txt"
name = "data/cibadguys"    
urllib.urlretrieve(url, name)
cibad = into_pandas('data/cibadguys', "cibad")

#emergingthreats ips
#http://rules.emergingthreats.net/blockrules/compromised-ips.txt
url = "http://rules.emergingthreats.net/blockrules/compromised-ips.txt"
name = "data/etcompromised"
urllib.urlretrieve(url, name)
etcompromised = into_pandas('data/etcompromised', 'etcompromised')

#malc0de
#http://malc0de.com/bl/IP_Blacklist.txt
url = "http://malc0de.com/bl/IP_Blacklist.txt"
name = "data/malc0deips"
urllib.urlretrieve(url,name)
# This one has a few more spaces at the top, so I need to manually import it
malc0deips = pd.read_csv('data/malc0deips', header=None, skiprows=4)
malc0deips.columns = ['Indicator']
# grab http://malc0de.com/bl/BOOT
url = "http://malc0de.com/bl/BOOT"
name = "data/malc0deboot"
urllib.urlretrieve(url, name)
# This one has some formatting stuff and has a space seperator
malc0deboot = pd.read_csv('data/malc0deboot', header=None, skiprows=6, sep=" ")
malc0deboot.columns = ['crud', 'Indicator', 'ignore']

# vxvault last 100, it may be worth doing this one hourly in a seperate script.
url = "http://vxvault.siri-urz.net/URL_List.php"
name = "data/vxvault"
urllib.urlretrieve(url, name)

#parse vxvault
maldomains = []
for line in open('data/vxvault'):
    try:
        name = get_tld(line)
        maldomains.append(name)
    except:
        pass
#deduplicate the contents of the list generated in the previous loop
maldomains_dedup = list(set(maldomains))
#pop the data into a dataframe
from pandas import *

vxdomains = DataFrame(maldomains_dedup)
vxdomains.columns = ['Indicator']

# Attempting to parse XML from http://support.clean-mx.de/clean-mx/xmlviruses.php?
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
    
url = "http://support.clean-mx.de/clean-mx/xmlviruses.php?"
name = "data/cleanmx.xml"
urllib.urlretrieve(url, name)

tree = ET.ElementTree(file="data/cleanmx.xml")

root = tree.getroot()
root.tag, root.attrib

# Grab the md5 hashes
hashes = []

for element in root.iter("md5"):
    hashes.append(element.text)

#Grab the ips
ips = []

for element in root.iter("ip"):
    ips.append(element.text)
    
    
# Grab URLs
urls = []

for element in root.iter("url"):
    urls.append(element.text)

# Split the tld and URI
domains = []
uris = []
for line in urls:
    try:
        name = get_tld(line)
        uri = line.split(name)[1]
        domains.append(name)
        uris.append(uri)
    except:
        pass
# import the new rows
from pandas import *
clean_mx_1 = DataFrame(domains)
clean_mx_1.columns = ['domain']
clean_mx_2 = DataFrame(uris)
clean_mx_2.columns = ['uri']

clean_mx_final = merge(clean_mx_1, clean_mx_2, left_index=True, right_index=True, how='inner')

# grab shadowserver info
url = "http://www.shadowserver.org/ccfull.php"
data = "data/shadowserver"
urllib.urlretrieve(url, data)
try:
	shadowserver = pd.read_csv('data/shadowserver', header=None, sep=":")
	shadowserver.columns = ['Indicator', 'Port', 'Reverse_DNS', 'ASN', 'Country']
except:
	pass

#Nathan Fowler's data
#https://www.packetmail.net/iprep.txt
url = "https://www.packetmail.net/iprep.txt"
name = "data/iprep"
urllib.urlretrieve(url, name)
nfowlerrep = pd.read_csv('data/iprep', header=None, skiprows=30, sep=';')
nfowlerrep.columns = ['Indicator', 'last_seen', 'context', 'cumulative_history']

#dataloaders
data_loader("ip", zeusips.Indicator, "zeustracker.abuse.ch", "malware")
data_loader("domain", zeusdomains.Indicator, "zeustracker.abuse.ch", "malware")
data_loader("ip", bots.Indicator, "blocklist.de", "malware")
data_loader("ip", ftp.Indicator, "blocklist.de", "scanner")
data_loader("ip", imap.Indicator, "blocklist.de", "scanner")
data_loader("ip", pop3.Indicator, "blocklist.de", "scanner")
data_loader("ip", ssh.Indicator, "blocklist.de", "scanner")
data_loader("ip", cibad.Indicator, "ciarmy.com", "malicious")
data_loader("ip", etcompromised.Indicator, "emergingthreats", "compromised_host")
data_loader("ip", malc0deips.Indicator, "malc0de.com", "malware")
data_loader("domain", malc0deboot.Indicator, "malc0de.com", "malware")
data_loader("domain", vxdomains.Indicator, "vxvault", "malware")
data_loader("ip", nfowlerrep.Indicator, "packetmail_iprep", "scanner")
clean_mx_data_loader("domain", clean_mx_final.domain, "cleanmx.de", "malware", clean_mx_final.uri)
try:
    data_loader("ip", shadowserver.Indicator, "shadowserver", "c2")
except:
    pass



