#!/usr/bin/env python

import re
import json
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from bs4 import BeautifulSoup
from pyvirtualdisplay import Display
import csv

#---------------------- ----------------------------- -------------
# Prevent chrome browser from opening while browsing 
display = Display(visible=0, size=(800, 600))
display.start()
# Set up webdriver with chrome engine 
s=Service("/home/revo/chromedriver/chromedriver")
driver = webdriver.Chrome(service=s)
#driver = webdriver.Chrome("/home/revo/chromedriver/chromedriver")

#----------------------------------------------------------------------------

# IIoT devices manufacturing companies
iiot_list = ('Linx', 'Johnson', 'GridConnect', 'Impinj')

# ICS devices manufacturing companies
ics_list = ('GE Digital', 'Bosch', 'Siemens', 'Mitsubishi', 'Schneider', 'ABB', 'Schweitzer', 'General Electric', 'Wind River')

#test
test_list = ["firmware", "router"]

# IoT devices manufacturing companies
iot_list = ('Amazon Echo', 'Google Home', 'Verizon', 'digi', 'Particle', 'SmartCare', 'Edimax', 'ZigBee', 'Z-Wave', 'E2 Max', 'E7 Beacon', 'P1 Plus', 'August Doorbell', 'August Smart', 'Kuri Mobile', 'Belkin WeMo', 'Footbot Air', 'Nest Smoke', 'Nest T3021US', 'Philips Hue', 'Bitdefender BOX', 'Ring Doorbell', 'WeMo Insight', 'Logitech Harmony', 'Particle Photon', 'NETGEAR Orbi', 'Canary', 'Cinder', 'Nespresso Prodigio', 'Netatmo', 'Samsung SmartThings', 'Sonos', 'Wink', 'Apple Watch', 'Garmin Forerunner', 'Peloton', 'Google Cardboard', 'Samsung Gear')

embedded_systems = iiot_list+ics_list+iot_list
embedded_iot = iot_list
embedded_ics = ics_list
embedded_iiot = iiot_list

cve_id = "" # Points to the CVE where the word is found
foundCves = [] # Stores the found CVEs using the word lists

# The delimiter of CVEs in cve.txt
delim = '======================================================' 

#---------------------------------------------------------------
with open("cve.txt", "r") as file:
    lines = file.readlines()
    for i in range(0, len(lines)):
        if re.search(delim, lines[i]):
            cve_id = lines[i+1]
        for word in embedded_systems:
            if re.search("Reference:", lines[i]):
                break                   
            elif re.search(r'\b'+word+r'\b', lines[i]):
                # Store CVES in foundCves array
                foundCves.append(cve_id[6:-1])
                break

uniqFoundCves = list(dict.fromkeys(foundCves))
print(len(uniqFoundCves))


'''non_embedded = open("non_embedded.txt", "w+")
array = []
with open("filtredCVEs.txt", "r") as fcve:
    ff = fcve.readlines()
    for i in range(len(ff)):
        array.append(ff[i].strip())
    for entry in uniqFoundCves:
        if entry not in array:
            non_embedded.write(entry+'\n')'''

#======================================================================

cve_cwe_array = {} # Stors all exist {'CVE': 'CWE'} in the json file
cwes = [] # Stores the CWE of only CVEs in the uniqFoundCves list
non_exist_foundCves = [] # Stors non-defined in NVD CWEs

with open("nvdcve-1.1-2015.json", "r") as f:
    data = json.load(f)
    for i in data['CVE_Items']:
        for j in range(0, len(i['cve']['problemtype']['problemtype_data'])):
            for k in range(0, len(i['cve']['problemtype']['problemtype_data'][j]['description'])):
                # 'CVE':'CWE'
                if i['cve']['CVE_data_meta']['ID'] in uniqFoundCves:
                    cve_cwe_array[i['cve']['CVE_data_meta']['ID']] = i['cve']['problemtype']['problemtype_data'][j]['description'][k]['value']

print(len(cve_cwe_array))

'''for cve in cve_cwe_array:
    if cve in uniqFoundCves:
        exist_foundCves.append(cve)
print(len(exist_foundCves))
      
noninfo = 0
for cve in uniqFoundCves:
    try:
        cwes.append(cve_cwe_array[cve])
            if re.search('NVD', cve_cwe_array[cve]):
                noninfo += 1
    except KeyError:
        non_exist_foundCves.append(cve)
#print(len(cwes))
#print(noninfo)
#print(len(non_exist_foundCves))
      
#=======================================================================================================================================
      
with open('cve_cwe.csv', 'w+') as f:
    write =  csv.writer(f)
    for j in uniqFoundCves:
        try:
            driver.get("https://cwe.mitre.org/data/definitions/"+cve_cwe_array[j][4:]+".html")
            content = driver.page_source
            soup = (content)
            for div in soup.findAll('div', attrs={'style':'overflow:auto;'}):
                write.writerow([j, div.h2.string])
        except KeyError:BeautifulSoup
            continue
      
f.close()
      
# Let store the CVEs in an html file to make the parsing more easier
link = "https://nvd.nist.gov/vuln/detail/"
      
arraylist = []
htmlfile = open("testhtml.html", "w+")
for entry in uniqFoundCves:
    arraylist.append(entry)
      
    for value in arraylist:
    htmlfile.write('<a href='+link+value+'>'+value+'</a></br>')
      
file.close()
#=========================================================================================================================================='''