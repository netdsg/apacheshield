#!/usr/bin/python3

maxErrorAllowed = 1
apacheAccessLog = '/var/log/apache2/access.log'
whiteListFile = 'apacheWhiteList.txt'
clientErrorHash = 'clientErrorHash.json'
blockCodes = ['400', '401', '404']

import time, json, re, subprocess, hashlib, os, pprint
from pygtail import Pygtail

def checkWhiteList(whiteListFile, seenWhiteFileSum):
    if os.path.isfile(whiteListFile):
        nowWhiteFileSum = hashlib.md5(open(whiteListFile, 'rb').read()).hexdigest()
        if nowWhiteFileSum != seenWhiteFileSum:
            ourWhiteFile = open(whiteListFile, 'r')
            rawWhiteList = ourWhiteFile.read()
            ourWhiteFile.close()
            whiteList = rawWhiteList.splitlines()
            for i in whiteList:
                if i in errorHash:
                    del errorHash[i]
            return whiteList, nowWhiteFileSum
        else:
            return 'noChange', nowWhiteFileSum
    else:
        touchWhiteFile = subprocess.getoutput(['touch ' + whiteListFile])
        nowWhiteFileSum = hashlib.md5(open(whiteListFile, 'rb').read()).hexdigest()
        return [], nowWhiteFileSum
        
def applyBlocking(clientIP):
    if errorHash[clientIP] >= maxErrorAllowed and clientIP not in blockedSet:
        applyRule = subprocess.getoutput(['iptables -A INPUT -s ' + clientIP + ' -j DROP'])
        blockedSet.add(clientIP)

def initFirewall(phase):
    iptablesList = [
    'iptables -F',
    'iptables -P FORWARD DROP',
    'iptables -P INPUT   ACCEPT',
    'iptables -P OUTPUT  ACCEPT',
    ]
    for r in iptablesList:
        applyRule = subprocess.getoutput([r])
    if phase == 'whiteListMaint':
        for clientIP in blockedSet:
            if clientIP not in whiteList:
                applyRule = subprocess.getoutput(['iptables -A INPUT -s ' + clientIP + ' -j DROP'])
    if phase == 'scriptStart':
        for clientIP in errorHash:
            if errorHash[clientIP] >= maxErrorAllowed and clientIP not in whiteList:
                blockedSet.add(clientIP)
                applyRule = subprocess.getoutput(['iptables -A INPUT -s ' + clientIP + ' -j DROP'])

blockedSet = set()

# get errorHash
if os.path.isfile(clientErrorHash):
    with open(clientErrorHash) as ourJson:
        errorHash = json.load(ourJson)
else:
    errorHash = {}

whiteList, seenWhiteFileSum = checkWhiteList(whiteListFile, 'null')

initFirewall('scriptStart')

# main loop
while True:
    time.sleep(1)
    updateNeeded  = 0
    for l in Pygtail(apacheAccessLog):
        logMatch = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s-\s-\s\[.+\]\s\".+\"\s(\d+)\s\d+\s', l)
        if logMatch:
            clientIP = logMatch.group(1)
            htmlCode = logMatch.group(2)
            if htmlCode in blockCodes and clientIP not in whiteList:
                if clientIP not in errorHash:
                    errorHash[clientIP] = 1
                else:
                    errorHash[clientIP] +=1
                updateNeeded = 1
                applyBlocking(clientIP)
        else:
            print('!!! Did not match parser !!! - : ' + l)
        if updateNeeded == 1:
            with open(clientErrorHash, 'w') as ourJson:
                json.dump(errorHash, ourJson)
    candWhiteList, seenWhiteFileSum = checkWhiteList(whiteListFile, seenWhiteFileSum)
    if candWhiteList != 'noChange':
        whiteList = candWhiteList
        initFirewall('whiteListMaint')

