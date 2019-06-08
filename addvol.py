# -*- coding: utf-8 -*-
#Add image in volutility by Lionel PRAT (lionel.prat9@gmail.com)
import json
import sys
import re
import os
import requests
################
#Volutility ADD#
################
urlvolutil = 'http://172.17.0.1:8080/createsession/'
urlvolcsrf = 'http://172.17.0.1:8080'
def add_vol(filename,name,description):
    #get csrf
    r1 = requests.get(urlvolcsrf)
    tokencsrf=None
    if r1.status_code == 200:
        recsrf=re.compile('<input type=\\\\\'hidden\\\\\' name=\\\\\'csrfmiddlewaretoken\\\\\' value=\\\\\'(?P<csrf>[^\']+)\\\\\'')
        for m in recsrf.finditer(str(r1.content)):
            ret=m.groupdict()
            if ret and 'csrf' in ret and ret['csrf']:
                tokencsrf=ret['csrf']
    datapost = {
      'csrfmiddlewaretoken': tokencsrf,
      'sess_name': name,
      'sess_path': '/opt/images/'+filename,
      'profile': 'AutoDetect',
      'description': description,
      'new': 'New',
      'auto_run': None 
    }
    rx = requests.post(urlvolutil, data=datapost, cookies=r1.cookies)
    if rx:
        print("Add RAM in volatility")
    else:
        print("Try to Add RAM in volatility, code return by volutility: %d" % (rx.status_code))

if len(sys.argv) != 4:
    print("Usage: ./addvol.py file name description\n")
    sys.exit(0)

add_vol(sys.argv[1],sys.argv[2],sys.argv[3])
