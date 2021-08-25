# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libUtils
import requests
import json
import libConfig

URL = libConfig.GetConfig('CTAS', 'URL')

def GetClassType(data):
    ClassType = []

    for item in data:
        if item['classtype'] == None:
            ClassType.append('none')
        else:
            ClassType.append(item['classtype'])

    return list(set(ClassType))
    
def ParseData(data, address):
    outlist = []
    out = {'rules': 'none', 'classtype': 'none', 'raw': 'none'}
    signature = 'none'
    proto = 'none'
    attacker_ip = 'none'
    attacker_port = 'none'
    class_type = 'none'

    if 'res_data_attacker' in data:
        if len(data['res_data_attacker']) < 1:
            return outlist
        else:
            for item in data['res_data_attacker']:
                if 'signature' in item:
                    signature = item['signature']

                if 'proto' in item:
                    proto = item['proto']

                if 'attacker_ip' in item:
                    attacker_ip = item['attacker_ip']

                if 'attacker_port' in item:
                    attacker_port = item['attacker_port']

                if 'classtype' in item:
                    class_type = item['classtype']

                rules = "alert {} {} any -> any {} (msg: {})".format(proto, attacker_ip, attacker_port, signature)
                out['raw'] = item
                out['rules'] = rules
                out['classtype'] = class_type
                outlist.append(out)

            return outlist

    return False