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

def LookupIp(address):
    ret = ['none']

    if libUtils.IsPrivateIP(address):
        return ret

    IP_Search_URL = '{}/model/multi_search_data.php?model=ip_search'.format(URL)
    raw_data = '-----------------------------237611620126405\n' \
               'Content-Disposition: form-data; name="multi_search"\n\n{}' \
               '\n-----------------------------237611620126405--'.format(address)
    headers = {'Content-Type': "multipart/form-data; boundary=---------------------------237611620126405",
               'Referer': 'https://securecast.co.kr'}

    try:
        ret = requests.post(IP_Search_URL, data=raw_data, headers=headers, timeout=3)
    except Exception as e:
        return ret

    if ret.status_code != 200:
        return ret

    try:
        data = json.loads(ret.text)
    except:
        return ret

    ParsedData = ParseData(data, address)
    ret = GetClassType(ParsedData)
    return ret

def CheckCtas():

    try:
        res = requests.get(URL)
        if res.status_code == 200:
            return True
    except requests.ConnectionError as exception:
        return False

    return False

def UnitTest():
    ret = CheckCtas()
    if ret:
        libUtils.UnitTestPrint(True, 'libCtas', 'CheckCtas', ret)
    else:
        libUtils.UnitTestPrint(False, 'libCtas', 'CheckCtas', ret)

    IP = '8.8.8.8'
    data = LookupIp(IP)
    if data[0] == 'exploit':
        libUtils.UnitTestPrint(True, 'libCtas', 'LookupIp', data[0])
    else:
        libUtils.UnitTestPrint(False, 'libCtas', 'LookupIp', data[0])

    return True
