# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIFiles, VirusTotalAPIError
import libConfig
import libUtils
import json
import requests

URL = libConfig.GetConfig('VIRUSTOTAL', 'URL')
API_KEY = libConfig.GetConfig('VIRUSTOTAL', 'API_KEY')

vt_api_ip_addresses = VirusTotalAPIIPAddresses(API_KEY)
vt_api_files = VirusTotalAPIFiles(API_KEY)

def LookupFilehash(filehash):
    retVal = {'harmless':0, 'malicious':0}
    try:
        ret = vt_api_files.get_report(filehash)
    except VirusTotalAPIError as e:
        print(e, e.err_code)
        return {}
    else:
        if vt_api_files.get_last_http_error() == vt_api_files.HTTP_OK:
            vtdata = json.loads(ret)

        else:
            return {}

    return vtdata

def LookupIp(address):
    retVal = {'harmless':0, 'malicious':0}
    try:
        ret = vt_api_ip_addresses.get_report(address)
    except:
        return retVal
    else:
        if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
            jsonret = json.loads(ret)
            #result = json.dumps(result, sort_keys=False, indent=4)
            retVal['harmless'] = jsonret['data']['attributes']['last_analysis_stats']['harmless']
            retVal['malicious'] = jsonret['data']['attributes']['last_analysis_stats']['malicious']

        else:
            return retVal

    return retVal, jsonret

def CheckVT():
    url = '{}'.format(URL)

    try:
        res = requests.get(url)
        if res.status_code == 200:
            return True
    except:
        return False

    return False

def UnitTest():
    address = '8.8.8.8'
    ret = CheckVT()
    if ret:
        libUtils.UnitTestPrint(True, 'LibVirustotal', 'CheckVT', ret)
    else:
        libUtils.UnitTestPrint(False, 'LibVirustotal', 'CheckVT', ret)

    ret = LookupIp(address)
    if ret:
        libUtils.UnitTestPrint(True, 'LibVirustotal', 'LookupIp', ret)
    else:
        libUtils.UnitTestPrint(False, 'LibVirustotal', 'LookupIp', ret)

    filehash = '3e857094c9d89b31676477ce7d8d523f94c767f3cb0769dae99af76b3c4e004b'
    ret = lookupfilehash(filehash)

    return True