# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
import libConfig
import libUtils
import json
import requests

URL = libConfig.GetConfig('VIRUSTOTAL', 'URL')
API_KEY = libConfig.GetConfig('VIRUSTOTAL', 'API_KEY')

VT = VirusTotalAPIIPAddresses(API_KEY)

def LookupIp(address):
    try:
        result = VT.get_report(address)
    except:
        return False
    else:
        if VT.get_last_http_error() == VT.HTTP_OK:
            result = json.loads(result)
            result = json.dumps(result, sort_keys=False, indent=4)

        else:
            return False

    return True

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

    return True
