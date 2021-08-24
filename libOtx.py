# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

from OTXv2 import OTXv2
import libTypes
import libConfig
import libUtils
import hashlib
import json

API_KEY = libConfig.GetConfig('OTX', 'API_KEY')
URL = libConfig.GetConfig('OTX', 'URL')
OTX = OTXv2(API_KEY, server=URL)

def getValue(results, keys):
    if type(keys) is list and len(keys) > 0:

        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

def hostname(otx, hostname):
    alerts = []
    result = otx.get_indicator_details_by_section(libTypes.HOSTNAME, hostname, 'general')

    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    alerts.append('In pulse: ' + pulse['name'])

    result = otx.get_indicator_details_by_section(libTypes.DOMAIN, hostname, 'general')
    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    alerts.append('In pulse: ' + pulse['name'])

    return alerts

def ip(otx, ip, section='general'):
    # section = general, geo, reputation, url_list, passive_dns, malware, nids_list, http_scans
    data = {'ref':'OTX', 'section':None, 'response':None}

    try:
        result = otx.get_indicator_details_by_section(libTypes.IPv4, ip, section)
    except:
        return False

    if section == 'general':
        # response.status = 400, response.text = {"detail": "IP is private."}
        data['section'] = section
        data['response'] = result
        return data

    if section == 'reputation':
        # response.status = 200, response.text = {"reputation": null}
        if not result[section]:
            return False

        data['section'] = section
        data['response'] = result[section]
        return data

    return False

def url(otx, url):
    alerts = []
    result = otx.get_indicator_details_full(libTypes.URL, url)

    google = getValue(result, ['url_list', 'url_list', 'result', 'safebrowsing'])
    if google and 'response_code' in str(google):
        alerts.append({'google_safebrowsing': 'malicious'})

    clamav = getValue(result, ['url_list', 'url_list', 'result', 'multiav', 'matches', 'clamav'])
    if clamav:
        alerts.append({'clamav': clamav})

    avast = getValue(result, ['url_list', 'url_list', 'result', 'multiav', 'matches', 'avast'])
    if avast:
        alerts.append({'avast': avast})

    # Get the file analysis too, if it exists
    has_analysis = getValue(result, ['url_list', 'url_list', 'result', 'urlworker', 'has_file_analysis'])
    if has_analysis:
        hash = getValue(result, ['url_list', 'url_list', 'result', 'urlworker', 'sha256'])
        file_alerts = file(otx, hash)
        if file_alerts:
            for alert in file_alerts:
                alerts.append(alert)

    # Todo: Check file page

    return alerts

def file(otx, hash):
    alerts = []

    hash_type = libTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = libTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = libTypes.FILE_HASH_SHA1

    result = otx.get_indicator_details_full(hash_type, hash)

    avg = getValue(result, ['analysis', 'analysis', 'plugins', 'avg', 'results', 'detection'])
    if avg:
        alerts.append({'avg': avg})

    clamav = getValue(result, ['analysis', 'analysis', 'plugins', 'clamav', 'results', 'detection'])
    if clamav:
        alerts.append({'clamav': clamav})

    avast = getValue(result, ['analysis', 'analysis', 'plugins', 'avast', 'results', 'detection'])
    if avast:
        alerts.append({'avast': avast})

    microsoft = getValue(result,
                         ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', 'Microsoft',
                          'result'])
    if microsoft:
        alerts.append({'microsoft': microsoft})

    symantec = getValue(result,
                        ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', 'Symantec',
                         'result'])
    if symantec:
        alerts.append({'symantec': symantec})

    kaspersky = getValue(result,
                         ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'virustotal', 'scans', 'Kaspersky',
                          'result'])
    if kaspersky:
        alerts.append({'kaspersky': kaspersky})

    suricata = getValue(result, ['analysis', 'analysis', 'plugins', 'cuckoo', 'result', 'suricata', 'rules', 'name'])
    if suricata and 'trojan' in str(suricata).lower():
        alerts.append({'suricata': suricata})

    return alerts

def LookupIp(ip):
    alerts = []
    ret = {'pulse_info_cnt': 0, 'reputation': 0}

    if libUtils.IsPrivateIP(ip):
        return alerts

    try:
        result = OTX.get_indicator_details_by_section(libTypes.IPv4, ip, 'general')
        if len(result['validation']):
            for i in result['validation']:
                if 'source' in i:
                    if i['source'] == 'whitelist':
                        ret['pulse_info_cnt'] = 0
                        ret['reputation'] = 0
                        return ret

        ret['pulse_info_cnt'] = result['pulse_info']['count']
        ret['reputation'] = result['reputation']
    except Exception:
        ret['pulse_info_cnt'] = 0
        ret['reputation'] = 0
        return ret

    '''
    if ret['reputation']:
        text = 'ip: {}, reputation; {}, count: {}'.format(ip, result['reputation'], result['pulse_info']['count'])
        print(text)
    '''
    return ret

def LookupHost(hostname):
    alerts = hostname(OTX, hostname)
    if len(alerts) > 0:
        retStr = "{}".format(alerts)
    else:
        retStr = "Unknown or not identified as malicious"

    return retStr

def LookupUrl(url):
    alerts = url(OTX, url)
    if len(alerts) > 0:
        retStr = "{}".format(alerts)
    else:
        retStr = "Unknown or not identified as malicious"

    return retStr

def LookupHash(hash):
    alerts = file(OTX, hash)
    if len(alerts) > 0:
        retStr = "{}".format(alerts)
    else:
        retStr = "Unknown or not identified as malicious"

    return retStr

def LookupFile(file):
    hash = hashlib.md5(open(file, 'rb').read()).hexdigest()
    alerts = file(OTX, hash)
    if len(alerts) > 0:
        retStr = "{}".format(alerts)
    else:
        retStr = "Unknown or not identified as malicious"

    return retStr
    
def UnitTest():
    ip = '216.58.197.174'
    ip = '216.239.32.21'
    ip = '151.101.194.133'
    ip = '23.227.38.64'
    ip = '52.114.133.60'
    ret = {'pulse_info_cnt': 0, 'reputation': 0}
    retVal = LookupIp(ip)
    text = '[UnitTest:LibOTX:LookupIp] SUCCESS : {}'.format(retVal)
    print(text)

    try:
        result = OTX.get_indicator_details_by_section(libTypes.IPv4, ip, 'general')
        '''
        print(json.dumps(result, indent=4, sort_keys=True))
        print(ip)
        print(len(result['validation']))
        '''

        if len(result['validation']):
            ret['pulse_info_cnt'] = 0
            ret['reputation'] = 0
            for i in result['validation']:
                if 'source' in i:
                    if i['source'] == 'whitelist':
                        print(i['source'])
                        print(ret)
                        print("CLEAN")
                        exit()

        ret['pulse_info_cnt'] = result['pulse_info']['count']
        ret['reputation'] = result['reputation']
        text = '[UnitTest:LibOTX:OTXv2] SUCCESS : pulse_info_cnt: {}, reputation: {}'.format(ret['pulse_info_cnt'], ret['reputation'])
        print(text)

    except Exception as e:
        text = '[UnitTest:LibOTX:OTXv2] FAIL : Exception!!'
        print(text)
        ret['pulse_info_cnt'] = 0
        ret['reputation'] = 0

    if ret['reputation']:
        text = '[UnitTest:LibOTX:OTXv2] SUCCESS : ip: {}, reputation; {}, count: {}'.format(ip, ret['reputation'], ret['pulse_info']['count'])
        print(text)