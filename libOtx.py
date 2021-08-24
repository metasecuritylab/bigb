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

        