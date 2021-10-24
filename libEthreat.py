# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import requests
import os
import libConfig
import libUtils

DIR = libConfig.GetConfig('ET', 'DIR')
emerging_block_ips = libConfig.GetConfig('ET', 'emerging-block-ips')
compromised_ips = libConfig.GetConfig('ET', 'compromised-ips')

def Download(url, file_name):
    with open(file_name, "wb") as file:
        response = requests.get(url)
        file.write(response.content)

    return True

def ParseETRules(fname):
    bucket = list()
    filename = "{}/{}".format(DIR, fname)
    ret = os.path.isfile(filename)

    if not ret:
        return False

    with open(filename, 'r') as fdata:
        lines = fdata.readlines()
        for line in lines:
            if len(line) > 1:
                if line[0] != '#':
                    bucket.append({'ip': line.strip('\n'), 'ref': fname})

    return bucket

def GetETRules():
    filename = "{}/emerging-block-ips.txt".format(DIR)
    if not Download(emerging_block_ips, filename):
        return False

    filename = "{}/compromised-ips.txt".format(DIR)
    if not Download(compromised_ips, filename):
        return False

    return True

def GetBlackListFromET():
    black_list = list()
    ret = ParseETRules("emerging-block-ips.txt")
    if not ret:
        return black_list

    black_list.extend(ret)
    ret = ParseETRules("compromised-ips.txt")
    if not ret:
        return black_list

    black_list.extend(ret)

    return black_list

def DetectEmergingThreats(address):
    maliciousIPs = GetBlackListFromET()
    if not maliciousIPs:
        return False

    for mip in maliciousIPs:
        if mip['ip'] == address:
            return mip

    return False

def UnitTest():
    ret = GetETRules()
    if ret:
        libUtils.UnitTestPrint(True, 'libEthreat', 'GetETRules', ret)
    else:
        libUtils.UnitTestPrint(False, 'libEthreat', 'GetETRules', ret)

    ret = GetBlackListFromET()
    if len(ret):
        libUtils.UnitTestPrint(True, 'libEthreat', 'GetBlackListFromET', len(ret))
    else:
        libUtils.UnitTestPrint(False, 'libEthreat', 'GetBlackListFromET', len(ret))
