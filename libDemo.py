# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import os
import random
import yaml
import libConfig
import libUtils

DIR = 'demo'
FNAME = 'bambenek_banjori.ipset'
LIMIT = libConfig.GetConfig('DEMO', 'LIMIT')

def ParseRules(fname):
    bucket = {}
    ret = os.path.isfile(fname)

    if not ret:
        return False

    with open(fname, 'r') as fdata:
        lines = fdata.readlines()
        for line in lines:
            if len(line) > 1:
                if line[0] != '#':
                    bucket[line.strip('\n')] = random.randrange(1000000,9000000)

    return bucket

def GetTrafficFile(num, limit):
    fw_dst_hits = 0
    filename = "{}/{}".format(DIR, FNAME)
    fw_dst_ip = ParseRules(filename)
    if not fw_dst_ip:
        return {}, 0

    for i, k in enumerate(fw_dst_ip.copy()):
        if i > limit-1:
            del fw_dst_ip[k]

    for i, v in fw_dst_ip.items():
        fw_dst_hits = fw_dst_hits + v

    return fw_dst_ip, fw_dst_hits

def GetTrafficYML(num):
    fname = 'demo/data.yml'
    fw_dst_ip = {}
    fw_dst_hits = 0
    with open(fname) as f:
        ret = yaml.load(f, Loader=yaml.FullLoader)

    del ret[num][int(LIMIT):]

    for i in ret[num]:
        fw_dst_ip[i] = random.randrange(1000000,9000000)

    for i, v in fw_dst_ip.items():
        fw_dst_hits = fw_dst_hits + v

    return fw_dst_ip, fw_dst_hits

def UnitTest():
    fw_dst_ip, fw_dst_hits = GetTrafficYML(1)
    if len(fw_dst_ip):
        libUtils.UnitTestPrint(True, 'libDemo', 'GetTrafficYML', len(fw_dst_ip))
    else:
        libUtils.UnitTestPrint(False, 'libDemo', 'GetTrafficYML', rlen(fw_dst_ip))    
    if fw_dst_hits:
        libUtils.UnitTestPrint(True, 'libDemo', 'GetTrafficYML', fw_dst_hits)
    else:
        libUtils.UnitTestPrint(False, 'libDemo', 'GetTrafficYML', fw_dst_hits)