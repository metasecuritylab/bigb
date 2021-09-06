# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import os
import random

DIR = 'demo'
FNAME = 'bambenek_banjori.ipset'

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

def GetTraffic(stat_done):
    fw_dst_hits = 0
    filename = "{}/{}".format(DIR, FNAME)
    fw_dst_ip = ParseRules(filename)
    if not fw_dst_ip:
        return {}, 0

    for i, v in fw_dst_ip.items():
        fw_dst_hits = fw_dst_hits + v

    print(fw_dst_hits)
    return fw_dst_ip, fw_dst_hits
