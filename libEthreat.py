# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libConfig
import requests
import os

DIR = libConfig.GetConfig('ET', 'dir')
emerging_block_ips = libConfig.GetConfig('ET', 'emerging-block-ips')
compromised_ips = libConfig.GetConfig('ET', 'compromised-ips')

def Download(url, file_name):
    with open(file_name, "wb") as file:
        response = requests.get(url)
        file.write(response.content)

    return True

def ParseETRules(fname):
    bucket = list()
    ret = os.path.isfile(fname)

    if not ret:
        return False

    with open(fname, 'r') as fdata:
        lines = fdata.readlines()
        for line in lines:
            if len(line) > 1:
                if line[0] != '#':
                    bucket.append({'ip': line.strip('\n'), 'ref': fname})

    return bucket