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