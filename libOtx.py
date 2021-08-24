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