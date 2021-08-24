# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libConfig
import json
import requests

url = libConfig.GetConfig('SLACK', 'TEST')
otx = libConfig.GetConfig('OTX', 'URL')
ctas = libConfig.GetConfig('CTAS', 'URL')
vt = libConfig.GetConfig('VIRUSTOTAL', 'URL')
DASHBOARD = libConfig.GetConfig('DASHBOARD', 'REMOTE')
username = libConfig.GetConfig('SLACK', 'USER')