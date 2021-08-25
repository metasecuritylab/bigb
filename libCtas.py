# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libUtils
import requests
import json
import libConfig

URL = libConfig.GetConfig('CTAS', 'URL')

def GetClassType(data):
    ClassType = []

    for item in data:
        if item['classtype'] == None:
            ClassType.append('none')
        else:
            ClassType.append(item['classtype'])

    return list(set(ClassType))