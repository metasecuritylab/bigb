# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libConfig

CTAS_SVR = libConfig.GetConfig('CTAS', 'URL')

def GetClassType(data):
    ClassType = []

    for item in data:
        if item['classtype'] == None:
            ClassType.append('none')
        else:
            ClassType.append(item['classtype'])

    return list(set(ClassType))