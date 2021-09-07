# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import configparser
import datetime
import libUtils

ConfName = 'config/config.ini'
config = configparser.ConfigParser()

def UpdateConfig(section, key, value):
    config = configparser.ConfigParser()
    config.read(ConfName)

    if section not in config.sections():
        return False

    config.set(section, key, value)

    with open(ConfName, 'w') as configfile:
        config.write(configfile)

    return True

def GetConfig(section, key):
    config = configparser.ConfigParser()
    config.read(ConfName)

    if section not in config.sections():
        return False

    if key == 'DAY':
        return config.get(section, key)

    return config.get(section, key)

def GetTasks():
    index = list()
    day = int(GetConfig('DETECTION', 'DURATION'))
    today = datetime.date.today()

    for i in range(day):
        strIndex = today - datetime.timedelta(days=i)
        nowDate = strIndex.strftime('%Y-%m-%d')
        index.append(nowDate)

    return index

def UnitTest():
    section = 'DETECTION'
    key = 'DURATION'
    value = '12'
    ret_A = UpdateConfig(section, key, value)
    if ret_A:
        libUtils.UnitTestPrint(True, 'libConfig', 'UpdateConfig', value)
    else:
        libUtils.UnitTestPrint(False, 'libConfig', 'UpdateConfig', value)

    ret_B = GetConfig(section, key)
    if ret_B:
        libUtils.UnitTestPrint(True, 'libConfig', 'GetConfig', value)
    else:
        libUtils.UnitTestPrint(False, 'libConfig', 'GetConfig', value)