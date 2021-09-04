# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import configparser
import datetime

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
        text = "[UnitTest:LibConfig:UpdateConfig] SUCCESS : {}".format(value, ret_A)
    else:
        text = "[UnitTest:LibConfig:UpdateConfig] FAIL : {}".format(value, ret_A)
    print(text)

    ret_B = GetConfig(section, key)
    if ret_B:
        text = "[UnitTest:LibConfig:GetConfig] SUCCESS : {}".format(value, ret_B)
    else:
        text = "[UnitTest:LibConfig:GetConfig] FAIL : {}".format(value, ret_B)
    print(text)

    if value == ret_B:
        text = "[UnitTest:LibConfig:GetConfig] SUCCESS : The set value({}) is the same as the set value({})".format(value, ret_B)
    else:
        text = "[UnitTest:LibConfig:GetConfig] FAIL : The set value({})  is different from the set value({})".format(value, ret_B)
    print(text)