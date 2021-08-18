# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import configparser

ConfName = 'config/config.ini'
config = configparser.ConfigParser()


def UpdateConfig(section, key, value):
    config = configparser.ConfigParser()
    config.read(ConfName)

    if section not in config.sections():
        log = 'no section {}-{}-{}'.format(section, key, value)
        return False

    config.set(section, key, value)

    fp = open(ConfName, "w")
    config.write(fp)
    fp.close()

    return True
    
def GetConfig(section, key):
    # Get value of section in config
    config = configparser.ConfigParser()
    config.read(ConfName)

    if section not in config.sections():
        log = 'no section {}-{}'.format(section, key)
        return False

    if key == 'DAY':
        return config.get(section, key)

    return config.get(section, key)

def UnitTest():
    section = 'DETECTION'
    key = 'DURATION'
    value = '1'
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