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
    UpdateConfig(section, key, value)
    retValue = GetConfig(section, key)

    if retValue == value:
        text = "[UnitTest:LibConfig] SUCCESS : The set value({}) is the same as the set value({})".format(value, retValue)
    else:
        text = "[UnitTest:LibConfig] FAIL : : The set value({})  is different from the set value({})".format(value, retValue)

    print(text)