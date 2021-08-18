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