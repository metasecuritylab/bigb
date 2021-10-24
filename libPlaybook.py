# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import json

def GetData(fname):
    fname = 'config/{}.json'.format(fname)
    with open(fname, "r") as json_file:
        data = json.load(json_file)
    return data

