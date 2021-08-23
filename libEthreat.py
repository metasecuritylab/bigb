# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libConfig
import requests
import os

DIR = libConfig.GetConfig('ET', 'dir')
emerging_block_ips = libConfig.GetConfig('ET', 'emerging-block-ips')
compromised_ips = libConfig.GetConfig('ET', 'compromised-ips')
