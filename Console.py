# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import sys
import libDash
import libUtils

options = sys.argv[1]
if options in ['-h', '--help']:
    print('Usage: python3 Console.py [OPTIOINS...]')
    print('')
    print('  -i, --init          Init Dashboard')

if options in ['-i', '--init']:
    libDash.ClearDashBoard()
    libUtils.InfoPrint("SUCCESS")
