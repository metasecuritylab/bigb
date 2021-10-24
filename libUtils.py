# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

from pathlib import Path
import socket
import ipaddress
import hashlib
import sys

def IsPrivateIP(address):
    if ipaddress.ip_address(address).is_private:
        return True

    return False

def IsExistFile(mfile):
    file = Path(mfile)

    if file.is_file():
        return True

    return False

def Intersection(data):
    index = 0
    res = None
    for i in data:
        index += 1
        if not res:
            res = data[i]
        else:
            res = list(set(res) & set(data[i]))
        if index > len(data):
            break

    return res

def ValidAddrIPv4(address):
    parts = address.split(".")
    if len(parts) != 4:
        return False
    for item in parts:
        if item == '':
            return False
        try:
            if not 0 <= int(item) <= 255:
                return False
        except:
            return False

    return True

def IsValidIPv4Addr(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True

def IsValidIPv6Addr(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True

def ConvHumanFormat(num):
    magnitude = 0

    if type(num) != int:
        exit()

    while abs(num) >= 1000:
        magnitude += 1
        num /= 1000.0

    return '%.2f%s' % (num, ['', 'K', 'M', 'G', 'T', 'P'][magnitude])

def GetToken(text):
    if not text:
        return False

    enc = hashlib.md5()
    enc.update(text.encode('utf-8'))
    token = enc.hexdigest()

    return token

def InfoPrint(text):
    # text color code: red 31, green: 32, yellow: 33, blue: 34
    # bg color code: red 41, green: 42, yellow: 43, blue: 44
    print('\033[96m' + '[INFO] ' + '\033[0m' + text)

def ErrorPrint(text):
    print('\033[31m' + '[ERROR] ' + '\033[0m' + text)

def UnitTestPrint(flag, file, func, str):
    if flag:
        text = "\033[93m[UNITTEST]\033[0m[{}:{}] \033[96mSUCCESS\033[0m : {}".format(file, func, str)
        print(text)
    else:
        text = "\033[93m[UNITTEST]\033[0m[{}:{}] \033[101m\033[97mFAIL\033[0m : {}".format(file, func, str)
        print(text)


def printProgressBar(i,max,postText,preText):
    n_bar =40 #size of progress bar
    j= i/max
    sys.stdout.write('\r')
    sys.stdout.write(f"{preText} [{'█' * int(n_bar * j):{n_bar}s}] {int(100 * j)}%  {postText}")
    sys.stdout.flush()