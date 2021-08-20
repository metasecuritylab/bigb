# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import requests
import json
import libConfig

SERVER = libConfig.GetConfig('DASHBOARD', 'HOST')
PORT = libConfig.GetConfig('DASHBOARD', 'PORT')
TIMEOUT = libConfig.GetConfig('DASHBOARD', 'TIMEOUT')
api_key = libConfig.GetConfig('DASHBOARD', 'API_KEY')

def CommFront(URI, data):
    API = [
        "securitylevel",
        "taskprogress",
        "task",
        "message",
        "processing",
        "threatinfo",
        "securitylevelv2",
        "warninglist",
        "criticallist",
        "test",
        "timeline"
    ]

    if not URI in API:
        return False

    URL = "{}:{}/widgets/{}".format(SERVER, PORT, URI)

    try:
        requests.post(URL, json=data, timeout=int(TIMEOUT))
        # 버전에 따라서 다른가 보네
    except:
        return False

    return True

def UpdateTimeline(event, init=False):
    if init:
        event = []

    data = {"auth_token": api_key, "events": event}
    ret = CommFront("timeline", data)

    return ret

def UpdateWarning(wlist=[], init=False):
    if init:
        wlist = []

    data = {"auth_token": api_key, "items": wlist}
    ret = CommFront("warninglist", data)

    return ret

def UpdateCritical(clist=[], init=False):
    if init:
        clist = []

    data = {"auth_token": api_key, "items": clist}
    ret = CommFront("criticallist", data)

    return ret

def UpdateThreatInfo(UMcnt=0, AMcnt=0, BIPcnt=0, Tcnt=0, Traffic=0, WIPcnt=0, init=False):
    items = [
        {"label": "Estimation Model", "value": UMcnt},
        {"label": "AI/ML Model", "value": AMcnt},
        {"label": "Task(Day)", "value": Tcnt},
        {"label": "Inspect Traffic", "value": Traffic},
        {"label": "Black IP", "value": BIPcnt},
        {"label": "White IP", "value": WIPcnt}
    ]

    if init:
        items = []

    data = {"auth_token": api_key, "items": items}
    ret = CommFront("threatinfo", data)

    return ret

def UpdateSecurityLevel(criticals=0, warnings=0, init=False):
    data = {
        "auth_token": api_key,
        "criticals": int(criticals),
        "warnings": int(warnings)
    }

    if init:
        data['error'] = "No data"

    ret = CommFront("securitylevel", data)

    return ret

def UpdateTaskProgress(value=0, init=False):
    data = {
        "auth_token": api_key,
        "value": value
    }

    if init:
        del data['value']

    ret = CommFront("taskprogress", data)

    return ret

def UpdateTaskChart(done: object = 0, ready: object = 0, init=False):
    datasets = [
        {
            "data": [done, ready],
            "backgroundColor": ["#F7464A", "#46BFBD"],
            "hoverBackgroundColor": ["#FF6384", "#36A2EB"]
        }
    ]

    if init:
        datasets = []

    data = {"auth_token": api_key, "labels": ["Done", "Ready"], "datasets": datasets}
    ret = CommFront("task", data)

    return ret

def UpdateMessage(message="", init=False):
    if init:
        message = "NO DATA"

    data = {"auth_token": api_key, "text": message}
    ret = CommFront("message", data)

    return ret

def UpdateProcessing(items=[], init=False):

    if init:
        items = []

    data = {"auth_token": api_key, "unordered": "True", "items": items}
    ret = CommFront("processing", data)

    return ret

def UpdateSecurityLevelV2(criticals, warnings, status, init=False):
    data = {
        "auth_token": api_key,
        "criticals": criticals,
        "warnings": warnings,
        "status": status
    }

    if init:
        data = {}

    ret = CommFront("securitylevelv2", data)

    return ret

def ClearDashBoard():

    UpdateProcessing(init=True)
    UpdateMessage(init=True)
    UpdateWarning(init=True)
    UpdateCritical(init=True)
    UpdateTaskProgress(init=True)
    UpdateThreatInfo(init=True)
    UpdateTaskChart(init=True)
    UpdateSecurityLevel(init=True)

    return True

def CheckDash():

    url = '{}'.format(SERVER)

    try:
        res = requests.get(url)
        if res.status_code == 200:
            return True
    except requests.ConnectionError as exception:
        return False

    return False

def UnitTest():

    item1 = {"label":"1.1.1.1", "value":"OK"}
    item2 = {"label":"2.2.2.2", "value":"Analysing"}
    item3 = {"label":"3.3.3.3", "value":"BIP"}
    items = [item1, item2, item3]
    ret = UpdateProcessing(items)
    if ret:
        text = '[UnitTest:LibDash:UpdateProcessing] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateProcessing] FAIL : {}'.format(ret)

    print(text)

    message = "Hi, My name is suwonchon"
    ret = UpdateMessage(message)
    if ret:
        text = '[UnitTest:LibDash:UpdateMessage] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateMessage] FAIL : {}'.format(ret)

    print(text)

    ret = UpdateWarning(items)
    if ret:
        text = '[UnitTest:LibDash:UpdateWarning] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateWarning] FAIL : {}'.format(ret)

    print(text)

    ret = UpdateCritical(items)
    if ret:
        text = '[UnitTest:LibDash:UpdateCritical] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateCritical] FAIL : {}'.format(ret)

    print(text)

    value = 10
    ret = UpdateTaskProgress(value)
    if ret:
        text = '[UnitTest:LibDash:UpdateTaskProgress] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateTaskProgress] FAIL : {}'.format(ret)

    print(text)

    ValueOfEmodel = 1
    ValueOfMLmodel = 1
    DayOfTask = 12
    ValueOfTraffic = 10
    CountOfBIP = 30
    CountOfWIP = 10

    ret = UpdateThreatInfo(ValueOfEmodel, ValueOfMLmodel, CountOfBIP, DayOfTask, ValueOfTraffic, CountOfWIP)
    if ret:
        text = '[UnitTest:LibDash:UpdateThreatInfo] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateThreatInfo] FAIL : {}'.format(ret)

    print(text)

    done = 2
    ready = 1
    ret = UpdateTaskChart(done, ready)
    if ret:
        text = '[UnitTest:LibDash:UpdateTaskChart] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateTaskChart] FAIL : {}'.format(ret)

    print(text)

    event1 = {"name":"event1", "date":"Thu, 7 May 2020 09:54:51 +0000", "background": "red"}
    event2 = {"name":"event2", "date":"Thu, 6 May 2020 09:54:51 +0000", "background": "yellow"}
    event3 = {"name":"event3", "date":"Thu, 5 May 2020 09:54:51 +0000", "background": "white"}
    event = [event1, event2, event3]
    ret = UpdateTimeline(event)
    if ret:
        text = '[UnitTest:LibDash:UpdateTimeline] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateTimeline] FAIL : {}'.format(ret)

    print(text)

    criticals = 0
    warnings = 0

    ret = UpdateSecurityLevel(criticals, warnings)
    if ret:
        text = '[UnitTest:LibDash:UpdateSecurityLevel] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateSecurityLevel] FAIL : {}'.format(ret)

    print(text)

    criticals = 2
    warnings = 2
    status = "yellow"
    ret = UpdateSecurityLevelV2(criticals, warnings, status)
    if ret:
        text = '[UnitTest:LibDash:UpdateSecurityLevelV2] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateSecurityLevelV2] FAIL : {}'.format(ret)

    print(text)

    ret = ClearDashBoard()
    if ret:
        text = '[UnitTest:LibDash:UpdateSecurityLevelV2] SUCCESS : {}'.format(ret)
    else:
        text = '[UnitTest:LibDash:UpdateSecurityLevelV2] FAIL : {}'.format(ret)

    print(text)

    return True