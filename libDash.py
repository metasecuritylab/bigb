# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import requests
import libConfig
import yaml
import libUtils
from datetime import datetime

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
    except requests.exceptions.RequestException as e:
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

def UpdateThreatInfo(Pnum=0, MLnum=0, BIPnum=0, IIPnum=0, Tasknum=0, Traffic=0, EIPnum=0, init=False):
    items = [
        {"label": "Task(Day)", "value": Tasknum},
        {"label": "Playbook Model", "value": Pnum},
        {"label": "AI/ML Model", "value": MLnum},
        {"label": "Traffic", "value": Traffic},
        {"label": "Inspected IP", "value": IIPnum},
        {"label": "Blacklist IP", "value": BIPnum},
        {"label": "Excluded IP", "value": EIPnum},
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
        data['value'] = 0

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
    InitTimeline()

    return True

def GetTimeline():
    fname = 'dashboard/timeline_data.yml'
    with open(fname) as f:
        ret = yaml.load(f, Loader=yaml.FullLoader)

    return ret

def InitTimeline():
    fname = 'dashboard/timeline_data.yml'
    data = {}
    data['events'] = [{"name":'Exit', "date":'Dec 31, 2023', "background": 'lightblue'}]

    with open(fname, 'w') as f:
        yaml.dump(data, f)

    return True

def SetTimeline(event):
    fname = 'dashboard/timeline_data.yml'

    data = GetTimeline()
    data['events'].append(event)

    with open(fname, 'w') as f:
        yaml.dump(data, f)

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
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateProcessing', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateProcessing', ret)

    message = "Hello"
    ret = UpdateMessage(message)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateMessage', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateMessage', ret)

    ret = UpdateWarning(items)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateWarning', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateWarning', ret)

    ret = UpdateCritical(items)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateCritical', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateCritical', ret)

    value = 10
    ret = UpdateTaskProgress(value)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateTaskProgress', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateTaskProgress', ret)

    Pnum = 1
    MLnum = 1
    BIPnum = 12
    IIPnum = 10
    Tasknum = 30
    Traffic = 10
    EIPnum = 10

    ret = UpdateThreatInfo(Pnum, MLnum, BIPnum, IIPnum, Tasknum, Traffic, EIPnum)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateThreatInfo', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateThreatInfo', ret)

    done = 2
    ready = 1
    ret = UpdateTaskChart(done, ready)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateTaskChart', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateTaskChart', ret)

    event1 = {"name":"event1", "date":"Thu, 7 May 2021", "background": "red"}
    event2 = {"name":"event2", "date":"Thu, 6 May 2021", "background": "yellow"}
    event3 = {"name":"event3", "date":"Thu, 5 May 2021", "background": "white"}
    event = [event1, event2, event3]
    ret = UpdateTimeline(event)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateTimeline', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateTimeline', ret)

    criticals = 0
    warnings = 0

    ret = UpdateSecurityLevel(criticals, warnings)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateSecurityLevel', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateSecurityLevel', ret)
    
    criticals = 2
    warnings = 2
    status = "yellow"
    ret = UpdateSecurityLevelV2(criticals, warnings, status)
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'UpdateSecurityLevelV2', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'UpdateSecurityLevelV2', ret)

    ret = ClearDashBoard()
    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'ClearDashBoard', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'ClearDashBoard', ret)

    InitTimeline()

    event = {"name":"red", "date":"Thu, 1 Sep 2021", "background": "red"}
    ret = SetTimeline(event)
    event = {"name":"orange", "date":"Thu, 2 Sep 2021", "background": "orange"}
    ret = SetTimeline(event)
    event = {"name":"yellow", "date":"Thu, 3 Sep 2021", "background": "yellow"}
    ret = SetTimeline(event)
    event = {"name":"green", "date":"Thu, 4 Sep 2021", "background": "green"}
    ret = SetTimeline(event)
    event = {"name":"blue", "date":"Thu, 5 Sep 2021", "background": "blue"}
    ret = SetTimeline(event)
    event = {"name":"violet", "date":"Thu, 6 Sep 2021", "background": "violet"}
    ret = SetTimeline(event)
    event = {"name":"cyan", "date":"Thu, 7 Sep 2021", "background": "cyan"}
    ret = SetTimeline(event)
    event = {"name":"black", "date":"Thu, 8 Sep 2021", "background": "black"}
    ret = SetTimeline(event)
    event = {"name":"pink", "date":"Thu, 9 Sep 2021", "background": "pink"}
    ret = SetTimeline(event)
    event = {"name":"#e0440e", "date":"Thu, 10 Sep 2021", "background": "#e0440e"}
    ret = SetTimeline(event)
    event = {"name":"#e6693e", "date":"Thu, 11 Sep 2021", "background": "#e6693e"}
    ret = SetTimeline(event)
    event = {"name":"#ec8f6e", "date":"Thu, 12 Sep 2021", "background": "#ec8f6e"}
    ret = SetTimeline(event)
    event = {"name":"#f6c7b6", "date":"Thu, 13 Sep 2021", "background": "#f6c7b6"}
    ret = SetTimeline(event)

    if ret:
        libUtils.UnitTestPrint(True, 'libDash', 'SetTimeline', ret)
    else:
        libUtils.UnitTestPrint(False, 'libDash', 'SetTimeline', ret)

    return True
