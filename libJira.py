# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libConfig
import requests
import libUtils
import logging
import json
from datetime import datetime
from dateutil.relativedelta import relativedelta
from urllib.parse import unquote
from jira import JIRA, JIRAError

logging.getLogger().setLevel(logging.ERROR)

JIRA_URL = libConfig.GetConfig('JIRA', 'URL')
USER = libConfig.GetConfig('JIRA', 'USER')
PASS = libConfig.GetConfig('JIRA', 'API_KEY')
PROJ = libConfig.GetConfig('JIRA', 'PROJECT')
EXCLUDEDIP_KEY = libConfig.GetConfig('JIRA', 'EXCLUDEDIP')
RETIREE_KEY = libConfig.GetConfig('JIRA', 'RETIREE')

# timeout을 1로 설정하면 read 오류나요
FlagTimeout = 10
FlagWarnings = False
FlagPAT = True

def CheckJIRA():
    url = '{}'.format(JIRA_URL)
    try:
        res = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(e)
    else:
        if res.status_code == 200:
            return True

    return False


def ConnJIRA(PAT=FlagPAT):

    if PAT:
        try:
            headers = JIRA.DEFAULT_OPTIONS["headers"].copy()
            headers["Authorization"] = "Bearer {}".format(PASS)
            jira = JIRA(server=JIRA_URL, options={"headers": headers})
        except:
            text = 'Fail to connect JIRA Service'
            libUtils.ErrorPrint(text)
            exit()
        else:
            if jira:
                return jira
    else:
        try:
            jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
        except:
            text = 'Fail to connect JIRA Service'
            libUtils.ErrorPrint(text)
            exit()
        else:
            if jira:
                return jira

    return None


def GetIssue(Key):
    ret = {}
    jira = ConnJIRA()
    if not jira:
        return ret
    try:
        issue = jira.issue(Key)
        ret['summary'] = issue.fields.summary
        ret['description'] = issue.fields.description
        ret['issuetype'] = issue.fields.issuetype
        ret['priority'] = issue.fields.priority
        ret['status'] = issue.fields.status
        ret['duedate'] = issue.fields.duedate
        ret['watches'] = issue.fields.watches
        ret['resolution'] = issue.fields.resolution
        ret['assignee'] = issue.fields.assignee
        ret['watches'] = issue.fields.watches.isWatching
        ret['labels'] = issue.fields.labels
    except JIRAError as e:
        print(e.status_code, e.text)

    return ret


def GetExcludedIP():
    exip = []
    jira = ConnJIRA()
    if not jira:
        return exip
    try:
        issue = jira.issue(EXCLUDEDIP_KEY)
        desc = issue.fields.description
    except:
        return exip
    else:
        str = desc.split('|')
        for ip in str:
            if libUtils.IsValidIPv4Addr(ip.strip()):
                exip.append(ip.strip())

    return exip


def GetRetiree():
    retiree = []
    jira = ConnJIRA()
    if not jira:
        return retiree
    try:
        issue = jira.issue(RETIREE_KEY)
        desc = issue.fields.description
    except:
        return retiree
    else:
        str = desc.split('|')
        for id in str:
            if id.strip():
                retiree.append(id.strip())

    rm_set = {'AD계정'}
    result = [i for i in retiree if i not in rm_set]

    return result


def UpdateIssue(Key, Data):
    jira = ConnJIRA()
    if not jira:
        return False
    try:
        issue = jira.issue(Key)
        issue.update(fields=Data)
    except JIRAError as e:
        print(e.status_code, e.text)

    return True


def GetWatcher(Key):
    ret = {}
    jira = ConnJIRA()
    if not jira:
        return ret
    try:
        issue = jira.issue(Key)
        watcher = jira.watchers(issue)
    except:
        return ret
    else:
        for i in watcher.watchers:
            # ret[i.name] = i.emailAddress
            # if it's testing.
            ret[i.displayName] = i.emailAddress

    return ret


def GetKey(TYPE, DATE, OPTION=None):
    ret = []
    jql = "summary ~ {} AND summary ~ {}".format(TYPE, DATE)
    if OPTION:
        jql = "summary ~ {} AND summary ~ {} AND summary ~ {}".format(TYPE, DATE, OPTION)

    jira = ConnJIRA()
    if not jira:
        return ret
    try:
        for issue in jira.search_issues(jql):
            ret.append(issue.key)
    except:
        return ret

    return ret


def SetWatcher(Key, Watchers):
    if not Watchers:
        return False

    jira = ConnJIRA()
    if not jira:
        return False
    try:
        issue = jira.issue(Key)
        for w in Watchers:
            jira.add_watcher(issue, w)
    except:
        return False

    return True


def GetTransitions(Key):
    ret = {}
    jira = ConnJIRA()
    if not jira:
        return False
    try:
        issue = jira.issue(Key)
        transitions = jira.transitions(issue)
        jira.transition_issue(issue, transition='Done')
        print(transitions)
    except:
        return False

    return True


def ExistIssue(ISSUETYPE, DATE, OPTION=None):
    key = None

    key = GetKey(ISSUETYPE, DATE, OPTION)
    if len(key) == 1:
        return key[0]

    if len(key) == 0:
        return None

    return key


def MakeDescPlaybook01(data):
    h1 = "h2. Analysis Overview\n\n"
    m = ""

    for i in data:
        m1 = "{{color:#de350b}}Indicator{{color}}: {}\n".format(i['indicator'])
        m2 = "{{color:#de350b}}Verdict{{color}}: {}\n".format(i['verdict'])
        m3 = "{{color:#de350b}}Reputation{{color}}: {}\n".format(i['reputation'])
        m4 = "{{color:#de350b}}ASN{{color}}: {}\n".format(i['asn'])
        m5 = "{{color:#de350b}}Location{{color}}: {}\n".format(i['location'])
        m6 = "{{color:#de350b}}Related Pulses{{color}}: {}\n".format(i['pulses'])
        m7 = "{{color:#de350b}}Related malware{{color}}: {}\n".format(i['malware'])
        m8 = "{{color:#de350b}}Last Analysis Stats{{color}}: harmless: {}, malicios: {}, suspicious: {}, undetected: {}\n".format(
            i['stat']['harmless'], i['stat']['malicious'], i['stat']['suspicious'], i['stat']['undetected'])
        t1 = "||AV Company||Result||AV Company||Result ||AV Company||Result||\n"
        cnt = 0
        div = 3
        t2 = ''

        for j, k in i['result'].items():
            end = False
            cnt = cnt + 1
            if k['result'] == 'clean':
                t2 = t2 + '|{}|(/) {}'.format(j, k['result'])
            elif k['result'] == 'malicious':
                t2 = t2 + '|{}|(-) {}'.format(j, k['result'])
            else:
                t2 = t2 + '|{}|(!) {}'.format(j, k['result'])

            if cnt == div:
                t2 = t2 + '|\n'
                cnt = 0
                end = True

        if end == False:
            t2 = t2 + '|'

        m = m + m1 + m2 + m3 + m4 + m5 + m6 + m7 + m8 + t1 + t2 + '\n----\n\n'

    desc = h1 + m

    return desc


def UpdatePlaybook01(data, key):
    desc = MakeDescPlaybook01(data)

    summary = '[PLAYBOOK-01][2021-10-01] Suspicious traffic is found'
    issuetype = {'name': 'Playbook'}  # PLAYBOOK_01, Task, Epic
    priority = {'name': 'Medium'}  # Highest, High, Medium, Low, Lowest
    assignee = {'name': 'schon'}
    data = {
        # 'summary': summary,
        'description': desc
        # 'issuetype': issuetype,
        # 'priority': priority,
        # 'assignee': assignee
    }

    ret = UpdateIssue(key, data)

    return True


def CreatePlaybook01(data, Task):
    dt = datetime.strptime(Task, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    name = 'Playbook-01'
    date = Task
    summary = '[{}][{}] Suspicious traffic is found'.format(name, date)
    desc = MakeDescPlaybook01(data)
    issuetype = {'name': 'Playbook'}
    priority = {'name': 'Medium'}  # Highest, High, Medium, Low, Lowest
    assignee = {'name': 'schon'}
    labels = [Task, name]

    data = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': issuetype,
        'priority': priority,
        'assignee': assignee,
        'labels': labels
    }

    watchers = ['schon']

    ret = CreateIssue(data, watchers)

    return True


def CreateIssue(data, watchers):
    # Project, IssueType, Summary, Attachment, DueDate, Description, Assignee,
    # Priority, Labels, Original Estimate, Remaining Estimate

    jira = ConnJIRA()
    if not jira:
        return False
    try:
        issue = jira.create_issue(fields=data)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False
    else:
        jira.transition_issue(issue, transition='Assigned')

        for w in watchers:
            jira.add_watcher(issue, w)

    return True


def GetUserInfo(user):
    jira = ConnJIRA()
    if not jira:
        return False
    try:
        info = jira.user(user)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False
    else:
        print("name: {}, email: {}, dpname: {}, active: {}".format(info.name, info.emailAddress, info.displayName,
                                                                   info.active))

    return info


def MakeDescPlaybook02(data):
    username = '-'
    event = '-'
    lastdate = '-'
    task = '-'
    result = '-'
    reason = '-'
    source = '-'
    hostname = '-'

    if 'user' in data[0]['_source']:
        username = data[0]['_source']['user']['name']
    if 'event' in data[0]['_source']:
        event = data[0]['_source']['event']['code']
        if event == 4648:
            event = "A logon was attempted using explicit credentials(4648)                 ."
        if event == 4776:
            event = "The computer attempted to validate the credentials for an account(4776)."
        if event == 4625:
            event = "An account failed to log on(4625)                                      ."
        if event == 4768:
            event = "A Kerberos authentication ticket was requested(4768)                   ."
        result = data[0]['_source']['event']['outcome']
        lastdate = data[0]['_source']['event']['created']
    if 'winlog' in data[0]['_source']:
        task = data[0]['_source']['winlog']['task']
    if 'source' in data[0]['_source']:
        ip = data[0]['_source']['source']['ip']
        port = data[0]['_source']['source']['port']
        source = '{}:{}'.format(ip, port)
    if 'host' in data[0]['_source']:
        hostname = data[0]['_source']['host']['hostname']

    m1 = "* {{color:#de350b}}Username{{color}}: :( {}(Retiree)\n".format(username)
    m2 = "||{{color:#de350b}}Event{{color}}|{}|\n".format(event)
    m3 = "||{{color:#de350b}}Last date{{color}}|{}|\n".format(lastdate)
    m4 = "||{{color:#de350b}}Task{{color}}|{}|\n".format(task)
    m5 = "||{{color:#de350b}}Result{{color}}|(-) {}|\n".format(result)
    if result == 'success':
        m5 = "||{{color:#de350b}}Result{{color}}|(/) {}|\n".format(result)
    m6 = "||{{color:#de350b}}failure.reason{{color}}|{}|\n".format(reason)
    m7 = "||{{color:#de350b}}Source{{color}}|{}|\n".format(source)
    m8 = "||{{color:#de350b}}Host.name{{color}}|{}|\n".format(hostname)
    m9 = "||{{color:#de350b}}Count{{color}}|{}|\n".format(len(data))
    m0 = "||{color:#f4f5f7}============={color}|{color:#ffffff}================================================{color}|\n\n"

    desc = m1 + m2 + m3 + m4 + m5 + m6 + m7 + m8 + m9 + m0
    return desc


def Playbook01(DATA):
    fcreate = False
    fupdate = False
    task = DATA['info']['task']

    if FlagPAT:
        try:
            headers = JIRA.DEFAULT_OPTIONS["headers"].copy()
            headers["Authorization"] = "Bearer {}".format(PASS)
            jira = JIRA(server=JIRA_URL, options={"headers": headers})
        except:
            text = 'Fail to connect JIRA Service'
            libUtils.ErrorPrint(text)
            return False
    else:
        try:
            jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False

    issuetype = 'Playbook-01'

    keys = []
    jql = "summary ~ {} AND summary ~ {}".format(issuetype, task)
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    h1 = "h2. Analysis Overview\n\n"
    m = ""

    idx = 0
    for k, v in DATA['data'].items():
        if len(v.keys()) < 3:
            continue

        '''
        if not 'otx' in v.keys():
            continue

        if not 'ctas' in v.keys():
            continue
        '''

        idx = idx + 1
        m = m + "{{color:#de350b}}Indicator{{color}}: {}\n".format(k)
        m = m + "{{color:#de350b}}Verdict{{color}}: {}\n".format('Suspicious')

        t2 = ''
        for kk, vv in v.items():
            if kk == 'otx':
                m = m + "{{color:#de350b}}Reputation{{color}}: {}\n".format(vv['reputation'])
                m = m + "{{color:#de350b}}ASN{{color}}: {}\n".format(vv['asn'])
                m = m + "{{color:#de350b}}Location{{color}}: {}, {}\n".format(vv['city'], vv['country_name'])
                m = m + "{{color:#de350b}}Related Pulses{{color}}: {}\n".format(vv['pulse_info']['count'])
                m = m + "{{color:#de350b}}Related Sections{{color}}: {}\n".format(', '.join(vv['sections']))

            if kk == 'emergingthreat':
                m = m + "{{color:#de350b}}Emerging Threats Rule{{color}}: {}, {}\n".format(vv['result'], vv['ref'])

            if kk == 'virustotal':
                i = vv['data']['attributes']['last_analysis_stats']
                m = m + "{{color:#de350b}}Last Analysis Stats{{color}}: (/) harmless: {}, (x) malicios: {}, (-) suspicious: {}, (!) undetected: {}\n".format(
                    i['harmless'], i['malicious'], i['suspicious'], i['undetected'])
                m = m + "||AV Company||Result||AV Company||Result ||AV Company||Result||\n"
                cnt = 0
                div = 3

                for j, k in vv['data']['attributes']['last_analysis_results'].items():
                    end = False
                    cnt = cnt + 1
                    if k['result'] == 'clean':
                        t2 = t2 + '|{}|(/) {}'.format(j, k['result'])
                    elif k['result'] == 'malicious':
                        t2 = t2 + '|{}|(-) {}'.format(j, k['result'])
                    else:
                        t2 = t2 + '|{}|(!) {}'.format(j, k['result'])

                    if cnt == div:
                        t2 = t2 + '|\n'
                        cnt = 0
                        end = True

                if end == False:
                    t2 = t2 + '|'

        m = m + t2 + '\n----\n\n'

    m1 = "{{panel:bgColor=#ffebe6}}*(-) Reported: {}, (/) Inspected Traffic: {}, (i) Duration: {}*{{panel}}\n".format(
        idx, len(DATA['data']), DATA['info']['task'])
    desc = h1 + m1 + m + '\n'

    dt = datetime.strptime(task, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Suspicious traffic is found'.format(issuetype, task)

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'High'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [task, issuetype]
    }

    watchers = ['schon']

    if fupdate:
        if desc == olddesc:
            libUtils.InfoPrint('Issue is not updated')
            return False
        else:
            libUtils.InfoPrint('Issue is updated now')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        libUtils.InfoPrint('Issue is created now')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    return False

def Playbook02(DATA):
    fcreate = False
    fupdate = False
    task = DATA['info']['task']

    try:
        print(JIRA_URL, USER, PASS)
        jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    issuetype = 'Playbook-02'

    keys = []
    jql = "summary ~ {} AND summary ~ {}".format(issuetype, task)
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    h1 = "h2. Analysis Overview\n\n"
    d = ''

    m = "{panel:bgColor=#ffebe6}*(-) Users: "
    # m = "* {color:#de350b}Users{color}: "

    for u, v in DATA['data'].items():
        m = m + "{}, ".format(u)
        if v['e4648']:
            d = d + MakeDescPlaybook02(v['e4648'])
        if v['e4776']:
            d = d + MakeDescPlaybook02(v['e4776'])
        if v['e4625']:
            d = d + MakeDescPlaybook02(v['e4625'])
        if v['e4768']:
            d = d + MakeDescPlaybook02(v['e4768'])

    # m = m[:len(m)-2]
    m = m + ' (/) Duration: {}*{{panel}}\n'.format(DATA['info']['task'])
    desc = h1 + m + d

    dt = datetime.strptime(task, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Suspicious retiree login attempt'.format(issuetype, task)

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'High'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [task, issuetype]
    }

    watchers = ['schon']

    if fupdate:
        if desc == olddesc:
            print('No Updated')
            return False
        else:
            print('New Updated')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        print('CREATE!!')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    return False


def Playbook03(DATA, USERID, TASK):
    fcreate = False
    fupdate = False
    task = TASK

    try:
        jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    issuetype = 'Playbook-03'

    keys = []
    jql = "summary ~ {} AND summary ~ {} AND summary ~ {}".format(issuetype, task, USERID)
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    try:
        info = jira.user(USERID)  # info.name, info.emailAddress, info.displayName, info.active
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    d = ""
    for i in DATA:
        ip = i['_source']['source']['ip']
        port = i['_source']['source']['port']
        created = i['_source']['event']['created']
        outcome = i['_source']['event']['outcome']
        reason = i['_source']['winlog']['logon']['failure']['reason']
        user = i['_source']['user']['name']

        d = d + "{{quote}}{{color:#de350b}}Date: {{color}}{}\n".format(created)
        d = d + "{{color:#de350b}}Source: {{color}}{}:{}\n".format(ip, port)
        d = d + "{{color:#de350b}}Reason: {{color}}{}\n{{quote}}\n".format(reason)

    h1 = "h2. Hello, {}\n\n".format(info.displayName)
    m1 = "There have been repeated login failures in your account.\n"
    m2 = "If you've never tried to log in, check this activity and secure your account.\n"
    m3 = "If you have any questions or need help,\n"
    m4 = "please leave a reply or feel free to contact the IS team directly at any time.\n"

    desc = h1 + m1 + d + m2 + m3 + m4

    dt = datetime.strptime(task, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Audit failed login - {}'.format(issuetype, task, info.name)

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'Medium'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [task, issuetype]
    }

    watchers = ['schon']

    if fupdate:
        if desc == olddesc:
            print('No Updated')
            return False
        else:
            print('New Updated')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        print('CREATE!!')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    return False


def Playbook04(TASK, DATA):
    fcreate = False
    fupdate = False

    try:
        jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    issuetype = 'Playbook-04'

    keys = []
    jql = "summary ~ {} AND summary ~ {}".format(issuetype, TASK)
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    h1 = "h2. Analysis Overview\n\n"
    d = ''

    for k, v in DATA['track'].items():
        ipsdata = v['data']['ipsdata']
        ipsdatalen = len(ipsdata)
        wwwdata = v['data']['wwwdata']
        wwwdatalen = len(wwwdata)
        if k == 'e1396' and ipsdatalen > 0:
            d = d + "{panel:bgColor=#ffebe6}*(-) Server Side Script File Upload(JSP)*{panel}\n"
            d = d + '* IPS ({})\n\n'.format(ipsdatalen)
        if k == 'e1397' and ipsdatalen > 0:
            d = d + "{panel:bgColor=#deebff}*(-) Server Side Script File Upload(PHP)*{panel}\n"
            d = d + '* IPS ({})\n\n'.format(ipsdatalen)
        if k == 'e1398' and ipsdatalen > 0:
            d = d + "{panel:bgColor=#e3fcef}*(-) Server Side Script File Upload(ASP)*{panel}\n"
            d = d + '* IPS ({})\n\n'.format(ipsdatalen)
        if k == 'e1247' and ipsdatalen > 0:
            d = d + "{panel:bgColor=#fefae6}*(-) Apache Tomcat DefaultServlet PUT method File upload*{panel}\n"
            d = d + '* IPS ({})\n\n'.format(ipsdatalen)
        if k == 'e3727' and ipsdatalen > 0:
            d = d + "{panel:bgColor=#eae6ff}*(-) PHP WebShell Backdoor -2*{panel}"
            d = d + '* IPS ({})\n\n'.format(ipsdatalen)

        for i, vv in enumerate(ipsdata):
            date = vv['_source']['time']
            victim = vv['_source']['Victim']
            attack_name = vv['_source']['attack_name']
            hacker = vv['_source']['Hacker']
            sport = vv['_source']['SrcPort']
            protocol = vv['_source']['Protocol']

            hexraw = vv['_source']['RawData']
            bytesraw = bytes.fromhex(hexraw[108:])
            asciiraw = bytesraw.decode("ASCII")
            rawdata = unquote(asciiraw)

            d = d + '{quote}\n'
            d = d + "{{color:#de350b}}Date{{color}}: {}\n".format(date)
            d = d + "{{color:#de350b}}Client > Server{{color}}: {}:{}  > {}:{}\n".format(hacker, sport, victim,
                                                                                         protocol)
            d = d + "{{color:#de350b}}Attack{{color}}: {}\n".format(attack_name)
            d = d + "{{color:#de350b}}Raw{{color}}: {}\n".format(rawdata)
            d = d + '{quote}\n'

        if k == 'e1396' and wwwdatalen > 0:
            d = d + '* WWW ({})\n\n'.format(wwwdatalen)
        if k == 'e1397' and wwwdatalen > 0:
            d = d + '* WWW ({})\n\n'.format(wwwdatalen)
        if k == 'e1398' and wwwdatalen > 0:
            d = d + '* WWW ({})\n\n'.format(wwwdatalen)
        if k == 'e1247' and wwwdatalen > 0:
            d = d + '* WWW ({})\n\n'.format(wwwdatalen)
        if k == 'e3727' and wwwdatalen > 0:
            d = d + "{panel:bgColor=#eae6ff}*(-) PHP WebShell Backdoor -2*{panel}"
            d = d + '* WWW ({})\n\n'.format(wwwdatalen)

        for i, vv in enumerate(wwwdata):
            date = vv['fields']['reqdate'][0]
            clientip = vv['fields']['clientip'][0]
            dstip = vv['fields']['dstip'][0]
            dstport = vv['fields']['port'][0]
            hostname = vv['fields']['host.name'][0]
            uri = vv['fields']['uri'][0]
            uriquery = vv['fields']['uriquery'][0]
            method = vv['fields']['method'][0]
            protocol = vv['fields']['version'][0]
            status = vv['fields']['status'][0]
            if i > 3:
                continue
            d = d + '{quote}\n'
            d = d + "{{color:#de350b}}Date{{color}}: {}\n".format(date)
            d = d + "{{color:#de350b}}Client > Server{{color}}: {} > {}:{}({})\n".format(clientip, dstip, dstport,
                                                                                         hostname)
            d = d + "{{color:#de350b}}Uri{{color}}: {}\n".format(uri)
            d = d + "{{color:#de350b}}Uriquery{{color}}: {}\n".format(uriquery)
            d = d + "{{color:#de350b}}Method{{color}}: {}\n".format(method)
            d = d + "{{color:#de350b}}Protocol{{color}}: {}\n".format(protocol)
            d = d + "{{color:#de350b}}Status{{color}}: {}\n".format(status)
            d = d + '{quote}\n'

    desc = h1 + d

    dt = datetime.strptime(TASK, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Suspicious file upload'.format(issuetype, TASK)

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'Medium'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [TASK, issuetype]
    }

    watchers = ['schon']

    if fupdate:

        if desc == olddesc:
            print('No Updated')
            return False
        else:
            print('New Updated')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        print('CREATE!!')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    return False


def Playbook05(TASK, DATA):
    fcreate = False
    fupdate = False

    try:
        jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    issuetype = 'Playbook-05'

    keys = []
    jql = "summary ~ {} AND summary ~ {}".format(issuetype, TASK)
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    h1 = "h2. Analysis Overview\n\n"
    d = ''

    print('fcreate: {}, fupdate: {}'.format(fcreate, fupdate))

    for i in DATA['result']:
        if i == 'e2869':
            d = d + "{{panel:bgColor=#deebff}}*(-) Directory Traversal Attack*{{panel}}\n".format(i)

        if i == 'e5108':
            d = d + "{{panel:bgColor=#deebff}}*(-) File Downloading/Viewing*{{panel}}\n".format(i)

        d = d + '* IPS ({})\n\n'.format(len(DATA[i]['data']['ipsdata']))
        for j, vv in enumerate(DATA[i]['data']['ipsdata']):
            if j > 3:
                continue

            date = vv['fields']['time'][0]
            victim = vv['_source']['Victim']
            protocol = vv['_source']['Protocol']
            hacker = vv['_source']['Hacker']
            srcport = vv['_source']['SrcPort']
            attack_name = vv['_source']['attack_name']
            risk = vv['_source']['Risk']
            device_name = vv['_source']['device_name']
            hexraw = vv['_source']['RawData']
            bytesraw = bytes.fromhex(hexraw[108:])
            asciiraw = bytesraw.decode("ASCII")
            rawdata = unquote(asciiraw)

            d = d + '{quote}\n'
            d = d + "{{color:#de350b}}Date{{color}}: {}\n".format(date)
            d = d + "{{color:#de350b}}Client > Server{{color}}: {}:{}  > {}:{}\n".format(hacker, srcport, victim,
                                                                                         protocol)
            d = d + "{{color:#de350b}}Attack{{color}}: {}\n".format(attack_name)
            d = d + "{{color:#de350b}}Raw{{color}}: {}\n".format(rawdata)
            d = d + '{quote}\n'

        cnt = 0
        for k, v in DATA[i]['data']['wwwdata'].items():
            cnt = cnt + len(v)

        d = d + '* WWW ({})\n\n'.format(cnt)
        for k, v in DATA[i]['data']['wwwdata'].items():
            for j, vv in enumerate(v):
                date = vv['fields']['reqdate'][0]
                clientip = vv['fields']['clientip'][0]
                dstip = vv['fields']['dstip'][0]
                dstport = vv['fields']['port'][0]
                hostname = vv['fields']['host.name'][0]
                uri = vv['fields']['uri'][0]
                uriquery = vv['fields']['uriquery'][0]
                method = vv['fields']['method'][0]
                protocol = vv['fields']['version'][0]
                status = vv['fields']['status'][0]
                if j > 3:
                    continue
                d = d + '{quote}\n'
                d = d + "{{color:#de350b}}Date{{color}}: {}\n".format(date)
                d = d + "{{color:#de350b}}Client > Server{{color}}: {} > {}:{}({})\n".format(clientip, dstip, dstport,
                                                                                             hostname)
                d = d + "{{color:#de350b}}Uri{{color}}: {}\n".format(uri)
                d = d + "{{color:#de350b}}Uriquery{{color}}: {}\n".format(uriquery)
                d = d + "{{color:#de350b}}Method{{color}}: {}\n".format(method)
                d = d + "{{color:#de350b}}Protocol{{color}}: {}\n".format(protocol)
                d = d + "{{color:#de350b}}Status{{color}}: {}\n".format(status)
                d = d + '{quote}\n'

    desc = h1 + d
    dt = datetime.strptime(TASK, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Account discovery attack'.format(issuetype, TASK)

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'Medium'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [TASK, issuetype]
    }

    watchers = ['schon']

    if fupdate:
        print('UPDATE!!')
        if desc == olddesc:
            print('No Updated')
            return False
        else:
            print('New Updated')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        print('CREATE!!')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    print(desc)

    return False


def Playbook06(TASK, DATA):
    fcreate = False
    fupdate = False

    try:
        jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    issuetype = 'Playbook-06'

    keys = []
    jql = "summary ~ {} AND summary ~ {}".format(issuetype, TASK)
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    h1 = "h2. Analysis Overview\n\n"
    d = ''
    d = d + "{panel:bgColor=#ffebe6}*(-) Security risk found*{panel}\n"

    for i in DATA['track']['e0001']['data']['parsedsepmdata']:
        ipaddress = i["IP Address"]
        computername = i["Computer name"]
        filepath = i["File path"]
        actualaction = i["Actual action"]
        eventtime = i["Event time"]
        groupname = i["Group Name"]
        username = i["User Name"]
        applicationhash = i["Application hash"]
        hashtype = i["Hash type"]
        applicationname = i["Application name"]
        applicationtype = i["Application type"]

        d = d + "{quote}\n"
        d = d + "{{color:#de350b}}Event time{{color}}: {}\n".format(eventtime)
        d = d + "{{color:#de350b}}IP Address{{color}}: {}\n".format(ipaddress)
        d = d + "{{color:#de350b}}Computer Name{{color}}: {}\n".format(computername)
        d = d + "{{color:#de350b}}FilePath{{color}}: {}\n".format(filepath)
        d = d + "{{color:#de350b}}Actual action{{color}}: {}\n".format(actualaction)
        d = d + "{{color:#de350b}}GroupName{{color}}: {}\n".format(groupname)
        d = d + "{{color:#de350b}}User Name{{color}}: {}\n".format(username)
        d = d + "{{color:#de350b}}Application hash{{color}}: {}\n".format(applicationhash)
        d = d + "{{color:#de350b}}Hash type{{color}}: {}\n".format(hashtype)
        d = d + "{{color:#de350b}}Application name{{color}}: {}\n".format(applicationname)
        d = d + "{{color:#de350b}}Application type{{color}}: {}\n".format(applicationtype)

        t2 = ''
        vtdata = DATA['track']['e0001']['data']['virustotal'][applicationhash]

        if vtdata:
            vtstats = vtdata["data"]["attributes"]["last_analysis_stats"]
            vtresults = vtdata["data"]["attributes"]["last_analysis_results"]

            d = d + "{{color:#de350b}}Last Analysis Stats{{color}}: (/) harmless: {}, (x) malicios: {}, (-) suspicious: {}, (!) undetected: {}\n".format(
                vtstats['harmless'], vtstats['malicious'], vtstats['suspicious'], vtstats['undetected'])
            d = d + "{quote}\n"

            d = d + "||AV Company||Result||AV Company||Result ||AV Company||Result||\n"
            cnt = 0
            div = 3

            for j, k in vtresults.items():
                end = False
                cnt = cnt + 1
                if k['result'] == 'clean':
                    t2 = t2 + '|{}|(/) {}'.format(j, k['result'][:15])
                elif k['category'] == 'malicious':
                    t2 = t2 + '|{}|(x) {}'.format(j, k['result'][:15])
                elif k['category'] == 'suspicious':
                    t2 = t2 + '|{}|(-) {}'.format(j, k['result'][:15])
                else:
                    t2 = t2 + '|{}|(!) {}'.format(j, k['result'])

                if cnt == div:
                    t2 = t2 + '|\n'
                    cnt = 0
                    end = True

            if end == False:
                t2 = t2 + '|'
        else:
            d = d + "{color:#de350b}Last Analysis Stats{color}: No Detected\n"
            d = d + "{quote}\n"

        d = d + t2 + "\n"

    desc = h1 + d
    dt = datetime.strptime(TASK, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Suspicious file upload'.format(issuetype, TASK)

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'Medium'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [TASK, issuetype]
    }

    watchers = ['schon']

    if fupdate:
        if desc == olddesc:
            print('No Updated')
            return False
        else:
            print('New Updated')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        print('CREATE!!')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    return False


def Playbook07(TASK, DATA, START):
    fcreate = False
    fupdate = False

    try:
        jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS), timeout=FlagTimeout)
    except JIRAError as e:
        print(e.status_code, e.text)
        return False

    issuetype = 'Playbook-07'

    keys = []
    jql = "summary ~ {} AND summary ~ {} AND summary ~ {}".format(issuetype, TASK, START[11:])
    for issue in jira.search_issues(jql):
        keys.append(issue.key)

    if len(keys) > 1:
        print("Duplicated Issue")
        return False

    if keys:
        fupdate = True
        issue = jira.issue(keys[0])
        olddesc = issue.fields.description
    else:
        fcreate = True

    h1 = "h2. Analysis Overview\n\n"
    d = ''

    for k, v in DATA['track']['e0002']['data'].items():
        if k == 'ips02data':
            for kk, vv in v.items():
                cnt = len(vv)
                start = DATA['info']['start']
                end = DATA['info']['end'][11:]
                hacker = kk

                d = d + "{{panel:bgColor=#ffebe6}}*(-) Hacker IP: {}, (/) Duration: {} - {}, (i) Count: {}*{{panel}}\n".format(
                    hacker, start, end, cnt)
                for i, vvv in enumerate(vv):
                    if i > 3:
                        continue

                    date = vvv['fields']['time'][0]
                    victim = vvv['_source']['Victim']
                    protocol = vvv['_source']['Protocol']
                    hacker = vvv['_source']['Hacker']
                    srcport = vvv['_source']['SrcPort']
                    attack_name = vvv['_source']['attack_name']
                    risk = vvv['_source']['Risk']
                    device_name = vvv['_source']['device_name']
                    hexraw = vvv['_source']['RawData']
                    bytesraw = bytes.fromhex(hexraw[108:])
                    asciiraw = bytesraw.decode("UTF-8")
                    rawdata = unquote(asciiraw)
                    tt = rawdata.split('https:')

                    d = d + '{quote}\n'
                    d = d + "{{color:#de350b}}Date{{color}}: {}\n".format(date)
                    d = d + "{{color:#de350b}}Client > Server{{color}}: {}:{}  > {}:{}\n".format(hacker, srcport,
                                                                                                 victim, protocol)
                    d = d + "{{color:#de350b}}Attack{{color}}: {}\n".format(attack_name)
                    d = d + "{{color:#de350b}}Raw{{color}}: {}\n".format(rawdata)
                    d = d + '{quote}\n'



    desc = h1 + d

    dt = datetime.strptime(TASK, '%Y-%m-%d')
    aftermonth = dt + relativedelta(months=1)
    duedate = aftermonth.strftime('%Y-%m-%d')
    summary = '[{}][{}] Anomaly traffic detection {}'.format(issuetype, TASK, START[11:])

    issuedata = {
        'project': {'key': PROJ},
        'summary': summary,
        'description': desc,
        'duedate': duedate,
        'issuetype': {'name': 'Playbook'},
        'priority': {'name': 'Medium'},  # Highest, High, Medium, Low, Lowest
        'assignee': {'name': 'schon'},
        'labels': [TASK, issuetype]
    }

    watchers = ['schon']

    if fupdate:
        if desc == olddesc:
            print('No Updated')
            return False
        else:
            print('New Updated')

        try:
            issue = jira.issue(keys[0])
            issue.update(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)

        return True

    if fcreate:
        print('CREATE!!')
        try:
            issue = jira.create_issue(fields=issuedata)
        except JIRAError as e:
            print(e.status_code, e.text)
            return False
        else:
            jira.transition_issue(issue, transition='Assigned')
            for w in watchers:
                jira.add_watcher(issue, w)

        return True

    return False


def UnitTest():
    ret = CheckJIRA()
    if ret:
        libUtils.UnitTestPrint(True, 'libJira', 'CheckJIRA', ret)
    else:
        libUtils.UnitTestPrint(False, 'libJira', 'CheckJIRA', ret)

    key = '{}-2'.format(PROJ)
    ret = GetWatcher(key)
    if len(ret):
        libUtils.UnitTestPrint(True, 'libJira', 'GetWatcher', ret)
    else:
        libUtils.UnitTestPrint(False, 'libJira', 'GetWatcher', ret)

    ret = GetRetiree()
    if len(ret):  # 251
        libUtils.UnitTestPrint(True, 'libJira', 'GetRetiree', len(ret))
    else:
        libUtils.UnitTestPrint(False, 'libJira', 'GetRetiree', len(ret))

    ret = GetExcludedIP()
    if len(ret):  # 32
        libUtils.UnitTestPrint(True, 'libJira', 'GetExcludedIP', len(ret))
    else:
        libUtils.UnitTestPrint(False, 'libJira', 'GetExcludedIP', len(ret))

    key = "{}-4".format(PROJ)
    Watchers = ['suwonchon']
    ret = SetWatcher(key, Watchers)
    if ret:
        libUtils.UnitTestPrint(True, 'libJira', 'SetWatcher', ret)
    else:
        libUtils.UnitTestPrint(False, 'libJira', 'SetWatcher', ret)

# UnitTest()
