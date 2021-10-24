# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import time
import datetime
import signal
import sys
import random
import libConfig
import libElastic
import libEthreat
import libCtas
import libDash
import libUtils
import libOtx
import libJira
import libDemo
import libPlaybook
import libVirustotal


def signal_handler(sig, frame):
    print('BYE~')
    sys.exit(0)


def GetLastProcessingList(data, maxLen=8):
    while True:
        if len(data) <= maxLen:
            break
        else:
            del data[0]

    return data


def ListDeduplication(fIP, Value, List):
    for item in List:
        if item['label'] == fIP and item['value'] == Value:
            return True

    return False


def ConvTimeStamp(Task):
    # Task is date-time
    sDate = "{} {}".format(Task, (libConfig.GetConfig('DETECTION', 'STIME')))
    sEpoch = libElastic.ConvEpoch(sDate)
    eDate = "{} {}".format(Task, (libConfig.GetConfig('DETECTION', 'ETIME')))
    eEpoch = libElastic.ConvEpoch(eDate)
    text = "Task date: {}({}) - {}({})".format(sDate, sEpoch, eDate, eEpoch)

    return sDate, eDate


def CalcProgressValue(total, done):
    if done == 0:
        pValue = 0
    elif done == total:
        pValue = 100
    else:
        pValue = round(done / total * 100, 1)

    return pValue

fsleep = True
sleeptime = 1
fdemo = True
fjira = True
frdata = True
fwdata = False
aimlcnt = 0
playbook_cnt = 7

def playbook01():

    while True:
        signal.signal(signal.SIGINT, signal_handler)

        libDash.ClearDashBoard()
        if fsleep:
            time.sleep(sleeptime)

        data = libPlaybook.GetData('playbook01')
        blackip = libEthreat.GetBlackListFromET()
        plist = []
        wlist = []
        clist = []

        if fdemo:
            libUtils.InfoPrint("Start in DEMO mode")
            task_list = libDemo.GetTaskList()
            #task_list = task_list[:2]
        else:
            task_list = libConfig.GetTasks()

        #libUtils.InfoPrint("Get threat information")

        for task_done, task in enumerate(task_list):
            text = "Task {} is started.".format(task)
            libUtils.InfoPrint(text)
            warning_num = 0
            critical_num = 0
            data['info']['task'] = task
            task_ready = len(task_list)-task_done

            libDash.UpdateSecurityLevel(criticals=critical_num, warnings=warning_num)
            if fsleep:
                time.sleep(sleeptime)
            libDash.UpdateTaskChart(done=task_done, ready=task_ready)
            if fsleep:
                time.sleep(sleeptime)
            libDash.UpdateMessage(message=text)
            if fsleep:
                time.sleep(sleeptime)

            s_date, e_date = ConvTimeStamp(task)
            text = "Please wait for gathering data. It takes few minutes"
            libUtils.InfoPrint(text)

            libDash.UpdateMessage(message=text)
            if fsleep:
                time.sleep(sleeptime)

            if fdemo:
                fname = 'playbook01-{}'.format(task)
                f_ip_list, f_ip_hits = libDemo.GetTrafficFromDATA(fname)
                data = libDemo.GetData(fname)
                #task = data['info']['task']
            else:
                # f_ip_list, f_ip_hits = libDemo.GetTrafficYML(task_done)
                f_ip_list, f_ip_hits = libElastic.GetIPsFromElastic(s_date, e_date, 'DST')
                data['traffic']['dst'] = f_ip_list
                if fjira:
                    data['traffic']['excludedip'] = libJira.GetExcludedIP()

            task_split = task.split('-')
            task_conv_date = datetime.date(int(task_split[0]), int(task_split[1]), int(task_split[2]))
            date = task_conv_date.strftime("%a %d %b %Y")

            excluded_ip = data['traffic']['excludedip']
            len_f_ip_list = len(data['traffic']['dst'])

            if len_f_ip_list == 0:
                text = 'No logs, please check log repository!'
                libUtils.InfoPrint(text)
                libDash.UpdateMessage(message=text)
                time.sleep(600)
                continue

            HfIPHits = libUtils.ConvHumanFormat(f_ip_hits)
            libDash.UpdateThreatInfo(Pnum=playbook_cnt, MLnum=aimlcnt, BIPnum=len(blackip),
                                     IIPnum=len_f_ip_list, Tasknum=len(task_list), Traffic=HfIPHits,
                                     EIPnum=len(excluded_ip))
            if fsleep:
                time.sleep(sleeptime)

            text = "Inspected IP: {}, Volume: {}".format(len_f_ip_list, HfIPHits)
            libUtils.InfoPrint(text)

            libDash.UpdateMessage(message=text)
            if fsleep:
                time.sleep(sleeptime)

            i = 0
            for fIP, v in data['traffic']['dst'].items():
                i = i + 1
                libDash.UpdateTaskProgress(int(100 * i / len_f_ip_list))
                libUtils.printProgressBar(i,len_f_ip_list,"completed","[INFO]")
                if i == len_f_ip_list:
                    print('')

                if not fdemo:
                    data['data'][fIP] = {}

                bypass = 0
                cOTX = 0
                cWINS = 0
                cET = 0

                plist = GetLastProcessingList(plist)
                wlist = GetLastProcessingList(wlist)
                clist = GetLastProcessingList(clist)
                # print('fip: {}, critical: {}, warning: {}'.format(fIP, len(clist),len(wlist)))

                # 1. Checking Excluded
                if fIP in excluded_ip:
                    bypass = bypass + 1
                    plist.append({'label': fIP, 'value': "Bypass excluded traffic"})
                    data['data'][fIP]['excludedip'] = 'True'

                # 2. Checking Private IP
                if libUtils.IsPrivateIP(fIP):
                    bypass = bypass + 1
                    plist.append({'label': fIP, 'value': "Bypass internal traffic"})
                    data['data'][fIP]['privateip'] = 'True'

                if bypass > 0:
                    libDash.UpdateProcessing(plist)
                    continue

                # 3. OTX lookup
                if not fdemo:
                    retLookupOTX, dataOTX = libOtx.LookupIp(fIP)
                else:
                    retLookupOTX = {'pulse_info_cnt': 0, 'reputation': 0}
                    for k, v in data['data'][fIP].items():
                        if k == 'otx':
                            retLookupOTX = {'pulse_info_cnt': v['pulse_info']['count'],'reputation': v['reputation']}
                            dataOTX = v

                if retLookupOTX['pulse_info_cnt']:
                    cOTX += 1
                    data['data'][fIP]['otx'] = dataOTX

                # 4. Wins lookup
                if not fdemo:
                    retLookupCTAS, dataCTAS = libCtas.LookupIp(fIP)
                else:
                    retLookupCTAS = 0
                    for k, v in data['data'][fIP].items():
                        if k == 'ctas':
                            dataCTAS = v
                            retLookupCTAS = 1

                if retLookupCTAS > 0:
                    cWINS += 1
                    data['data'][fIP]['ctas'] = dataCTAS

                # 5. Emerging threat lookup
                for BIP in blackip:
                    if BIP['ip'] == fIP:
                        cET += 1
                        data['data'][fIP]['emergingthreat'] = {'result':'True', 'ref':BIP['ref']}

                # POST PROCESSING
                if cOTX + cWINS + cET < 1:
                    plist.append({'label': fIP, 'value': 'OK'})
                    libDash.UpdateProcessing(plist)
                    if fsleep:
                        time.sleep(sleeptime)
                    continue

                warning_num += 1
                text = ''
                if cOTX > 0:
                    text = text + 'Threat Score: {}'.format(retLookupOTX['pulse_info_cnt'])
                if cWINS > 0:
                    text = text + ', ' + 'KISA: Found'
                if cET > 0:
                    text = text + ', ' + 'ET: Found'

                wlist.append({'label': fIP, 'value': text})

                if cOTX + cWINS + cET > 1:
                    # 6. Virustotal
                    if not fdemo:
                        retlookupvt, dataVT = libVirustotal.LookupIp(fIP)
                        data['data'][fIP]['virustotal'] = dataVT

                    color = ['red', 'orange', 'yellow', 'green', 'blue', 'violet', 'cyan', 'black', 'pink', '#e0440e']
                    color_num = random.randrange(0, len(color))
                    event = {"name": fIP, "date": date, "background": color[color_num]}
                    libDash.SetTimeline(event)

                    if len(clist) < 1:
                        critical_num += 1
                        clist.append({'label': fIP, 'value': 'Suspicious'})
                        libDash.UpdateCritical(clist)
                        message = "Checking {} now.".format(fIP)
                    else:
                        if not ListDeduplication(fIP, 'Suspicious', clist):
                            critical_num += 1
                            clist.append({'label': fIP, 'value': 'Suspicious'})
                            libDash.UpdateCritical(clist)
                            message = "Checking {} now.".format(fIP)
                        else:
                            message = "Checking {} now.".format(fIP)

                    libDash.UpdateMessage(message=message)
                    if fsleep:
                        time.sleep(sleeptime)
                    # libSlack.SendSlack(criticalNum, warningNum, fIP, mOTX, mWINS, mET)

                libDash.UpdateWarning(wlist)
                if fsleep:
                    time.sleep(sleeptime)

                plist.append({'label': fIP, 'value': 'Analysing'})
                libDash.UpdateProcessing(plist)
                if fsleep:
                    time.sleep(sleeptime)

                libDash.UpdateSecurityLevel(criticals=critical_num, warnings=warning_num)
                if fsleep:
                    time.sleep(sleeptime)

            if fwdata:
                filename = 'playbook01-{}'.format(task)
                libDemo.PutData(filename, data)

            if fjira:
                libJira.Playbook01(data)

            message = 'Task {} is finished.'.format(task)
            libDash.UpdateMessage(message=message)
            if fsleep:
                time.sleep(sleeptime)

if __name__ == "__main__":
    playbook01()