# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import time
import signal
import sys
import libConfig
import libElastic
import libEthreat
import libCtas
import libDash
import libUtils
import libOtx
import libJira
import libDemo

Debug = True

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

def GetThreatInfo():
    TaskList = libConfig.GetTasks()
    BlackIP = libEthreat.GetBlackListFromET()
    UserModel = 0
    EstiModel = 7
    ExcludedIP = libJira.GetExcludedIP()

    return TaskList, BlackIP, UserModel, EstiModel, ExcludedIP

def main():
    libDash.ClearDashBoard()
    print("[INFO] Playbook01 is started, Reset the dashboard")
    plist = []
    wlist = []
    clist = []

    ''' Start of demon '''
    while True:
        signal.signal(signal.SIGINT, signal_handler)
        TaskList, BlackIP, UserModelNum, EstiModelNum, ExcludedIP = GetThreatInfo()
        print("[INFO] Get threat information")
        TaskDoneNum = 0
        TaskTotalNum = len(TaskList)
        plist = []
        wlist = []

        for Task in TaskList:
            warningNum = 0
            criticalNum = 0
            libDash.UpdateSecurityLevel(criticals=criticalNum, warnings=warningNum)
            time.sleep(1)

            text = '[INFO] Task {} is started. '.format(Task)
            print(text)
            TaskReadyNum = TaskTotalNum - TaskDoneNum
            libDash.UpdateTaskChart(done=TaskDoneNum, ready=TaskReadyNum)
            libDash.UpdateMessage(message=text)
            time.sleep(1)

            sDate, eDate = ConvTimeStamp(Task)
            text = "[INFO] Please wait for gathering data. It takes few minutes"
            print(text)
            libDash.UpdateMessage(message=text)
            time.sleep(1)
            if not Debug:
                fIPList, fIPHits = libElastic.GetIPsFromElastic(sDate, eDate, 'DST')
            else:
                print("[INFO] Start in demo mode")
                fIPList, fIPHits = libDemo.GetTraffic(TaskDoneNum)

            if len(fIPList) == 0:
                text = '[INFO] No logs, please check log repository!'
                print(text)
                libDash.UpdateMessage(message=text)
                time.sleep(10)
                continue

            HfIPList = libUtils.ConvHumanFormat(len(fIPList))
            HfIPHits = libUtils.ConvHumanFormat(fIPHits)
            libDash.UpdateThreatInfo(UMcnt=UserModelNum, AMcnt=EstiModelNum, BIPnum=len(BlackIP),
                                    Tcnt=len(TaskList), Traffic=HfIPHits, EIPnum=len(ExcludedIP))
            text = "[INFO] Inspected IP: {}, Volume: {}".format(HfIPList, HfIPHits)
            print(text)
            libDash.UpdateMessage(message=text)

            ProcessTotalNum = len(fIPList)
            ProcessDoneNum = 0
            wData = {}

            for i, fIP in enumerate(fIPList):
                if i < ProcessTotalNum-1:
                    print('.', end='')
                else:
                    print('.')

                cWhite = 0
                mWhite = ''
                cPrivate = 0
                mPrivate = ''
                cOTX = 0
                mOTX = ''
                cWINS = 0
                mWINS = ''
                cET = 0
                mET = ''

                wData[fIP] = {}
                wValue = {}

                ProcessCurrCnt = CalcProgressValue(ProcessTotalNum, ProcessDoneNum)
                libDash.UpdateTaskProgress(ProcessCurrCnt)
                plist = GetLastProcessingList(plist)
                wlist = GetLastProcessingList(wlist)
                clist = GetLastProcessingList(clist)

                # 1. Checking Excluded
                if fIP in ExcludedIP:
                    cWhite += 1
                    mWhite = "Bypass excluded traffic"
                    plist.append({'label': fIP, 'value': mWhite})
                    wValue['mWhite'] = mWhite

                # 2. Checking Private IP
                if libUtils.IsPrivateIP(fIP):
                    cPrivate += 1
                    mPrivate = "Bypass internal traffic"
                    plist.append({'label': fIP, 'value': mPrivate})
                    wValue['mPrivate'] = mPrivate

                if cWhite + cPrivate > 0:
                    ProcessDoneNum += 1
                    libDash.UpdateProcessing(plist)
                    continue

                # 3. OTX lookup
                retLookupOTX = libOtx.LookupIp(fIP)
                if retLookupOTX['pulse_info_cnt']:
                    cOTX += 1
                    mOTX = 'pulse info: {}'.format(retLookupOTX['pulse_info_cnt'])
                    wValue['mOTX'] = mOTX

                # 4. Wins lookup
                # retLookupWINS = libCtas.LookupIp(fIP)
                retLookupWINS = False
                if retLookupWINS:
                    cWINS += 1
                    conretLookupWINS = ','.join(retLookupWINS)
                    message = conretLookupWINS[:17] + (conretLookupWINS[17:] and '..')
                    mWINS = 'Threat class-type is {}'.format(message)
                    wValue['mWINS'] = mWINS

                # 5. Emerging threat lookup
                for BIP in BlackIP:
                    if BIP['ip'] == fIP:
                        cET += 1
                        mET = 'reported emerging threat'
                        wValue['mET'] = mET

                wData[fIP] = wValue
                # POST PROCESSING
                ProcessDoneNum += 1
                if cOTX + cWINS + cET < 1:
                    plist.append({'label': fIP, 'value': 'OK'})
                    libDash.UpdateProcessing(plist)
                    continue

                if cOTX > 0:
                    if len(wlist) < 1:
                        warningNum += 1
                        wlist.append({'label': fIP, 'value': mOTX})
                    else:
                        if not ListDeduplication(fIP, mOTX, wlist):
                            warningNum += 1
                            wlist.append({'label': fIP, 'value': mOTX})

                if cWINS > 0:
                    if len(wlist) < 1:
                        warningNum += 1
                        wlist.append({'label': fIP, 'value': mWINS})
                    else:
                        if not ListDeduplication(fIP, mWINS, wlist):
                            warningNum += 1
                            wlist.append({'label': fIP, 'value': mWINS})

                if cET > 0:
                    if len(wlist) < 1:
                        warningNum += 1
                        wlist.append({'label': fIP, 'value': mET})
                    else:
                        if not ListDeduplication(fIP, cET, wlist):
                            warningNum += 1
                            wlist.append({'label': fIP, 'value': cET})

                if cOTX + cWINS + cET > 1:
                    if len(clist) < 1:
                        criticalNum += 1
                        clist.append({'label': fIP, 'value': 'Suspicious'})
                        libDash.UpdateCritical(clist)
                        message = "Checking {} now.".format(fIP)
                    else:
                        if not ListDeduplication(fIP, 'Suspicious', clist):
                            criticalNum += 1
                            clist.append({'label': fIP, 'value': 'Suspicious'})
                            libDash.UpdateCritical(clist)
                            message = "Checking {} now.".format(fIP)
                        else:
                            message = "Checking {} now.".format(fIP)

                    libDash.UpdateMessage(message=message)
                    #libSlack.SendSlack(criticalNum, warningNum, fIP, mOTX, mWINS, mET)

                libDash.UpdateWarning(wlist)
                plist.append({'label': fIP, 'value': 'Analysing'})
                libDash.UpdateProcessing(plist)
                libDash.UpdateSecurityLevel(criticals=criticalNum, warnings=warningNum)

            time.sleep(1)
            ProcessCurrCnt = CalcProgressValue(ProcessTotalNum, ProcessDoneNum)
            libDash.UpdateTaskProgress(ProcessCurrCnt)
            TaskDoneNum += 1
            message = 'Task {} is finished. Next task.'.format(Task)
            libDash.UpdateMessage(message=message)

if __name__ == "__main__":
    main()
