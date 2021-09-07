# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import elasticsearch
import libConfig
import libUtils
import datetime
import libDsl
import warnings
warnings.filterwarnings("ignore")

NSS_ELK_URL = libConfig.GetConfig('NSS_ELASTIC', 'URL')
NSS_ELK_API_ID = libConfig.GetConfig('NSS_ELASTIC', 'API_ID')
NSS_ELK_API_KEY = libConfig.GetConfig('NSS_ELASTIC', 'API_KEY')
SYS_ELK_URL = libConfig.GetConfig('SYS_ELASTIC', 'URL')
PAY_ELK_URL = libConfig.GetConfig('PAY_ELASTIC', 'URL')

def CheckELK(URL):
    try:
        elasticsearch.Elasticsearch(URL, timeout=30, max_retries=10, retry_on_timeout=True)
    except:
        print('connection fail for ElasticSearch')
        return False

    return True

def ConvEpoch(dt):
    try:
        str_dt = datetime.datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
        epoch_dt = int(str_dt.timestamp()) * 1000
    except:
        return False

    return epoch_dt

def MakeTimeWindows(start, end):
    windows = 100000
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)
    wDate = list()
    sTime = sEpoch
    eTime = 0

    while True:
        if eTime == eEpoch:
            break

        eTime = sTime + windows
        if eTime > eEpoch:
            eTime = eEpoch

        text = {'start': sTime, 'end': eTime}
        wDate.append(text)
        sTime = eTime + 1

    return wDate

def GetAggSearch(index, url, body, key=None):
    try:
        es_client = elasticsearch.Elasticsearch(url, api_key=key, verify_certs=False, timeout=30,
                                                max_retries=10, retry_on_timeout=True)
    except:
        print('connection fail for ElasticSearch')
        return False, 0

    res = es_client.search(index=index, body=body)

    return res

def GetListSearch(index, url, body):
    retVal = []
    _KEEP_ALIVE_LIMIT = '30s'
    size = 100

    try:
        es_client = elasticsearch.Elasticsearch(url, verify_certs=False, timeout=30, max_retries=10,
                                                retry_on_timeout=True)
    except:
        print('connection fail for ElasticSearch')
        return False, 0

    res = es_client.search(index=index, scroll=_KEEP_ALIVE_LIMIT, size=size, body=body)
    if res['hits']['total']['value'] < 1:
        return retVal

    sid = res['_scroll_id']
    fetched = len(res['hits']['hits'])
    for i in range(fetched):
        retVal.append(res['hits']['hits'][i]['_source']['message'])

    while (fetched > 0):
        res = es_client.scroll(scroll_id=sid, scroll=_KEEP_ALIVE_LIMIT)
        fetched = len(res['hits']['hits'])
        for i in range(fetched):
            retVal.append(res['hits']['hits'][i]['_source']['message'])

    return retVal

def GetTargetListFromElastic(index, start, end, tIP, side):
    # Call API

    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)
    windows = [100, 500, 1000, 1500, 2000]

    try:
        es_client = elasticsearch.Elasticsearch(NSS_ELK_URL, timeout=30, max_retries=10, retry_on_timeout=True)
    except:
        return False, 0

    sum_other_doc_count = 10
    for item in windows:
        if sum_other_doc_count < 1:
            break

        if side == 'src':
            body = libDsl.GetIPsByTarget(sEpoch, eEpoch, Lhits=0, Laggs=item, dstip=tIP, srcip=None)
        elif side == 'dst':
            body = libDsl.GetIPsByTarget(sEpoch, eEpoch, Lhits=0, Laggs=item, dstip=None, srcip=tIP)
        else:
            return False, 0

        response = es_client.search(index=index, body=body)
        sum_other_doc_count = response['aggregations']['data']['sum_other_doc_count']

    if sum_other_doc_count > 1:
        return False, 0

    bucket = response['aggregations']['data']['buckets']

    return bucket, len(bucket)


def GetIPsFromElastic(start, end, side=None):
    # Call playbook
    if not side:
        return {}, 0

    try:
        es_client = elasticsearch.Elasticsearch(NSS_ELK_URL, api_key=(NSS_ELK_API_ID, NSS_ELK_API_KEY),
                                                verify_certs=False, timeout=30, max_retries=1, retry_on_timeout=True)
    except:
        return {}, 0

    dst = {}
    hits = 0
    size = 10000
    windows = MakeTimeWindows(start, end)
    for item in windows:
        body = libDsl.GetIPsBySide(item['start'], item['end'], Lhits=0, Laggs=size, side=side)
        try:
            response = es_client.search(index='nss-fw-*', body=body)
        except:
            return {}, 0

        sum_other_doc_count = response['aggregations']['data']['sum_other_doc_count']

        if sum_other_doc_count > 0:
            print('fail to clear sum other doc count')

        for j in response['aggregations']['data']['buckets']:
            if j['key'] in dst:
                dst[j['key']] += j['doc_count']
            else:
                dst[j['key']] = j['doc_count']

    for item in dst:
        hits = hits + dst[item]

    return dst, hits


def GetLogIPS(srcip, dstip, start, end):
    retVal = []
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)

    body = libDsl.logips(srcip, dstip, sEpoch, eEpoch)
    res = GetAggSearch('ips-*', PAY_ELK_URL, body)

    if res['hits']['total']['value'] < 1:
        return retVal

    src = res['aggregations']['2']['buckets'][0]['key']
    dst = res['aggregations']['2']['buckets'][0]['3']['buckets'][0]['key']

    for event in res['aggregations']['2']['buckets'][0]['3']['buckets'][0]['4']['buckets']:
        text = "{}->{}, {}, {}".format(src, dst, event['key'], event['doc_count'])
        retVal.append(text)

    return retVal

def GetLogFW(srcip, dstip, start, end, sport=0, dport=0):
    retVal = []
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)
    body = libDsl.logfw(srcip, dstip, sEpoch, eEpoch, sport, dport)
    res = GetAggSearch('nss-fw-*', NSS_ELK_URL, body, (NSS_ELK_API_ID, NSS_ELK_API_KEY))
    if res['hits']['total']['value'] < 1:
        return retVal

    src = res['aggregations']['2']['buckets'][0]['key']
    dst = res['aggregations']['2']['buckets'][0]['5']['buckets'][0]['3']['buckets'][0]['key']

    for sport in res['aggregations']['2']['buckets'][0]['5']['buckets']:
        for dport in sport['3']['buckets'][0]['6']['buckets']:
            for action in dport['4']['buckets']:
                text = "{}:{}->{}:{} {}".format(src, sport['key'], dst, dport['key'], action['key'])
                retVal.append(text)

    return retVal

def GetLogWWW(uri, start, end):
    retVal = []
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)

    body = libDsl.logwww(uri, sEpoch, eEpoch)
    res = GetAggSearch('weblog-www-*', SYS_ELK_URL, body)

    if res['hits']['total']['value'] < 1:
        return retVal

    for status in res['aggregations']['3']['buckets']:
        for srcip in status['4']['buckets']:
            text = "{} {} {}".format(status['key'], srcip['key'], srcip['doc_count'])
            retVal.append(text)

    return retVal

def GetLogSpecial(uri, start, end):
    retVal = []
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)

    body = libDsl.logwww(uri, sEpoch, eEpoch)
    res = GetAggSearch('weblog-special-*', SYS_ELK_URL, body)

    if res['hits']['total']['value'] < 1:
        return retVal

    for status in res['aggregations']['3']['buckets']:
        for srcip in status['4']['buckets']:
            text = "{} {} {}".format(status['key'], srcip['key'], srcip['doc_count'])
            retVal.append(text)

    return retVal

def GetLogWindows(hostname, start, end):
    retVal = []
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)

    body = libDsl.logwindows(hostname, sEpoch, eEpoch)
    res = GetAggSearch('syslog-windows-*', SYS_ELK_URL, body)

    if res['hits']['total']['value'] < 1:
        return retVal

    for eventcode in res['aggregations']['2']['buckets']:
        text = "{} {}".format(eventcode['key'], eventcode['doc_count'])
        retVal.append(text)

    return retVal

def GetLogLinux(hostname, start, end):
    sEpoch = ConvEpoch(start)
    eEpoch = ConvEpoch(end)

    body = libDsl.loglinux(hostname, sEpoch, eEpoch)
    ret = GetListSearch('syslog-linux-*', SYS_ELK_URL, body)

    return ret

def UnitTest():
    libUtils.UnitTestPrint(True, 'libElastic', 'GetLogLinux', 1)