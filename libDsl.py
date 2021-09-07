# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import json
import libConfig
import libUtils

OBSERVER_NAME = libConfig.GetConfig('FILTER', 'OBSERVER_NAME')

def AddMatch(key, value):
    match = {'match': {key: {'query': value}}}
    return match

def AddRange(gte, lte):
    range = {'range': {'@timestamp': {'gte': gte, 'lte': lte, 'format': 'epoch_millis'}}}
    return range

def AddTerm(field, size, order):
    term = {'terms': {'field': field, 'size': size, 'order': {'_count': order}}}
    return term

def query_get_target(gte, lte, dstip=None, srcip=None):
    query = {'query': {'bool': {'must': []}}}
    range = AddRange(gte, lte)
    query['query']['bool']['must'].append(range)
    match = AddMatch('observer.name', OBSERVER_NAME)
    query['query']['bool']['must'].append(match)

    if dstip:
        match = AddMatch('dstip', dstip)
        query['query']['bool']['must'].append(match)

    if srcip:
        match = AddMatch('srcip', srcip)
        query['query']['bool']['must'].append(match)

    return json.dumps(query)

def GetIPsBySide(gte, lte, Lhits=0, Laggs=5, side=None):
    if not side:
        return ''

    query = {'aggs': {'data': {}}, 'size': Lhits, 'query': {'bool': {'must': []}}}
    range = AddRange(gte, lte)
    query['query']['bool']['must'].append(range)

    if side == 'DST':
        term = AddTerm('destination.ip', Laggs, 'desc')
        query['aggs']['data'] = term
    elif side == 'SRC':
        term = AddTerm('source.ip', Laggs, 'desc')
        query['aggs']['data'] = term
    else:
        return ''

    match_phrase = {"match_phrase":{"observer.name": OBSERVER_NAME}}
    query['query']['bool']['must'].append(match_phrase)

    return json.dumps(query)

def GetIPsByTarget(gte, lte, Lhits=0, Laggs=5, dstip=None, srcip=None):
    if not dstip and not srcip:
        return ''

    query = {'aggs': {'data': {}}, 'size': Lhits, 'query': {'bool': {'must': []}}}

    range = AddRange(gte, lte)
    query['query']['bool']['must'].append(range)

    if dstip:
        term = AddTerm('srcip.keyword', Laggs, 'desc')
        query['aggs']['data'] = term

        match = AddMatch('dstip', dstip)
        query['query']['bool']['must'].append(match)

    if srcip:
        term = AddTerm('dstip.keyword', Laggs, 'desc')
        query['aggs']['data'] = term

        match = AddMatch('srcip', srcip)
        query['query']['bool']['must'].append(match)

    match = AddMatch('observer.name', OBSERVER_NAME)
    query['query']['bool']['must'].append(match)

    return json.dumps(query)

def logips(srcip, dstip, gte, lte):
    query = {'aggs': {
        "2": {
            "terms": {"field": "Hacker.keyword", "order": {"_count": "desc"}, "size": 5},
            "aggs": {
                "3": {
                    "terms": {"field": "Victim.keyword", "order": {"_count": "desc"}, "size": 5},
                    "aggs": {
                        "4": {"terms": {"field": "attack_name.keyword", "order": {"_count": "desc"}, "size": 20}}
                    }
                }
            }
        }
    }, 'size': 0, 'query': {
        "bool": {
            "must": [],
            "filter": [
                {"match_all": {}},
                {"match_phrase": {"Hacker": srcip}},
                {"match_phrase": {"Victim": dstip}}
            ],
            "should": [],
            "must_not": []
        }
    }}

    range = AddRange(gte, lte)
    query['query']['bool']['filter'].append(range)

    return json.dumps(query)

def logwww(uri, gte, lte):
    query = {'aggs': {
        "3": {
            "terms": {"field": "status.keyword", "order": {"_count": "desc"}, "size": 10},
            "aggs": {
                "4": {
                    "terms": {"field": "dstip.keyword", "order": {"_count": "desc"}, "size": 2000}
                }
            }
        }
    }, 'size': 0, 'query': {
        "bool": {
            "must": [],
            "filter": [
                {"match_all": {}},
                {"match_phrase": {"uri.keyword": {"query": uri}}}
            ],
            "should": [],
            "must_not": []
        }
    }}
    range = AddRange(gte, lte)
    query['query']['bool']['filter'].append(range)

    return json.dumps(query)

def logwindows(hostname, gte, lte):
    query= {'aggs': {
        "2": {
            "terms": {"field": "event.code", "order": {"_count": "desc"}, "size": 5}
        }
    }, 'size': 0, 'query': {
        "bool": {
            "must": [],
            "filter": [
                {"match_all": {}},
                {"match_phrase": {"host.name": {"query": hostname}}}
            ],
            "should": [],
            "must_not": []
        }
    }}

    range = AddRange(gte, lte)
    query['query']['bool']['filter'].append(range)

    return json.dumps(query)

def loglinux(hostname, gte, lte):
    query = {
        "aggs": {
            "2": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "30m",
                    "time_zone": "Asia/Seoul",
                    "min_doc_count": 1
                }
            }
        },
        "stored_fields": ["*"],
        "script_fields": {},
        "query": {
            "bool": {
                "must": [],
                "filter": [
                    {
                        "match_all": {}
                    },
                    {
                        "match_phrase": {
                            "host.name": {
                                "query": hostname
                            }
                        }
                    },
                    {
                        "bool": {
                            "should": [
                                {
                                    "match_phrase": {
                                        "message": "SSH2 session"
                                    }
                                }
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ],
                "should": [],
                "must_not": []
            }
        },
        "version": 'true',
        "size": 1000,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc",
                    "unmapped_type": "boolean"
                }
            }
        ],
        "_source": {
            "excludes": []
        }
    }

    range = AddRange(gte, lte)
    query['query']['bool']['filter'].append(range)

    return query

def logfw(srcip, dstip, gte, lte, sport=0, dport=0):
    if not srcip or not dstip:
       return ''

    query = {'aggs': {
        "2": {
            "terms": {"field": "source.ip", "order": {"_count": "desc"}, "size": 1},
            "aggs": {
                "5": {
                    "terms": {"field": "source.port", "order": {"_count": "desc"}, "size": 20},
                    "aggs": {
                        "3": {
                            "terms": {"field": "destination.ip", "order": {"_count": "desc"}, "size": 1},
                            "aggs": {
                                "6": {
                                    "terms": {"field": "destination.port", "order": {"_count": "desc"}, "size": 20},
                                    "aggs": {
                                        "4": {
                                            "terms": {"field": "event.type", "order": {"_count": "desc"}, "size": 10}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }, 'size': 0, 'query': {
        "bool": {
            "must": [{"match_all": {}}],
            "filter": [
                {"match_phrase": {"source.ip": {"query": srcip}}},
                {"match_phrase": {"destination.ip": {"query": dstip}}}
            ],
            "should": [],
            "must_not": []
        }
    }}

    range = AddRange(gte, lte)
    query['query']['bool']['filter'].append(range)

    if (dport > 0) and (dport < 65535):
       query['query']['bool']['filter'].append({"match_phrase": {"destination.port": {"query": str(dport)}}})

    if (sport > 0) and (sport < 65535):
       query['query']['bool']['filter'].append({"match_phrase": {"source.port": {"query": str(sport)}}})

    return json.dumps(query)

def UnitTest():
    srcip = "11.11.11.11"
    dstip = "22.22.22.22"
    sdate = "2020-11-01T15:00:00.000Z"
    edate = "2020-11-03T14:30:00.000Z"

    query = logfw(srcip, dstip, sdate, edate)
    if query:
        libUtils.UnitTestPrint(True, 'libDsl', 'logfw', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'logfw', len(query))

    dport = 80
    sport = 49430

    query = logfw(srcip, dstip, sdate, edate, sport, dport)
    if query:
        libUtils.UnitTestPrint(True, 'libDsl', 'logfw', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'logfw', len(query))

    target = '33.33.33.33'
    gte = 1576162800000
    lte = 1576249199000
    aggs_size = 5
    hits_size = 0

    query = GetIPsBySide(gte, lte, Lhits=0, Laggs=5)
    if not query:
        libUtils.UnitTestPrint(True, 'libDsl', 'GetIPsBySide', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'GetIPsBySide', len(query))

    query = GetIPsBySide(gte, lte, Lhits=0, Laggs=5, side='AA')
    if not query:
        libUtils.UnitTestPrint(True, 'libDsl', 'GetIPsBySide', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'GetIPsBySide', len(query))

    query = GetIPsBySide(gte, lte, Lhits=0, Laggs=5, side='SRC')
    if query:
        libUtils.UnitTestPrint(True, 'libDsl', 'GetIPsBySide', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'GetIPsBySide', len(query))

    query = GetIPsByTarget(gte, lte, Lhits=hits_size, Laggs=aggs_size)
    if not query:
        libUtils.UnitTestPrint(True, 'libDsl', 'GetIPsByTarget', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'GetIPsByTarget', len(query))

    query = GetIPsByTarget(gte, lte, Lhits=hits_size, Laggs=aggs_size, srcip=target)
    if query:
        libUtils.UnitTestPrint(True, 'libDsl', 'GetIPsByTarget', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'GetIPsByTarget', len(query))

    query = query_get_target(gte, lte, dstip=target)
    if query:
        libUtils.UnitTestPrint(True, 'libDsl', 'query_get_target', len(query))
    else:
        libUtils.UnitTestPrint(False, 'libDsl', 'query_get_target', len(query))