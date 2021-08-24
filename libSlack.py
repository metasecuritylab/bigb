# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

import libConfig
import json
import requests

url = libConfig.GetConfig('SLACK', 'TEST')
otx = libConfig.GetConfig('OTX', 'URL')
ctas = libConfig.GetConfig('CTAS', 'URL')
vt = libConfig.GetConfig('VIRUSTOTAL', 'URL')
DASHBOARD = libConfig.GetConfig('DASHBOARD', 'REMOTE')
username = libConfig.GetConfig('SLACK', 'USER')

def SendSlack(critical=0, warning=0, fIP="", mOTX="", mWINS="", mET=""):
    icon_emoji = ":grinning:"
    Title = "New reported cases:\n*<{}|Incident Response - New critical IP is reported>*".format(DASHBOARD)
    InfoIP = "*IP :*\n{}".format(fIP)
    InfoSecurityLevel = "*Security Level :*\nCritical: {}, Warning: {}".format(str(critical), str(warning))
    InfoReason = "*Reason :*"

    if len(mOTX) > 0:
        InfoReason = InfoReason + "\n{}".format(mOTX)

    if len(mWINS) > 0:
        InfoReason = InfoReason + "\n{}".format(mWINS)

    if len(mET) > 0:
        InfoReason = InfoReason + "\n{}".format(mET)

    InfoRef = "*Ref: *\n"
    payload = {
        "username": username,
        "icon_emoji": icon_emoji,
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": Title
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": InfoIP
                    },
                    {
                        "type": "mrkdwn",
                        "text": InfoSecurityLevel
                    },
                    {
                        "type": "mrkdwn",
                        "text": InfoReason
                    },
                    {
                        "type": "mrkdwn",
                        "text": InfoRef
                    }
                ]
            },
            {
                "type": "actions",
                "elements": [
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Actions:*\n"
                    }
                ]
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "emoji": True,
                            "text": "Deny"
                        },
                        "style": "danger",
                        "value": "click_me_123",
                    }
                ]
            }
        ]
    }

    element = {
        "type": "button",
            "text": {
                "type": "plain_text",
                "emoji": True,
                "text": "OTX General Information"
            },
            "style": "primary",
            "value": "click_me_123",
            "url": "{}/indicator/ip/{}".format(otx, fIP)
    }

    payload['blocks'][2]['elements'].append(element)

    element = {
        "type": "button",
        "text": {
            "type": "plain_text",
            "emoji": True,
            "text": "C-TAS Threat Information"
        },
        "style": "primary",
        "value": "click_me_123",
        "url": "{}".format(ctas)
    }

#    payload['blocks'][2]['elements'].append(element)

    element = {
        "type": "button",
        "text": {
            "type": "plain_text",
            "emoji": True,
            "text": "VirusTotal Reputation"
        },
        "style": "primary",
        "value": "click_me_123",
        "url": "{}/gui/ip-address/{}/detection".format(vt, fIP)
    }

    payload['blocks'][2]['elements'].append(element)

    try:
        requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
    except requests.exceptions.HTTPError as e:
        #print(e.response.text)
        return False

    return True