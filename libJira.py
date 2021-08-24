# !/usr/bin/env python
# dev: suwonchon(suwonchon@gmail.com)

from jira import JIRA, JIRAError
import libConfig
import requests

JIRA_URL = libConfig.GetConfig('JIRA', 'URL')
USER = libConfig.GetConfig('JIRA', 'USER')
PASS = libConfig.GetConfig('JIRA', 'PASS')
PROJ = libConfig.GetConfig('JIRA', 'PROJECT')

jira = JIRA(server=JIRA_URL, basic_auth=(USER, PASS))

def ReviewIssue(Key):
    try:
        issue = jira.issue(Key)
        summary = issue.fields.summary
    except JIRAError as e:
        #print(e.status_code, e.text)
        return False

    return True