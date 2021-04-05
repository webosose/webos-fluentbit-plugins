import argparse
import shutil
import os
import sys

from pprint import pprint
from atlassian import Jira

import util.logger as logger
import util.config as config


class WebOSJira:
    _instance = None

    @classmethod
    def _getInstance(cls):
        return cls._instance

    @classmethod
    def instance(cls, *args, **kargs):
        cls._instance = cls(*args, **kargs)
        cls.instance = cls._getInstance
        return cls._instance

    def __init__(self):
        self._jira = Jira(
            url=config.get_value('jira', 'url'),
            username=config.get_value('account', 'id'),
            password=config.get_value('account', 'pw'))
        return

    def create_issue(self, summary='unknown', description='unknown'):
        fields = {
            "project":{
                "key":"PLAT"
            },
            "customfield_10101":"444",
            "summary": summary,
            "components":[
                {
                    "name":"Bootd"
                }
            ],
            "description": description,
            "issuetype":{
                "name":"Bug"
            }
        }
        response = self._jira.issue_create(fields)
        return response

    def attach_files(self, key, files):
        for file in files:
            if os.path.exists(file) is False:
                logger.info("'{}' doesn't exist".format(file))
                continue
            self._jira.add_attachment(key, file)
        return

    def has_summary(self, summary):
        JQL = 'project = PLAT AND status in (Screen, Analysis, Implementation, Integration, Build, Verify) AND text ~ "{}"'.format(summary)
        response = self._jira.jql(JQL)
        if len(response['issues']) > 0:
            return True
        return False

    def has_key(self, key):
        return self._jira.issue_exists(key)

    def get_jira(self):
        return self._jira


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--key',                 type = str, help='TBD')
    parser.add_argument('--summary',             type = str, help='TBD')
    parser.add_argument('--description',         type = str, help='TBD')
    parser.add_argument('--attach-files',        type = str, nargs='*', help='TBD')
    parser.add_argument('--upload-files',        type = str, nargs='*', help='TBD')
    parser.add_argument('--id',                  type = str, help='TBD')
    parser.add_argument('--pw',                  type = str, help='TBD')
    parser.add_argument('--has-key',             action='store_true', help='TBD')
    parser.add_argument('--has-summary',         action='store_true', help='TBD')
    parser.add_argument('--without-info',        action='store_false', help='TBD')

    args = parser.parse_args()
    WebOSJira.instance().attach_files('PLAT-139820', ['test/test.txt', 'wwww'])