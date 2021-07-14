#!/usr/bin/python3

import argparse
import os
import json

import webos_common as common

from atlassian import Jira
from webos_common import NYX
from webos_capture import WebOSCapture
from webos_uploader import WebOSUploader


COMPONENT_TEMP = 'Temp'
DEFAULT_JOURNALD = '/tmp/webos_journald.txt'
DEFAULT_SYSINFO = '/tmp/webos_info.txt'
DEFAULT_MESSAGES = '/tmp/webos_messages.tgz'


class WebOSIssue:
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
            url=common.get_value('jira', 'url'),
            username=common.get_value('account', 'id'),
            password=common.get_value('account', 'pw'))
        return

    def create_issue(self, summary=None, description=None, unique_summary=False, component=COMPONENT_TEMP):
        if summary is None and description is None:
            return None

        fields = {
            "project": {
                "key": "PLAT"
            },
            "customfield_10101": NYX.instance().get_info()['webos_build_id'],
            "customfield_10400": [
                {
                    "value": NYX.instance().get_device_name(),
                }
            ],
            "labels": [
                "Link-RDX-Server"
            ],
            "issuetype": {
                "name": "Bug"
            }
        }
        if summary is not None:
            fields['summary'] = summary
        if description is not None:
            fields['description'] = description
        if component != COMPONENT_TEMP:
            components = common.get_value('customfield', 'components')
            if component not in components:
                component = COMPONENT_TEMP
            fields['components'] = [
                { "name": component }
            ]

        if unique_summary:
            if summary is None:
                common.error("'summary' is required")
                return
            if self.check_summary(summary) is True:
                common.info("'{}' is already created".format(summary))
                return None
        return self._jira.issue_create(fields)


    def guess_component(self, summary):
        command = "unknown"
        if summary.find('/usr/sbin') > 0:
            command = summary[summary.find('/usr/sbin'):]
        elif summary.find('/usr/bin') > 0:
            command = summary[summary.find('/usr/bin'):]
        relations = common.get_value('customfield', 'relations')
        if command in relations:
            return relations[command]
        else:
            return COMPONENT_TEMP

    def update_issue(self, key, summary=None, description=None):
        if summary is None and description is None:
            return True

        fields = {}
        if summary is not None:
            fields['summary'] = summary
        if description is not None:
            fields['description'] = description

        try:
            self._jira.update_issue_field(key, fields)
            return True
        except:
            return False

    def check_summary(self, summary):
        summary = summary.replace("[","\\\\[")
        summary = summary.replace("]","\\\\]")
        JQL = 'project = PLAT AND summary ~ "{}" AND issuetype = Bug AND status not in (Closed, Verified)'.format(summary)
        response = self._jira.jql(JQL)
        if len(response['issues']) > 0:
            return True
        return False

    def attach_files(self, key, files):
        if files is None:
            return

        for file in files:
            if os.path.exists(file) is False:
                common.error("'{}' doesn't exist".format(file))
                continue
            self._jira.add_attachment(key, file)
            common.info("'{}' is attached".format(file))
        return

    def upload_files(self, key, files):
        if files is None or len(files) == 0:
            return

        true_files, false_files = WebOSUploader.instance().exists(files)
        server_files = WebOSUploader.instance().upload_files(key, true_files)

        comment = "##@@## RDX File Server Links @@##@@\n\n"
        for i, file in enumerate(true_files):
            desc = "WEB_URL"
            if file == DEFAULT_JOURNALD:
                desc = "SYS_LOG"
            elif file == DEFAULT_SYSINFO:
                desc = "SYS_INFO"
            elif file == DEFAULT_MESSAGES:
                desc = "MESSAGES"

            basename = os.path.basename(file)
            if basename.find('crashreport.txt') > 0:
                desc = "CRASHREPORT"
            elif basename.startswith("core"):
                desc = "COREDUMP"
            comment += "{} : [{}|{}]\n".format(desc, basename, server_files[i])
        self.add_comment(key, comment)
        common.info("All files are uploaded")

    def add_comment(self, key, comment):
        self._jira.issue_add_comment(key, comment)

    def check_key(self, key):
        return self._jira.issue_exists(key)

    def get_jira(self):
        return self._jira


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--id',               type=str, help='jira id')
    parser.add_argument('--pw',               type=str, help='jira pw')

    parser.add_argument('--key',              type=str, help='jira key')
    parser.add_argument('--summary',          type=str, help='jira summary')
    parser.add_argument('--description',      type=str, help='jira description')
    parser.add_argument('--component',        type=str, help='jira component')
    parser.add_argument('--comment',          type=str, help='jira comment')

    parser.add_argument('--attach-files',     type=str, nargs='*', help='All files are attached into jira ticket')
    parser.add_argument('--upload-files',     type=str, nargs='*', help='All files are uploaded into file server')

    parser.add_argument('--unique-summary',   action='store_true', help='Create issue only if it is unique summary')
    parser.add_argument('--without-sysinfo',  action='store_true', help='Disable uploading system information')
    parser.add_argument('--show-id',          action='store_true', help='Show ID and PASS')
    parser.add_argument('--show-component',   action='store_true', help='Show all components')
    parser.add_argument('--show-devicename',  action='store_true', help='Show all supported devices')

    args = parser.parse_args()

    # handle 'show' commands
    if args.show_id:
        id = common.get_value('account', 'id')
        pw = common.get_value('account', 'pw')
        print('ID : {}'.format(id))
        print('PW : {}'.format(pw))
        exit(1)

    if args.show_component:
        result = common.get_value('customfield', 'components')
        print(json.dumps(result, indent=4, sort_keys=True))
        exit(1)

    if args.show_devicename:
        result = common.get_value('deviceName')
        print(json.dumps(result, indent=4, sort_keys=True))
        exit(1)

    # handle 'id' and 'pw' first
    if args.id is not None or args.pw is not None:
        if args.id is not None and args.pw is not None:
            common.set_value('account', 'id', None, args.id)
            common.set_value('account', 'pw', None, args.pw)
        else:
            common.error("'id' and 'pw' are needed")
            exit(1)

    key = args.key
    upload_files = args.upload_files
    if upload_files is None:
        upload_files = []

    if key is not None:
        # handle 'UPDATE' mode
        result = WebOSIssue.instance().update_issue(args.key, args.summary, args.description)
        if result is False:
            common.error("Failed to update '{}'".format(args.key))
            exit(1)
    elif args.summary is not None:
        # handle 'CREATE' mode
        component = None
        if args.component is None:
            component = WebOSIssue.instance().guess_component(args.summary)
        else:
            component = args.component
        result = WebOSIssue.instance().create_issue(args.summary, args.description, args.unique_summary, component)
        if result is None or 'key' not in result:
            common.error("Failed to create new ticket")
            exit(1)
        key = result['key']
        common.info("'{}' is created".format(key))

        if args.without_sysinfo is False:
            WebOSCapture.instance().capture_journald(DEFAULT_JOURNALD)
            WebOSCapture.instance().capture_sysinfo(DEFAULT_SYSINFO)
            WebOSCapture.instance().capture_messages(DEFAULT_MESSAGES)

            upload_files.append(DEFAULT_JOURNALD)
            upload_files.append(DEFAULT_SYSINFO)
            upload_files.append(DEFAULT_MESSAGES)
    else:
        common.info("'key' or 'summary' is needed")
        exit(1)

    # handle 'attach-files'
    WebOSIssue.instance().attach_files(key, args.attach_files)

    # handle 'upload-files'
    WebOSIssue.instance().upload_files(key, upload_files)

    if args.comment is not None:
        WebOSIssue.instance().add_comment(key, args.comment)
