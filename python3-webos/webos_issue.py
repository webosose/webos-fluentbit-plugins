#!/usr/bin/python3

import argparse
import os
import json
import base64
import shutil
import requests

import webos_common as common

from atlassian import Jira
from webos_common import Crypto
from webos_common import NYX
from webos_common import Platform
from webos_capture import WebOSCapture
from webos_uploader import WebOSUploader


COMPONENT_TEMP = 'Temp'
DEFAULT_OUTDIR = '/var/spool/jira'
FILE_JOURNALD = 'messages.txt'
FILE_SYSINFO = 'info.txt'
FILE_MESSAGES = 'messages.tgz'
FILE_SCREENSHOT = 'screenshot.jpg'
PROJECT_KEY = common.get_value('jira', 'projectKey')

EXIT_STATUS_SUCCESS = 0
EXIT_STATUS_INVALID_REQUEST_PARAMS = 3
EXIT_STATUS_LOGIN_FAILED = 4

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
        pw = Crypto.instance().decrypt(common.get_value('account', 'pw'))
        self._jira = Jira(
            url=common.get_value('jira', 'url'),
            username=common.get_value('account', 'id'),
            password=pw)
        # Verify password first, if the password is incorrect, the account is locked.
        try:
            self._jira.user(common.get_value('account', 'id'))
        except requests.exceptions.HTTPError as ex:
            if ex.response.status_code != 401:
                return
            WebOSUploader.instance().sync_config()
            pw = Crypto.instance().decrypt(common.get_value('account', 'pw'))
            self._jira = Jira(
                url=common.get_value('jira', 'url'),
                username=common.get_value('account', 'id'),
                password=pw)
        return

    def create_issue(self, summary=None, description=None, priority=None, reproducibility=None, unique_summary=False, components=[COMPONENT_TEMP]):
        if summary is None and description is None:
            return None

        fields = {
            "project": {
                "key": PROJECT_KEY
            },
            "customfield_18405": NYX.instance().get_info()['webos_build_id'],
            "customfield_18122": [
                {
                    "value": NYX.instance().get_found_on(),
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
        if priority is not None:
            fields['priority'] = {'name': priority}
        if reproducibility is not None:
            fields['customfield_11202'] = {'value': reproducibility}
        common.debug('components {}'.format(components))
        fields['components'] = []
        for component in components:
            fields['components'].append({'name': component})

        if unique_summary:
            if summary is None:
                common.error("'summary' is required")
                return None
            issue = self.find_open_issue(summary)
            if issue is not None:
                common.info("'{}' is already created - {}".format(summary, issue))
                self.update_issue(issue, summary, description)
                return None
            if self.check_fixed_in(summary) is True:
                common.info("'{}' is already fixed".format(summary))
                return None
        return self._jira.issue_create(fields)

    def guess_component(self, summary):
        command = "unknown"
        if summary.find('/usr/sbin') > 0:
            command = summary[summary.find('/usr/sbin'):]
        elif summary.find('/usr/bin') > 0:
            command = summary[summary.find('/usr/bin'):]
        if command.find(' ') > 0:
            command = command[:command.find(' ')]
        common.debug('command {}'.format(command))
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

        return self._jira.update_issue_field(key, fields)

    def find_open_issue(self, summary):
        summary = summary.replace("[","\\\\[")
        summary = summary.replace("]","\\\\]")
        JQL = 'project = {} AND summary ~ "{}" AND issuetype = Bug AND status not in (Closed, Verify)'.format(PROJECT_KEY, summary)
        common.debug(JQL)
        response = self._jira.jql(JQL, limit=1)
        if len(response['issues']) > 0:
            return response['issues'][0]['key']
        return None

    def check_fixed_in(self, summary):
        summary = summary.replace("[","\\\\[")
        summary = summary.replace("]","\\\\]")
        JQL = 'project = {} AND summary ~ "{}" AND issuetype = Bug AND "Fixed In" is not Empty ORDER BY resolutiondate DESC'.format(PROJECT_KEY, summary)
        common.debug(JQL)
        response = self._jira.jql(JQL, limit=1)
        if len(response['issues']) == 0:
            return False
        try:
            fixed_in = response['issues'][0]['fields']['customfield_12415']
            common.info('Fixed In : {}'.format(fixed_in))
            # '2108' or '2108, OSE 373' or 'OSE 374, 2109' or 'thud 108'
            fixed_in_list = [x.strip() for x in fixed_in.split(',')]
            for x in fixed_in_list:
                if len(x.split(' ')) == 1:
                    # master build_id
                    fixed_build_id = int(x)
                    break
                elif x.startswith('thud'):
                    fixed_build_id = int(x[4:])
                    break
            device_build_id = int(NYX.instance().get_info()['webos_build_id'])
            common.info('Build Id : {}'.format(device_build_id))
            if int(fixed_build_id) > int(device_build_id):
                return True
        except Exception as ex:
            print(ex)
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
            basename = os.path.basename(file)
            desc = "WEB_URL"
            if basename == FILE_JOURNALD:
                desc = "SYS_LOG"
            elif basename == FILE_SYSINFO:
                desc = "SYS_INFO"
            elif basename == FILE_MESSAGES:
                desc = "MESSAGES"
            elif basename.startswith('screenshot'):
                desc = "SCREENSHOT"
            elif basename.find('crashreport.txt') > 0:
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

    def get_project_components(self, project_key=PROJECT_KEY):
        components = self._jira.get_project_components(project_key)
        for comp in components:
            print(comp['name'])

    def show_popup(self, message):
        params = {
            'message': message,
            'buttons': [{
                'label': 'Close',
                'onclick': 'luna://com.webos.notification/closeAlert',
                'params': {}
            }]
        }
        command = "luna-send -n 1 -f luna://com.webos.notification/createAlert '{}'".format(json.dumps(params, separators=(',', ':')))
        common.info(command)
        result = Platform.instance().execute(command)
        common.info(result)

    def close_issue(self, key):
        status = self._jira.get_issue_status(key)
        if 'Closed' == status:
            return
        if 'Verify' != status:
            self._jira.set_issue_status(key, 'Verify')
        self._jira.set_issue_status(key, 'Closed', fields={'resolution':{'name':'False Positive'}})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--id',               type=str, help='jira id')
    parser.add_argument('--pw',               type=str, help='jira pw')

    parser.add_argument('--key',              type=str, help='jira key')
    parser.add_argument('--summary',          type=str, help='jira summary')
    parser.add_argument('--description',      type=str, help='jira description')
    parser.add_argument('--comment',          type=str, help='jira comment')
    parser.add_argument('--priority',         type=str, help='jira priority')
    parser.add_argument('--reproducibility',  type=str, help='jira reproducibility')
    parser.add_argument('--close-issue',      type=str, help='jira key to close')

    parser.add_argument('--attach-files',     type=str, nargs='*', help='All files are attached into jira ticket')
    parser.add_argument('--upload-files',     type=str, nargs='*', help='All files are uploaded into file server')

    parser.add_argument('--components',       action='append', help='jira components')

    parser.add_argument('--unique-summary',   action='store_true', help='Create issue only if it is unique summary')
    parser.add_argument('--without-sysinfo',  action='store_true', help='Disable uploading system information')
    parser.add_argument('--show-id',          action='store_true', help='Show ID and PASS')
    parser.add_argument('--show-component',   action='store_true', help='Show all components')
    parser.add_argument('--show-devicename',  action='store_true', help='Show all supported devices')
    parser.add_argument('--attach-crashcounter', action='store_true', help='Attach crashcounter in description')
    parser.add_argument('--get-project-components', action='store_true', help='Show all components registered in project')
    parser.add_argument('--enable-popup',     action='store_true', help='Display the result in a pop-up')

    args = parser.parse_args()

    # handle 'show' commands
    if args.show_id:
        id = common.get_value('account', 'id')
        pw = common.get_value('account', 'pw')
        pw = Crypto.instance().b64encode(Crypto.instance().decrypt(pw))
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
        if args.id is None or args.pw is None:
            common.error("'id' and 'pw' are needed")
            exit(EXIT_STATUS_INVALID_REQUEST_PARAMS)
        if len(args.id) == 0 or len(args.pw) == 0:
            common.remove('account', 'id')
            common.remove('account', 'pw')
            exit(EXIT_STATUS_SUCCESS)
        try:
            pw = Crypto.instance().b64decode(args.pw)
            jira = Jira(common.get_value('jira', 'url'), args.id, pw)
            jira.user(args.id)
            pw = Crypto.instance().encrypt(pw)
            common.set_value('account', 'id', args.id)
            common.set_value('account', 'pw', pw)
        except base64.binascii.Error as ex:
            common.error(ex)
            exit(EXIT_STATUS_INVALID_REQUEST_PARAMS)
        except requests.exceptions.HTTPError as ex:
            common.error(ex)
            exit(EXIT_STATUS_LOGIN_FAILED)

    if args.get_project_components:
        WebOSIssue.instance().get_project_components()
        exit(1)

    if args.close_issue:
        WebOSIssue.instance().close_issue(args.close_issue)
        exit(EXIT_STATUS_SUCCESS)

    key = args.key
    upload_files = args.upload_files
    if upload_files is None:
        upload_files = []

    if args.attach_crashcounter:
        crashcounter = WebOSUploader.instance().increase_counter(args.summary)
        if args.description is None:
            args.description = ''
        args.description = '<p>Number of times this crash occurred : {}.</p>{}'.format(crashcounter, args.description)

    if key is not None:
        # handle 'UPDATE' mode
        try:
            WebOSIssue.instance().update_issue(args.key, args.summary, args.description)
        except Exception as ex:
            common.error("{} : Failed to update '{}'".format(ex, args.key))
            if ex.response and ex.response.status_code == 401:
                exit(EXIT_STATUS_LOGIN_FAILED)
            exit(1)

    elif args.summary is not None:
        # handle 'CREATE' mode
        outdir = os.path.join(DEFAULT_OUTDIR, '0')
        if not os.path.isdir(DEFAULT_OUTDIR):
            os.mkdir(DEFAULT_OUTDIR)
        subdirs = os.listdir(DEFAULT_OUTDIR)
        try:
            if len(subdirs) > 0:
                subdirs.sort(key=int, reverse=True)
                outdir = os.path.join(DEFAULT_OUTDIR, str(int(subdirs[0])+1))
        except Exception as ex:
            common.warn(str(ex))
        common.info('Set output dir: {}'.format(outdir))
        if os.path.exists(outdir):
            common.warn('Remove out dir: {}'.format(outdir))
            shutil.rmtree(outdir)
        os.mkdir(outdir)

        if args.without_sysinfo is False:
            journal_path = os.path.join(outdir, FILE_JOURNALD)
            sysinfo_path = os.path.join(outdir, FILE_SYSINFO)
            messages_path = os.path.join(outdir, FILE_MESSAGES)
            WebOSCapture.instance().capture_journald(journal_path)
            WebOSCapture.instance().capture_sysinfo(sysinfo_path)
            WebOSCapture.instance().capture_messages(messages_path)
            upload_files.append(journal_path)
            upload_files.append(sysinfo_path)
            upload_files.append(messages_path)
        screenshot_path = os.path.join(outdir, FILE_SCREENSHOT)
        WebOSCapture.instance().capture_screenshot(screenshot_path)
        upload_files.append(screenshot_path)

        components = []
        if args.components is None:
            components = [WebOSIssue.instance().guess_component(args.summary)]
        else:
            components = args.components
        try:
            result = WebOSIssue.instance().create_issue(args.summary, args.description, args.priority, args.reproducibility, args.unique_summary, components)
        except Exception as ex:
            error_text = ex.response.status_code if ex.response and ex.response.status_code else str(ex)
            common.error('Failed to create ticket : {}'.format(error_text))
            if args.enable_popup:
                WebOSIssue.instance().show_popup('Failed to create ticket : {}'.format(error_text))
            if error_text == 401:
                exit(EXIT_STATUS_LOGIN_FAILED)
            raise ex
        if result is None or 'key' not in result:
            common.error("Failed to create new ticket")
            exit(1)
        key = result['key']
        common.info("'{}' is created".format(key))
        keyfile = open(os.path.join(outdir, key), 'w')
        keyfile.close()
    else:
        common.info("'key' or 'summary' is needed")
        exit(0)

    # handle 'attach-files'
    WebOSIssue.instance().attach_files(key, args.attach_files)

    # handle 'upload-files'
    WebOSIssue.instance().upload_files(key, upload_files)

    if args.comment is not None:
        WebOSIssue.instance().add_comment(key, args.comment)

    if args.enable_popup and key:
        WebOSIssue.instance().show_popup('Ticket created : ' + key)

    # delete outdir
    common.info('Deleting {}'.format(outdir))
    shutil.rmtree(outdir)
