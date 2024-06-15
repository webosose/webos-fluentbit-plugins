#!/usr/bin/python3

import argparse
import os
import json
import base64
import shutil
import requests
import logging
import subprocess

import webos_common as common

from atlassian import Jira
from webos_common import Crypto
from webos_common import NYX
from webos_common import Platform
from webos_capture import WebOSCapture
from webos_uploader import WebOSUploader

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


COMPONENT_PM = 'PM'
DEFAULT_OUTDIR = '/tmp/jira'
FILE_JOURNALS = 'journals.txt'
FILE_SYSINFO = 'info.txt'
FILE_MESSAGES = 'messages.tgz'
FILE_SCREENSHOT = 'screenshot.jpg'
PROJECT_KEY = common.get_value('jira', 'projectKey')

EXIT_STATUS_SUCCESS = 0
EXIT_STATUS_INVALID_REQUEST_PARAMS = 3
EXIT_STATUS_LOGIN_FAILED = 4

REPRODUCIBILITY_DICT = {
    "always": "Always (100%)",
    "often": "Often (50-99%)",
    "seldom": "Seldom (10-49%)",
    "rarely": "Rarely (<10%)",
    "unknown": "I didn't try"
}

CUSTOMFIELD_FIXED_IN = "customfield_12415"
CUSTOMFIELD_FOUND_IN = "customfield_18405"
CUSTOMFIELD_FOUND_ON = "customfield_18122"
CUSTOMFIELD_REGRESSION = "customfield_12504"
CUSTOMFIELD_REPRODUCIBILITY = "customfield_11202"
CUSTOMFIELD_TRIAGE_STATUS = "customfield_18123"


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

    def __init__(self, retry_count=0):
        pw = Crypto.instance().decrypt(common.get_value('account', 'pw'))

        session = None
        if retry_count > 0:
            logging.info('WebOSIssue.__init__: retry_count={}'.format(retry_count))
            # https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html
            retry = Retry(retry_count, backoff_factor=0.1)
            adapter = HTTPAdapter(max_retries=retry)
            session = requests.Session()
            session.mount('http://', adapter)
            session.mount('https://', adapter)

        self._jira = Jira(
            url=common.get_value('jira', 'url'),
            username=common.get_value('account', 'id'),
            password=pw,
            session=session)

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

    def create_issue(self, summary=None, description=None, priority=None, reproducibility=None, issuetype=None, unique_summary=False, components=None, labels=[], assignee=None):
        if components is None:
            components = [COMPONENT_PM]
        if summary is None and description is None:
            return None

        fields = {
            "project": {
                "key": PROJECT_KEY
            },
            CUSTOMFIELD_FOUND_IN: NYX.instance().get_info()['webos_build_id'],
            CUSTOMFIELD_FOUND_ON: [
                {
                    "value": NYX.instance().get_found_on(),
                }
            ],
            "labels": labels,
            "issuetype": {
                "name": "Bug" if issuetype is None else issuetype
            }
        }
        if summary is not None:
            fields['summary'] = summary
        if description is not None:
            fields['description'] = description
        if priority is not None:
            fields['priority'] = {'name': priority}
        if reproducibility is not None:
            if reproducibility in REPRODUCIBILITY_DICT:
                reproducibility = REPRODUCIBILITY_DICT[reproducibility]
            logging.info("reporducibility '{}'".format(reproducibility))
            fields[CUSTOMFIELD_REPRODUCIBILITY] = {'value': reproducibility}
        logging.info('components {}'.format(components))
        fields['components'] = []
        for component in components:
            fields['components'].append({'name': component})
        if assignee is not None:
            fields['assignee'] = {'name': assignee}

        #if unique_summary:
        #    if summary is None:
        #        logging.error("'summary' is required")
        #        return None
        #    issue = self.find_open_issue(summary)
        #    if issue is not None:
        #        logging.info("'{}' is already created - {}".format(summary, issue))
        #        self.update_issue(issue, summary, description)
        #        return None
        #    if self.check_fixed_in(summary) is True:
        #        logging.info("'{}' is already fixed".format(summary))
        #        return None
        try:
            return self._jira.issue_create(fields)
        except requests.exceptions.HTTPError as ex:
            # {"errorMessages":[],"errors":{"components":"Component name 'luna-surfacemanager-base' is not valid"}}
            # {"errorMessages":[],"errors":{"customfield_18122":"Option value 'Nano-RPi4' is not valid"}}
            logging.warning('{} {}'.format(ex.response.status_code, ex.response.text))
            if ex.response.status_code == 400:
                errors = ex.response.json().get('errors', {})
                if len(errors) != 1 or 'components' not in errors:
                    raise ex
                errmsg = errors['components']
                errmsg_split = errmsg.split(' ')
                if len(errmsg_split) != 6:
                    raise ex
                del errmsg_split[2]
                if errmsg_split != ['Component', 'name', 'is', 'not', 'valid']:
                    raise ex
                for component in components:
                    fields['labels'].append('Component-Not-Found:{}'.format(component))
                fields['components'] = [{'name': COMPONENT_PM}]
                logging.info("Retry with components {} and labels {}".format(COMPONENT_PM, fields['labels']))
                return self._jira.issue_create(fields)
            raise ex

    def guess_component(self, exe):
        # for crash, [RDX_CRASH][webos] /usr/bin/coredump_example in _Z5funcCv (coredump_example + 0xeb4)
        try:
            # exe = summary.split(' ', 2)
            command = 'opkg search {}'.format(exe)
            logging.info(command)
            result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, encoding='utf-8')
            # opkg search /usr/bin/coredump_example
            # webos-fluentbit-plugins - 1.0.0-37+gitr0+30b1c18982-r12
            # lib32-webos-fluentbit-plugins - 1.0.0-37+gitr0+30b1c18982+gitr0+30b1c18982-r12
            logging.info(result)
            pkg = result.split(' ', 1)[0]
            pkg = pkg[6:] if pkg.startswith('lib32-') else pkg
            pkg2recipe = common.get_value('customfield', 'pkg2recipe')
            # logging.debg('pkg2recipe', pkg2recipe)
            if pkg in pkg2recipe:
                return pkg2recipe[pkg]
            else:
                return pkg
        except subprocess.CalledProcessError as ex:
            logging.error('CalledProcessError: {}'.format(ex.returncode))
        except Exception as ex:
            logging.error('Exception: {}'.format(ex))
        return COMPONENT_PM

    def update_issue(self, key, summary=None, description=None, labels=[]):
        fields = {}
        if summary is not None:
            fields['summary'] = summary
        if description is not None:
            fields['description'] = description
        if len(labels) > 0:
            fields['labels'] = labels

        return self._jira.update_issue_field(key, fields)

    def find_issue(self, key):
        return self._jira.issue(key)

    def find_issue_with_exact_summary(self, summary):
        updated_summary = summary.replace("[","\\\\[")
        updated_summary = updated_summary.replace("]","\\\\]")
        updated_summary = updated_summary.replace("\"","\\\"")
        JQL = 'project = {} AND summary ~ "{}" AND issuetype = Bug ORDER BY key DESC'.format(PROJECT_KEY, updated_summary)
        logging.info(JQL)
        start = 0
        limit = 100
        while True:
            response = self._jira.jql(JQL, start=start, limit=limit)
            logging.info('len : {} (start : {}, limit : {})'.format(len(response['issues']), start, limit))
            if len(response['issues']) == 0:
                return None
            for issue in response['issues']:
                # summary = "\\[TAS Failed\\]\\[OSE\\]\\ ABC"
                # Because jira query finds both cases below, so we should check if the summary matches exactly.
                # 1. [TAS Failed][OSE] ABC
                # 2. [TAS Failed][OSE Emulator] ABC
                if issue['fields']['summary'] != summary:
                    logging.debug('{} : Not matched ({})'.format(issue['key'], issue['fields']['summary']))
                    continue
                status_name = None
                try:
                    status_name = issue['fields']['status']['name']
                except Exception as ex:
                    pass
                if status_name == 'Closed':
                    logging.info('{} : Matched, but already closed.'.format(issue['key']))
                    return None
                logging.info('{} : Matched'.format(issue['key']))
                return issue
            start = limit
            limit = limit + 100

    def find_open_issue(self, summary):
        summary = summary.replace("[","\\\\[")
        summary = summary.replace("]","\\\\]")
        summary = summary.replace("\"","\\\"")
        JQL = 'project = {} AND summary ~ "{}" AND issuetype = Bug AND status not in (Closed, Verify)'.format(PROJECT_KEY, summary)
        logging.info(JQL)
        response = self._jira.jql(JQL, limit=1)
        if len(response['issues']) > 0:
            # return response['issues'][0]['key']
            return response['issues'][0]
        return None

    def check_fixed_in(self, issue):
        try:
            fixed_in = issue['fields'][CUSTOMFIELD_FIXED_IN]
            logging.info('Fixed In : {}'.format(fixed_in))
            if fixed_in is None:
                return False
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
            logging.info('Build Id : {}'.format(device_build_id))
            if int(fixed_build_id) > int(device_build_id):
                return True
        except Exception as ex:
            logging.warning(ex)
        return False

    def attach_files(self, key, files):
        if files is None:
            return

        for file in files:
            if os.path.exists(file) is False:
                logging.warning("'{}' doesn 't exist".format(file))
                continue
            self._jira.add_attachment(key, file)
            logging.info("'{}' is attached".format(file))
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
            if basename == FILE_JOURNALS:
                desc = "SYS_LOG"
            elif basename == FILE_SYSINFO:
                desc = "SYS_INFO"
            elif basename == FILE_MESSAGES:
                desc = "MESSAGES"
            elif basename.startswith('screenshot'):
                desc = "SCREENSHOT"
            elif basename.find('crashreport.txt') > 0 or basename.startswith('RDXD_'):
                desc = "CRASHREPORT"
            elif basename.startswith("core"):
                desc = "COREDUMP"
            comment += "{} : [{}|{}]\n".format(desc, basename, server_files[i])
        self.add_comment(key, comment)
        logging.info("All files are uploaded")

    def add_comment(self, key, comment):
        self._jira.issue_add_comment(key, comment)

    def check_key(self, key):
        return self._jira.issue_exists(key)

    def get_jira(self):
        return self._jira

    def get_project_components(self, project_key=PROJECT_KEY):
        return self._jira.get_project_components(project_key)
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
        logging.info(command)
        result = Platform.instance().execute(command)
        logging.info(result)

    def close_issue(self, key):
        status = self._jira.get_issue_status(key)
        if 'Closed' == status:
            return
        if 'Verify' != status:
            self._jira.set_issue_status(key, 'Verify')
        self._jira.set_issue_status(key, 'Closed', fields={'resolution':{'name':'Not a Bug'}})

    def verify_issue(self, key):
        status = self._jira.get_issue_status(key)
        if 'Verify' == status:
            return
        if 'Integration' == status:
            self._jira.set_issue_status(key, 'Implementation')
        self._jira.set_issue_status(key, 'Verify')

    def rescreen_issue(self, key, components):
        status = self._jira.get_issue_status(key)
        if 'Closed' == status:
            self._jira.set_issue_status(key, 'Verify')
        self._jira.set_issue_status(key, 'Screen', fields={CUSTOMFIELD_REGRESSION:{'value': 'No'}})
        # reset components and assignee
        fields = {
            CUSTOMFIELD_TRIAGE_STATUS: None
        }
        if isinstance(components, list) and len(components) > 0:
            fields['components'] = []
            for component in components:
                fields['components'].append({'name': component})
        self._jira.update_issue_field(key, fields)
        # -1 means Automatic
        self._jira.assign_issue(key, -1)

    def create_issue_link(self, name, inward, outward):
        data = {
            'type': {'name': name},
            'inwardIssue': {'key': inward},
            'outwardIssue': {'key': outward}
        }
        try:
            self._jira.create_issue_link(data)
            return True
        except Exception as ex:
            logging.error(ex)
            return False


if __name__ == "__main__":
    # Update the manual also, if necessary.
    # http://collab.lge.com/main/display/WEBOSPM/webos_issue.py+manual
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--id',                      type=str, help='Jira user id')
    parser.add_argument('--pw',                      type=str, help='Jira user pw')

    parser.add_argument('--key',                     type=str, help='Issue key')
    parser.add_argument('--summary',                 type=str, help='Issue summary')
    parser.add_argument('--description',             type=str, help='Issue description')
    parser.add_argument('--comment',                 type=str, help='Issue comment')
    parser.add_argument('--priority',                type=str, help='Issue priority [P1|P2|P3|P4|P5].')
    parser.add_argument('--reproducibility',         type=str, help='Issue reproducibility [always|often|seldom|rarely|unknown].')
    parser.add_argument('--issuetype',               type=str, help='Issue type [Bug|CCC Bug].')
    # parser.add_argument('--components',              action='append', help='Issue components')
    parser.add_argument('--components',              type=str, nargs='*', help='Issue components')
    parser.add_argument('--labels',                  type=str, nargs='*', help='Issue labels to be appended')
    parser.add_argument('--assignee',                type=str, help='Issue assignee')

    parser.add_argument('--attach-files',            type=str, nargs='*', help='All files are attached into jira ticket')
    parser.add_argument('--upload-files',            type=str, nargs='*', help='All files are uploaded into file server (The file on the server is deleted after the ticket is closed and a period of time has elapsed)')

    parser.add_argument('--without-sysinfo',         action='store_true', help='Disable uploading system information')
    parser.add_argument('--without-screenshot',      action='store_true', help='Disable taking screenshot')
    parser.add_argument('--close',                   action='store_true', help='Close issue with --key')

    parser.add_argument('--link-has-test-case',      type=str, help="Create link with 'has test case'")
    parser.add_argument('--link-is-a-test-case-for', type=str, help="Create link with 'is a test case for'")
    parser.add_argument('--link-relates-to',         type=str, help="Create link with 'relates to'")

    parser.add_argument('--unique-summary',          action='store_true', help='Create issue only if it is unique summary')
    parser.add_argument('--attach-crashcounter',     action='store_true', help='Attach crashcounter in description')
    parser.add_argument('--crashed-executable',      type=str, help='Crashed executable of the form /usr/bin/coredump_example. This is used to determine the component when the --components is not specified.')
    parser.add_argument('--show-id',                 action='store_true', help='Show ID and PASS')
    parser.add_argument('--show-component',          action='store_true', help='Show all components')
    parser.add_argument('--show-devicename',         action='store_true', help='Show all supported devices')
    parser.add_argument('--get-project-components',  action='store_true', help='Show all components registered in project')
    parser.add_argument('--enable-popup',            action='store_true', help='Display the result in a pop-up')
    parser.add_argument('--log-level',               type=str, help='Set log level [debug|info|warning|error]. The dafault value is warning.')
    parser.add_argument('--is-close',                action='store_true', help='(Deprecated) Close issue with --key')
    parser.add_argument('--retry-count',             type=int, help='Number of retries on Jira connection failure')
    parser.add_argument('--rescreen-if-exists',      action='store_true', help='Rescreen the issue if it exists. This is used with --unique-summary.')
    parser.add_argument('--verify',                  action='store_true', help='Verify issue with --key. (for test automation)')

    args = parser.parse_args()

    # set log level
    if args.log_level is not None:
        common.set_log_level(args.log_level)

    if args.retry_count is not None and args.retry_count > 0:
        WebOSIssue.instance(args.retry_count)

    # handle 'show' commands
    if args.show_id:
        id = common.get_value('account', 'id')
        pw = common.get_value('account', 'pw')
        pw = Crypto.instance().b64encode(Crypto.instance().decrypt(pw))
        print('ID : {}'.format(id))
        print('PW : {}'.format(pw))
        exit(EXIT_STATUS_SUCCESS)

    if args.show_component:
        result = common.get_value('customfield', 'components')
        print(json.dumps(result, indent=4, sort_keys=True))
        exit(EXIT_STATUS_SUCCESS)

    if args.show_devicename:
        result = common.get_value('deviceName')
        print(json.dumps(result, indent=4, sort_keys=True))
        exit(EXIT_STATUS_SUCCESS)

    # handle 'id' and 'pw' first
    if args.id is not None or args.pw is not None:
        if args.id is None or args.pw is None:
            logging.error("'id' and 'pw' are needed")
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
            if args.key is None and args.summary is None:
                exit(0)
        except base64.binascii.Error as ex:
            logging.error(ex)
            exit(EXIT_STATUS_INVALID_REQUEST_PARAMS)
        except requests.exceptions.HTTPError as ex:
            logging.error(ex)
            exit(EXIT_STATUS_LOGIN_FAILED)

    if args.get_project_components:
        components = WebOSIssue.instance().get_project_components()
        for comp in components:
            print(comp['name'])
        exit(EXIT_STATUS_SUCCESS)

    if (args.is_close or args.close) and args.key:
        WebOSIssue.instance().close_issue(args.key)
        exit(EXIT_STATUS_SUCCESS)

    if args.verify and args.key:
        WebOSIssue.instance().verify_issue(args.key)
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

    if args.description is None:
        args.description = common.get_value('template', 'bug')

    logging.debug('Description : "{}"'.format(args.description))

    issue = None
    if args.key is None and args.unique_summary:
        if args.summary is None:
            logging.error("'summary' is required")
            exit(1)
        #issue = WebOSIssue.instance().find_open_issue(args.summary)
        #if issue is not None:
        #    logging.info("'{}' is already created - {}".format(args.summary, issue['key']))
        #    # UPDATE mode
        #    args.key = issue['key']
        #elif WebOSIssue.instance().check_fixed_in(args.summary) is True:
        #    logging.info("'{}' is already fixed".format(args.summary))
        #    exit(0)
        # We may need to add "Found On." = "Signage-O20"/"TV-O22"/"OSE-RPi4" etc. to query.
        # Because issues are managed separately for each platform
        issue = WebOSIssue.instance().find_issue_with_exact_summary(args.summary)
        if issue is not None:
            logging.info("'{}' is already created with key {}".format(args.summary, issue['key']))
            status_name = None
            try:
                status_name = issue['fields']['status']['name']
                # exit(1)
            except Exception as ex:
                logging.error(ex)
            # bug   (rescreen = True):
            #       screen, analysis, ... => update
            #       verify, closed        => rescreen
            # crash (rescreen = False):
            #       screen, analyais, ... => update
            #       verify, closed        => create
            if status_name == 'Verify' or status_name == 'Closed':
                if WebOSIssue.instance().check_fixed_in(issue) is True:
                    logging.info("'{}' is already fixed".format(args.summary))
                    exit(0)
                elif args.rescreen_if_exists:
                    # re-screen (close->verify->screen)
                    logging.info("Re-Screen {} from {}".format(issue['key'], status_name))
                    WebOSIssue.instance().rescreen_issue(issue['key'], args.components)
                    # UPDATE mode
                    args.key = issue['key']
                else:
                    # CREATE mode
                    issue = None
            else:
                # UPDATE mode
                args.key = issue['key']
        else:
            # CREATE mode
            pass

    labels = []
    if len(upload_files) > 0 or args.without_sysinfo is False or args.without_screenshot is False:
        # This means that some files are uploaded to rdx server.
        # The files are deleted after the issue is closed and a certain period time has elapsed.
        labels = ['Link-RDX-Server']
    if args.labels is not None and len(args.labels) > 0:
        labels.extend(args.labels)
    logging.debug("Labels: {}".format(labels))

    if args.key is not None:
        # handle 'UPDATE' mode
        try:
            if args.labels is not None and len(args.labels) > 0 and issue is None:
                issue = WebOSIssue.instance().find_issue(args.key)
            if len(issue['fields'].get('labels')) > 0:
                labels.extend(issue['fields']['labels'])
                # remove duplicates
                labels = list(dict.fromkeys(labels))
                logging.debug("Labels: {}".format(labels))
            WebOSIssue.instance().update_issue(args.key, args.summary, args.description, labels)
        except Exception as ex:
            logging.error("{} : Failed to update '{}'".format(ex, args.key))
            if ex.response and ex.response.status_code == 401:
                exit(EXIT_STATUS_LOGIN_FAILED)
            exit(1)
        if args.comment is not None:
            if args.attach_crashcounter:
                args.comment = 'Number of times this crash occurred : {}.\n{}'.format(crashcounter, args.comment)
            WebOSIssue.instance().add_comment(args.key, args.comment)
            exit(0)

    elif args.summary is not None:
        # handle 'CREATE' mode
        outdir = DEFAULT_OUTDIR
        logging.info('Set output dir: {}'.format(outdir))
        if os.path.exists(outdir):
            logging.warning('Remove out dir: {}'.format(outdir))
            shutil.rmtree(outdir)
        os.mkdir(outdir)

        if args.without_sysinfo is False:
            journal_path = os.path.join(outdir, FILE_JOURNALS)
            sysinfo_path = os.path.join(outdir, FILE_SYSINFO)
            messages_path = os.path.join(outdir, FILE_MESSAGES)
            WebOSCapture.instance().capture_journald(journal_path)
            WebOSCapture.instance().capture_sysinfo(sysinfo_path)
            WebOSCapture.instance().capture_messages(messages_path)
            upload_files.append(journal_path)
            upload_files.append(sysinfo_path)
            upload_files.append(messages_path)
        if args.without_screenshot is False:
            screenshot_path = os.path.join(outdir, FILE_SCREENSHOT)
            WebOSCapture.instance().capture_screenshot(screenshot_path)
            upload_files.append(screenshot_path)

        components = None
        if args.components is not None:
            components = args.components
        elif args.crashed_executable is not None:
            components = [WebOSIssue.instance().guess_component(args.crashed_executable)]
        try:
            result = WebOSIssue.instance().create_issue(args.summary, args.description, args.priority, args.reproducibility, args.issuetype, args.unique_summary, components, labels, args.assignee)
            logging.info(result)
        except Exception as ex:
            error_text = ex.response.status_code if ex.response is not None and ex.response.status_code else str(ex)
            logging.error('Failed to create ticket : {}'.format(error_text))
            if args.enable_popup:
                WebOSIssue.instance().show_popup('Failed to create ticket : {}'.format(error_text))
            if error_text == 401:
                exit(EXIT_STATUS_LOGIN_FAILED)
            raise ex
        if result is None or 'key' not in result:
            logging.error("Failed to create new ticket")
            exit(1)
        key = result['key']
        logging.info("'{}' is created".format(key))
        keyfile = open(os.path.join(outdir, key), 'w')
        keyfile.close()
    else:
        logging.error("'key' or 'summary' is needed")
        exit(EXIT_STATUS_INVALID_REQUEST_PARAMS)

    # handle 'attach-files'
    WebOSIssue.instance().attach_files(key, args.attach_files)

    # handle 'upload-files'
    WebOSIssue.instance().upload_files(key, upload_files)

    if args.comment is not None:
        WebOSIssue.instance().add_comment(key, args.comment)

    if args.link_has_test_case is not None:
        WebOSIssue.instance().create_issue_link('Test Case', key, args.link_has_test_case)
    if args.link_is_a_test_case_for is not None:
        WebOSIssue.instance().create_issue_link('Test Case', args.link_is_a_test_case_for, key)
    if args.link_relates_to is not None:
        WebOSIssue.instance().create_issue_link('Relates', key, args.link_relates_to)

    if args.key is not None:
        # For ticket update, exit here.
        exit(0)

    if args.enable_popup and key:
        WebOSIssue.instance().show_popup('Ticket created : ' + key)
    # This is used when responding issue key in createBug
    print('Ticket created : {}'.format(key))

    # delete outdir
    logging.info('Deleting {}'.format(outdir))
    shutil.rmtree(outdir)
