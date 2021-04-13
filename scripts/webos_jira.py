import argparse
import os

from pprint import pprint
from atlassian import Jira

import util.logger as logger
import util.config as config

from base.nyx import NYX
from webos_info import WebOSInfo
from webos_uploader import WebOSUploader


UNKNOWN = 'Unknown'
DEFAULT_JOURNALD='/tmp/webos_journald.txt'
DEFAULT_INFO='/tmp/webos_info.txt'


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

    def update_issue(self, key, summary=None, description=None, append_description=False):
        if summary is None and description is None:
            return True

        fields = {}
        if append_description:
            if description is None:
                logger.error("'description' is required")
                return
            description = self._jira.issue_field_value(key, 'description') + '\n' + description

        if summary is not None:
            fields['summary'] = summary
        if description is not None:
            fields['description'] = description

        try:
            self._jira.update_issue_field(key, fields)
            return True
        except:
            return False

    def create_issue(self, summary=None, description=None, unique_summary=False, component=UNKNOWN):
        if summary is None and description is None:
            return None

        fields = {
            "project":{
                "key":"PLAT"
            },
            "customfield_10101": NYX.instance().get_info()['webos_build_id'],
            "customfield_10400": [
                {
                    "value": NYX.instance().get_device_name(),
                }
            ],
            "components": [
                {
                    "name": component
                }
            ],
            "labels":[
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

        if unique_summary:
            if summary is None:
                logger.error("'summary' is required")
                return
            if self.check_summary(summary) is True:
                logger.info("'{}' is already created".format(summary))
                return None
        return self._jira.issue_create(fields)

    def check_summary(self, summary):
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
                logger.error("'{}' doesn't exist".format(file))
                continue
            self._jira.add_attachment(key, file)
        return

    def upload_files(self, key, files):
        if files is None or len(files) == 0:
            return

        true_files, false_files = WebOSUploader.instance().exists(files)
        server_files = WebOSUploader.instance().upload_files(key, true_files)

        comment = "==== AUTO GENERATED SYSTEM INFO ====\n\n"
        for i, file in enumerate(true_files):
            comment += "[{}|{}]\n".format(os.path.basename(file), server_files[i])
        self.add_comment(key, comment)

    def add_comment(self, key, comment):
        self._jira.issue_add_comment(key, comment)

    def check_key(self, key):
        return self._jira.issue_exists(key)

    def get_jira(self):
        return self._jira


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--id',                 type=str, help='jira id')
    parser.add_argument('--pw',                 type=str, help='jira pw')
    parser.add_argument('--key',                type=str, help='jira key name (ex : PLAT-XXXXX)')

    parser.add_argument('--summary',            type=str, help='jira summary text (ex : Crash application manager ...)')
    parser.add_argument('--unique-summary',     action='store_true', help='Create ticket only if it is a unique summary')
    parser.add_argument('--description',        type=str, help='jira description')
    parser.add_argument('--append-description', action='store_true', help='Enable appendmode.')
    parser.add_argument('--component',          type=str, default=UNKNOWN, help='jira component')
    parser.add_argument('--comment',            type=str, help='jira comment')

    parser.add_argument('--attach-files',       type=str, nargs='*', help='Files for jira attachements')
    parser.add_argument('--upload-files',       type=str, nargs='*', help='Files for file server. The URLs are added to description')

    parser.add_argument('--without-info',       action='store_true', help='Disable uploading system information')

    args = parser.parse_args()

    # handle 'id' and 'pw' first
    if args.id is not None or args.pw is not None:
        if args.id is not None and args.pw is not None:
            config.set_value('account', 'id', None, args.id)
            config.set_value('account', 'pw', None, args.pw)
        else:
            logger.error("'id' and 'pw' are needed")
            exit(1)

    key = args.key
    upload_files = args.upload_files
    if upload_files is None:
        upload_files = []

    if key is not None:
        # handle 'UPDATE' mode
        result = WebOSJira.instance().update_issue(args.key, args.summary, args.description, args.append_description)
        if result is False:
            logger.error("Failed to update '{}'".format(args.key))
            exit(1)
    elif args.summary is not None:
        # handle 'CREATE' mode
        result = WebOSJira.instance().create_issue(args.summary, args.description, args.unique_summary, args.component)
        if result is None or 'key' not in result:
            logger.error("Failed to create new ticket")
            exit(1)
        key = result['key']
        logger.info("'{}' is created".format(key))

        if args.without_info is False:
            WebOSInfo.instance().capture_journald(DEFAULT_JOURNALD)
            WebOSInfo.instance().capture_info()

            upload_files.append(DEFAULT_JOURNALD)
            upload_files.append(DEFAULT_INFO)
    else:
        logger.info("'key' or 'summary' is needed")
        exit(1)

    # handle 'attach-files'
    WebOSJira.instance().attach_files(key, args.attach_files)

    # handle 'upload-files'
    WebOSJira.instance().upload_files(key, upload_files)

    if args.comment is not None:
        WebOSJira.instance().add_comment(key, args.comment)
