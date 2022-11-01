#!/usr/bin/python3

import argparse
import os
import requests
import logging

import webos_common as common

DEFAULT_SERVER = 'http://10.178.84.116:3002'
DEFAULT_SERVER_UPLOAD = DEFAULT_SERVER + '/upload'
DEFAULT_SERVER_CRASH = DEFAULT_SERVER + '/crash'
DEFAULT_SERVER_CONFIG = DEFAULT_SERVER + '/config'

class WebOSUploader:
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
        return

    def exists(self, files):
        A = []
        B = []
        for file in files:
            if os.path.exists(file) is False:
                B.append(file)
                continue
            A.append(file)
        return A, B

    def upload_files(self, key, upload_files, url=DEFAULT_SERVER_UPLOAD):
        if len(upload_files) == 0:
            return []

        files = {}
        for file in upload_files:
            basename = os.path.basename(file)
            files[basename] = (basename, open(file, "rb"))

        response = requests.post(url, files=files, data={ "key": key })
        if response.ok:
            return response.json()['downloadUrls']
        else:
            return []

    def increase_counter(self, summary, url=DEFAULT_SERVER_CRASH):
        summary = summary[summary.find(' '):].strip()
        summary = requests.utils.quote(summary, safe='')
        url = url + '/' + summary
        logging.info('PATCH {}'.format(url))
        response = requests.patch(url)
        logging.info('{}, count {}'.format(response.status_code, response.text))
        return response.text

    def sync_config(self, url=DEFAULT_SERVER_CONFIG):
        logging.info('GET {}'.format(url))
        response = requests.get(url)
        logging.info('{}'.format(response.status_code))
        if not response.ok:
            logging.warning(response.text)
            return
        common.sync_config(response.json())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--key',           type=str, help='jira key (ex : PLAT-XXXXX)')
    parser.add_argument('--url',           type=str, default=DEFAULT_SERVER_UPLOAD, help='File server URL')
    parser.add_argument('--upload-files',  type=str, nargs='*', help='Files for uploading.')
    parser.add_argument('--sync-config',   action='store_true', help='Sync config with server')
    parser.add_argument('--log-level',     type=str, help='Set log level [debug|info|warning|error]. The dafault value is warning.')

    args = parser.parse_args()
    if args.log_level is not None:
        common.set_log_level(args.log_level)

    if args.sync_config:
        try:
            WebOSUploader.instance().sync_config()
        except Exception as ex:
            logging.warning(ex)
        exit(1)

    print("WARNING: Recommend to use this with webos_issue.py. Uploaded files can be deleted based on status of jira ticket.")
    if args.key is None or args.url is None or args.upload_files is None:
        print("Required parameters are missing.")
        exit(1)

    true_files, false_files = WebOSUploader.instance().exists(args.upload_files)
    server_files = WebOSUploader.instance().upload_files(args.key, true_files, args.url)
    for i, file in enumerate(true_files):
        print("[OK] '{}' : '{}'".format(file, server_files[i]))
    for file in false_files:
        print("[NO] '{}'".format(file))

