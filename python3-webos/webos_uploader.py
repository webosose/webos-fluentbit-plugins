#!/usr/bin/python3

import argparse
import os
import requests

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

    def upload_files(self, key, upload_files, url='http://10.177.242.144:3002/upload'):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--key',           type=str, help='jira key name (ex : PLAT-XXXXX)')
    parser.add_argument('--url',           type=str, default='http://10.177.242.144:3002/upload', help='Simple File server)')
    parser.add_argument('--upload-files',  type=str, nargs='*', help='Files for file server.')

    args = parser.parse_args()

    if args.key is None or args.url is None or args.upload_files is None:
        print("Required parameters are missing.")
        exit(1)

    true_files, false_files = WebOSUploader.instance().exists(args.upload_files)
    server_files = WebOSUploader.instance().upload_files(args.key, true_files, args.url)
    for i, file in enumerate(true_files):
        print("[OK] '{}' : '{}'".format(file, server_files[i]))
    for file in false_files:
        print("[NO] '{}'".format(file))