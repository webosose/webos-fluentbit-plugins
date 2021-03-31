import argparse
import shutil
import os
import sys

from pprint import pprint

from util.connection import Connection

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--summary',             type = str, default='[Unknown]')
    parser.add_argument('--description',         type = str, default='[Unknown]')
    parser.add_argument('--attachments',         type = str, nargs='*', help='Force overwrite fixed-version')
    parser.add_argument('--upload-files',        type = str, nargs='*', help='Force overwrite fixed-version')
    parser.add_argument('--id',                  type = str)
    parser.add_argument('--pw',                  type = str)
    parser.add_argument('--without-systestinfo', action='store_true', help='Remove Cache Files')

    args = parser.parse_args()
    issue = Connection.instance().issue('PLAT-128367')

    pprint(issue)