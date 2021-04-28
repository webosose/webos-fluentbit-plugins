#!/usr/bin/python3

import argparse
import os
import json
import subprocess

import webos_common as common

from webos_common import NYX
from webos_common import Platform

DEFAULT_JOURNALD='/tmp/webos_journald.txt'
DEFAULT_INFO='/tmp/webos_info.txt'
DEFAULT_DUMP='/tmp/webos_dump.txt'

class WebOSCapture:
    _instance = None

    @classmethod
    def _getInstance(cls):
        return cls._instance

    @classmethod
    def instance(cls, *args, **kargs):
        cls._instance = cls(*args, **kargs)
        cls.instance = cls._getInstance
        return cls._instance

    @classmethod
    def get_header(cls, tag):
        result = '\n\n##@@## {} @@##@@\n'.format(tag)
        return result

    def __init__(self):
        self.file = None
        return

    def open(self, filename):
        try:
            self.file = open(filename, "w")
        except:
            return

    def write(self, tag, message):
        header = WebOSCapture.get_header(tag)
        if self.file is not None:
            self.file.write(header)
            self.file.write(message)
        else:
            print(header)
            print(message)

    def close(self):
        if self.file is not None:
            self.file.close()
            self.file = None
        return

    def capture_journald(self, file=DEFAULT_JOURNALD):
        command =  'journalctl > {}'.format(file)
        subprocess.check_output(command, shell=True, encoding='utf-8')
        print('Capture Journald : {}'.format(file))
        return

    def capture_sysinfo(self, file=DEFAULT_INFO):
        WebOSCapture.instance().open(file)
        WebOSCapture.instance().write('INFO', json.dumps(NYX.instance().get_info(), indent=4, sort_keys=True))

        for command in common.get_value('platform', 'commands'):
            result = Platform.instance().execute(command)
            WebOSCapture.instance().write(command, result)

        for f in common.get_value('platform', 'files'):
            result = Platform.instance().cat(f)
            WebOSCapture.instance().write(f, result)
        WebOSCapture.instance().close()
        print('Capture sysinfo : {}'.format(file))
        return

    def capture_coredump(self, in_file, out_file=DEFAULT_DUMP):
        # example name#1 : coredump/core.coreexam_ose.0.c7294e397ec747f98552c7c459f7dc1c.2434.1619053570000000.xz
        # example name#2 : core.com\x2ewebos\x2eservi.0.570dc828a3934019bdcd9317dfe1d0e2.613.1619578312000000.xz
        pid = os.path.basename(in_file).split('.')[-3]
        command = 'journalctl -t systemd-coredump | grep {}'.format(pid)

        print('COMMAND: {}'.format(command))
        output = subprocess.check_output(command, shell=True, encoding='utf-8')
        print('RESULT: {}'.format(output))

        l_index = output.find('[') + 1
        r_index = output.find(']')
        command = 'journalctl -t systemd-coredump _PID={} -o verbose > {}'.format(output[l_index:r_index], out_file)

        print('COMMAND: {}'.format(command))
        output = subprocess.check_output(command, shell=True, encoding='utf-8')
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--journald', type=str, help='capture journald')
    parser.add_argument('--sysinfo',  type=str, help='capture sysinfo')
    parser.add_argument('--coredump', type=str, nargs='*', help='capture coredump info')

    args = parser.parse_args()
    if args.journald is not None:
        WebOSCapture.instance().capture_journald(args.journald)
    if args.sysinfo is not None:
        WebOSCapture.instance().capture_sysinfo(args.sysinfo)
    if args.coredump is not None and len(args.coredump) == 2:
        WebOSCapture.instance().capture_coredump(args.coredump[0], args.coredump[1])
