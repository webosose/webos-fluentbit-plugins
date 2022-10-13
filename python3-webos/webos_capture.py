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
DEFAULT_MESSAGES = '/tmp/webos_messages.tgz'
DEFAULT_SCREENSHOT = '/tmp/webos_screenshot.jpg'
DEFAULT_TCSTEPS = '/tmp/webos_tcsteps.txt'


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
        command = 'journalctl > {}'.format(file)
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

    def capture_messages(self, file=DEFAULT_MESSAGES):
        message_files = ['var/log/' + x for x in os.listdir("/var/log") if x[:8] == 'messages']
        if len(message_files) == 0:
            common.info('/var/log/messages does not exist')
            return
        command = 'tar zcf {} -C / {}'.format(file, ' '.join(message_files))
        common.debug(command)
        subprocess.check_output(command, shell=True, encoding='utf-8')
        print('Capture messages : {}'.format(file))
        return

    def capture_screenshot(self, file=DEFAULT_SCREENSHOT):
        if 'OSE' in NYX.instance().get_info()['webos_name']:
            args = '{{"output":"{}","format":"JPG"}}'.format(file)
            command = "luna-send -n 1 luna://com.webos.surfacemanager/captureCompositorOutput '{}'".format(args)
        else:
            args = '{{"path":"{}","method":"DISPLAY","width":1920,"height":1080,"format":"JPEG"}}'.format(file)
            command = "luna-send -n 1 luna://com.webos.service.capture/executeOneShot '{}'".format(args)
        common.debug(command)
        subprocess.check_output(command, shell=True, encoding='utf-8')
        print('Capture screenshot : {}'.format(file))
        return

    def capture_tcsteps(self, file=DEFAULT_TCSTEPS):
        if os.path.exists('/run/systemd/journal/socket'):
            command = "journalctl -q -t PmLogCtl -u dropbear | tail -n 500 > {}".format(file)
        else:
            command = "zgrep -h 'qa-tools\|automation-test' /var/log/messages* | tail -n 500 > {}".format(file)
        common.debug(command)
        subprocess.check_output(command, shell=True, encoding='utf-8')
        print('Capture tc steps info : {}'.format(file))
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--journald', type=str, help='capture journald')
    parser.add_argument('--sysinfo',  type=str, help='capture sysinfo')
    parser.add_argument('--coredump', type=str, nargs='*', help='capture coredump info')
    parser.add_argument('--messages', type=str, help='capture /var/log/messages*')
    parser.add_argument('--screenshot', type=str, help='capture screenshot')
    parser.add_argument('--tcsteps',  type=str, help='capture tc steps info')

    args = parser.parse_args()
    if args.journald is not None:
        WebOSCapture.instance().capture_journald(args.journald)
    if args.sysinfo is not None:
        WebOSCapture.instance().capture_sysinfo(args.sysinfo)
    if args.coredump is not None and len(args.coredump) == 2:
        WebOSCapture.instance().capture_coredump(args.coredump[0], args.coredump[1])
    if args.messages is not None:
        WebOSCapture.instance().capture_messages(args.messages)
    if args.screenshot is not None:
        WebOSCapture.instance().capture_screenshot(args.screenshot)
    if args.tcsteps is not None:
        WebOSCapture.instance().capture_tcsteps(args.tcsteps)
