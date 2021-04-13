import argparse
import os
import json
import subprocess

import util.logger as logger
import util.config as config

from base.nyx import NYX
from base.platform import Platform

DEFAULT_JOURNALD='/tmp/webos_journald.txt'
DEFAULT_INFO='/tmp/webos_info.txt'

class WebOSInfo:
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
        header = WebOSInfo.get_header(tag)
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
        return

    def capture_info(self, file=DEFAULT_INFO):
        WebOSInfo.instance().open(file)
        WebOSInfo.instance().write('INFO', json.dumps(NYX.instance().get_info(), indent=4, sort_keys=True))

        for command in config.get_value('platform', 'commands'):
            result = Platform.instance().execute(command)
            WebOSInfo.instance().write(command, result)

        for file in config.get_value('platform', 'files'):
            result = Platform.instance().cat(file)
            WebOSInfo.instance().write(file, result)
        WebOSInfo.instance().close()
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--journald', type=str, default=DEFAULT_JOURNALD, help='journald file name')
    parser.add_argument('--info',     type=str, default=DEFAULT_INFO, help='info file name')

    args = parser.parse_args()
    WebOSInfo.instance().capture_journald(args.journald)
    WebOSInfo.instance().capture_info(args.info)
