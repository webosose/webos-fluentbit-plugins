import argparse
import os
import json

import util.logger as logger
import util.config as config

from base.nyx import NYX
from base.platform import Platform

DEFAULT_FILE='/tmp/webos_info.txt'

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

    def __init__(self):
        return

    def generate(self, file=DEFAULT_FILE):
        Platform.instance().open(file)
        Platform.instance().write('INFO', json.dumps(NYX.instance().get_info(), indent=4, sort_keys=True))
        Platform.instance().execute(config.get_value('platform', 'commands'))
        Platform.instance().cat(config.get_value('platform', 'files'))
        Platform.instance().close()
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=os.path.basename(__file__))
    parser.add_argument('--file', type=str, default=DEFAULT_FILE, help='Generated file name')

    args = parser.parse_args()
    WebOSInfo.instance().generate(args.file)
