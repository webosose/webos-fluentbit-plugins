import os
import shutil

from datetime import date
from jira import JIRA
from jira_cache import CachedIssues

import util.config as config
import util.logger as logger

class Connection:
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
        self._jira = None
        return

    def _connect(self):
        if self._jira is not None:
            return
        url = config.get_value('jira', 'url')
        id = config.get_value('account', 'id')
        pw = config.get_value('account', 'pw')
        logger.debug("Try to connect '{}'".format(url))
        self._jira = JIRA(url, auth=(id, pw), timeout=30)
        logger.debug("Connection is ready")


    def get_connection(self):
        return self._jira

    # this method is not support cache
    def issue(self, name):
        self._connect()
        return self._jira.issue(name)

    def search_issues(self, name, filter, members):
        CACHE_PATH = config.get_value('settings', 'cache_path')
        CACHE_MODE = config.get_value('settings', 'cache_mode')
        if CACHE_MODE is False:
            self._connect()
            return self._jira.search_issues(filter, fields=members)

        # check cache validataion
        path = os.path.join(CACHE_PATH, date.today().isoformat())
        if os.path.exists(path) is False:
            shutil.rmtree(CACHE_PATH, ignore_errors=True)
            os.makedirs(CACHE_PATH, mode=0o777)
            open(path, 'w')

        path = os.path.join(CACHE_PATH, name)
        result = None
        if os.path.exists(path) is False:
            logger.debug("Cannot find cache. Try to get '{}' from server and saved at '{}'".format(name, path))
            self._connect()
            result = self._jira.search_issues(filter, maxResults=200, fields=members)
            cached = CachedIssues(result)
            cached.dump(open(path, 'w'))
        else:
            result = CachedIssues.load(open(path))
        return result

