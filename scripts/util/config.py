import json
import sys
import util.logger as logger

from pprint import pprint
from datetime import date
from datetime import timedelta

with open('webos_jira_ro.json') as json_file:
    configs = json.load(json_file)

with open('webos_jira_rw.json') as json_file:
    rw_configs = json.load(json_file)
    for config in rw_configs:
        configs[config] = rw_configs[config]

def get_value(first_key, second_key=None, third_key=None):
    if second_key is None:
        return configs[first_key]
    elif third_key is None:
        return configs[first_key][second_key]
    else:
        return configs[first_key][second_key][third_key]

def set_value(first_key, second_key, third_key, value):
    if second_key is None:
        configs[first_key] = value
    elif third_key is None:
        configs[first_key][second_key] = value
    else:
        configs[first_key][second_key][third_key] = value