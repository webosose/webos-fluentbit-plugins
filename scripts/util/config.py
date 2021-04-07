import json

from pprint import pprint
from datetime import date
from datetime import timedelta

RO_CONFIG = 'webos_jira_ro.json'
RW_CONFIG = 'webos_jira_rw.json'

with open(RO_CONFIG) as json_file:
    mm_configs = json.load(json_file)

with open(RW_CONFIG) as json_file:
    rw_configs = json.load(json_file)
    for config in rw_configs:
        mm_configs[config] = rw_configs[config]

def get_value(first_key, second_key=None, third_key=None):
    if second_key is None:
        return mm_configs[first_key]
    elif third_key is None:
        return mm_configs[first_key][second_key]
    else:
        return mm_configs[first_key][second_key][third_key]

def set_value(first_key, second_key, third_key, value):
    with open(RW_CONFIG, 'w') as json_file:
        if second_key is None:
            mm_configs[first_key] = value
            rw_configs[first_key] = value
        elif third_key is None:
            if first_key not in rw_configs:
                mm_configs[first_key] = {}
                rw_configs[first_key] = {}
            mm_configs[first_key][second_key] = value
            rw_configs[first_key][second_key] = value
        else:
            if first_key not in rw_configs:
                mm_configs[first_key] = {}
                mm_configs[first_key][second_key] = {}
                rw_configs[first_key] = {}
                rw_configs[first_key][second_key] = {}
            mm_configs[first_key][second_key][third_key] = value
            rw_configs[first_key][second_key][third_key] = value
        json_file.write(json.dumps(rw_configs, indent=4, sort_keys=True))
