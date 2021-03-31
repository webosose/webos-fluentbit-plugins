import json
import sys
import util.logger as logger

from pprint import pprint
from datetime import date
from datetime import timedelta

with open('jira_report.json') as json_file:
    json_data = json.load(json_file)

def get_value(first_key, second_key=None, third_key=None):
    if second_key is None:
        return json_data[first_key]
    elif third_key is None:
        return json_data[first_key][second_key]
    else:
        return json_data[first_key][second_key][third_key]

def set_value(first_key, second_key, third_key, value):
    if second_key is None:
        json_data[first_key] = value
    elif third_key is None:
        json_data[first_key][second_key] = value
    else:
        json_data[first_key][second_key][third_key] = value