#!/usr/bin/python3

import subprocess
import datetime
import json

from sys import stdout


####### CONFIG #######


mm_configs = {}
rw_configs = {}

def update_config(first_key, configs):
    if first_key not in mm_configs:
        mm_configs[first_key] = configs
        return

    for second_key in configs:
        if second_key not in mm_configs[first_key]:
            mm_configs[first_key][second_key] = configs[second_key]
            continue
        if type(configs[second_key]) != type(mm_configs[first_key][second_key]):
            print('Type mismatch {} {}'.format(first_key, second_key))
            continue

        if isinstance(configs[second_key], list):
            s = set(mm_configs[first_key][second_key])
            s.update(configs[second_key])
            mm_configs[first_key][second_key] = list(s)
        elif isinstance(configs[second_key], dict):
            mm_configs[first_key][second_key].update(configs[second_key])
        else:
            mm_configs[first_key][second_key] = configs[second_key]

def update_configs(file):
    json_content = None
    try:
        with open(file) as json_file:
            json_content = json.load(json_file)
            for first_key in json_content:
                update_config(first_key, json_content[first_key])
    except:
        json_content = {}
    return json_content

update_configs('/etc/webos_config_1.json')
update_configs('/etc/webos_config_2.json')
rw_configs = update_configs('/var/luna/preferences/webos_rdx.json')

def get_value(first_key, second_key=None):
    try:
        if second_key is None:
            return mm_configs[first_key]
        return mm_configs[first_key][second_key]
    except:
        return None

def set_value(first_key, second_key, value):
    if first_key not in rw_configs:
        mm_configs[first_key] = {}
        rw_configs[first_key] = {}
    mm_configs[first_key][second_key] = value
    rw_configs[first_key][second_key] = value

    with open('/var/luna/preferences/webos_rdx.json', 'w') as json_file:
        json_file.write(json.dumps(rw_configs, indent=4, sort_keys=True))

if __name__ == "__main__":
    print(json.dumps(mm_configs, indent=4, sort_keys=True))


####### LOGGER #######


def timestamp(message):
    print('[TIMESTAMP][{}] {}'.format(datetime.datetime.now(), message))

def log(header, message):
    print('[{}] {}'.format(header, message))

def debug(message, force=False):
    if force is True:
        log('DEBUG', message)
    if get_value('developer', 'debug'):
        log('DEBUG', message)

def info(message, force=False):
    if force is True:
        log('INFO', message)
    if get_value('developer', 'info'):
        log('INFO', message)

def error(message):
    log('ERROR', message)


####### NYX #######


class NYX:
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
        self.info = {}
        self.info['serial_number']     = self.query('DeviceInfo', 'serial_number')
        self.info['product_id']        = self.query('DeviceInfo', 'product_id')
        self.info['hardware_revision'] = self.query('DeviceInfo', 'hardware_revision')
        self.info['nduid']             = self.query('DeviceInfo', 'nduid')
        self.info['device_name']       = self.query('DeviceInfo', 'device_name')
        self.info['webos_build_id']    = self.query('OSInfo', 'webos_build_id')
        self.info['webos_imagename']   = self.query('OSInfo', 'webos_imagename')
        self.info['webos_name']        = self.query('OSInfo', 'webos_name')
        self.info['webos_release']     = self.query('OSInfo', 'webos_release')

    def query(self, category, name):
        try:
            result = subprocess.check_output(['nyx-cmd', category, 'query', name], stderr=subprocess.DEVNULL)
            result = result.decode("utf-8").rstrip()
            return result
        except:
            return '<unknown>'

    def get_info(self):
        return self.info

    def get_found_on(self):
        device_names = get_value('deviceName')
        name = self.info['device_name']

        if name in device_names:
            return device_names[name]
        # The device_name can be the same in the upper layer of webos,
        # So distinguish by adding the webos_name; 'webOS XX Reference'
        webos_name = self.info['webos_name']
        try:
            return webos_name.split(' ')[1] + '-' + name.upper()
        except:
            return None


    def print(self):
        print('serial_number: {}'.format(self.info['serial_number']))
        print('product_id: {}'.format(self.info['product_id']))
        print('hardware_revision: {}'.format(self.info['hardware_revision']))
        print('nduid: {}'.format(self.info['nduid']))
        print('device_name: {}'.format(self.info['device_name']))
        print('webos_build_id: {}'.format(self.info['webos_build_id']))
        print('webos_imagename: {}'.format(self.info['webos_imagename']))
        print('webos_name: {}'.format(self.info['webos_name']))
        print('webos_release: {}'.format(self.info['webos_release']))


####### Platform #######


class Platform:
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

    def execute(self, command):
        result = None
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, encoding='utf-8')
        except:
            result = 'Failed to execute the command'
        return result

    def cat(self, file):
        result = None
        try:
            result = subprocess.check_output('cat {}'.format(file), shell=True, stderr=subprocess.DEVNULL, encoding='utf-8')
        except:
            result = 'Failed to read the file'
        return result
