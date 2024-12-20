#!/usr/bin/python3

import subprocess
import datetime
import json
import base64
import hashlib
import logging

from sys import stdout
from cryptography.fernet import Fernet


####### CONFIG #######

WEBOS_CONFIG_1_BASE = '/etc/webos_config_1_base.json'
WEBOS_CONFIG_2_PRODUCT = '/etc/webos_config_2_product.json'
WEBOS_CONFIG_3_SERVER = '/var/luna/preferences/webos_config_3_server.json'
WEBOS_CONFIG_4_RUNTIME = '/var/luna/preferences/webos_config_4_runtime.json'

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

update_configs(WEBOS_CONFIG_1_BASE)
update_configs(WEBOS_CONFIG_2_PRODUCT)
update_configs(WEBOS_CONFIG_3_SERVER)
rw_configs = update_configs(WEBOS_CONFIG_4_RUNTIME)

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

    with open(WEBOS_CONFIG_4_RUNTIME, 'w') as json_file:
        json_file.write(json.dumps(rw_configs, indent=4, sort_keys=True))

def remove(first_key, second_key):
    if first_key not in rw_configs:
        return
    if second_key not in rw_configs[first_key]:
        return
    del rw_configs[first_key][second_key]
    if len(rw_configs[first_key]) == 0:
        del rw_configs[first_key]

    with open(WEBOS_CONFIG_4_RUNTIME, 'w') as json_file:
        json_file.write(json.dumps(rw_configs, indent=4, sort_keys=True))

def sync_config(config):
    contents = None
    try:
        with open(WEBOS_CONFIG_3_SERVER) as json_file:
            contents = json.load(json_file)
        json_file.close()
    except Exception as ex:
        info(ex)

    if contents == config:
        debug('The same config as before')
        return
    info('Write {}'.format(WEBOS_CONFIG_3_SERVER))
    with open(WEBOS_CONFIG_3_SERVER, 'w') as json_file:
        json_file.write(json.dumps(config, indent=4, sort_keys=True))
    # Read downloaded config
    update_configs(WEBOS_CONFIG_3_SERVER)
    rw_configs = update_configs(WEBOS_CONFIG_4_RUNTIME)


if __name__ == "__main__":
    print(json.dumps(mm_configs, indent=4, sort_keys=True))


####### LOGGER #######


def timestamp(message):
    print('[TIMESTAMP][{}] {}'.format(datetime.datetime.now(), message))

def log(header, message):
    print('[{}] {}'.format(header, message))

def debug(message, force=False):
    if force is True or get_value('developer', 'debug'):
        log('DEBUG', message)

def info(message, force=False):
    if force is True or get_value('developer', 'info'):
        log('INFO', message)

def warn(message):
    log('WARN', message)

def error(message):
    log('ERROR', message)

# python logging
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
root_logger = logging.getLogger()
root_logger.addHandler(console_handler)

def set_log_level(level):
    if level == 'debug':
        root_logger.setLevel(logging.DEBUG)
    elif level == 'info':
        root_logger.setLevel(logging.INFO)
    elif level == 'warning':
        root_logger.setLevel(logging.WARNING)
    elif level == 'error':
        root_logger.setLevel(logging.ERROR)
    elif level == 'critical':
        root_logger.setLevel(logging.CRITICAL)
    else:
        logging.warning('Invalid log level {}'.format(level))


####### NYX #######


# if build_id is larger than threshold, consider as master build_id.
OSE_BUILD_ID_THRESHOLD = 2000
# The difference between master build_id and ose build_id is 1735.
OSE_BUILD_ID_DIFF = 1735

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

        # convert OSE build_id to master build_id
        webos_build_id = self.info['webos_build_id']
        webos_name = self.info['webos_name']
        try:
            if 'OSE' == webos_name.split(' ')[1] and int(webos_build_id) < OSE_BUILD_ID_THRESHOLD:
                webos_build_id = str(int(webos_build_id) + OSE_BUILD_ID_DIFF)
        except:
            pass

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
        found_on = None
        webos_name = self.info['webos_name']
        try:
            # webOS Apollo Reference Minimal
            # webOS Apollo Reference Main
            # webOS TV Reference
            # webOS Signage Reference
            # webOS OSE
            # webOS Nano Reference Headless
            # webOS ACP Reference
            found_on = webos_name.split(' ')[1] + '-'
        except:
            return found_on
        device_names = get_value('deviceName')
        name = self.info['device_name']
        if name in device_names:
            found_on = found_on + device_names[name]
        else:
            found_on = found_on + name.upper()
        return found_on

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


class Crypto:
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
        self.f = Fernet(base64.urlsafe_b64encode(hashlib.sha256(b'rdx_credential').digest()))

    def encrypt(self, plaintext):
        return self.f.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext):
        return self.f.decrypt(ciphertext.encode()).decode()

    def b64encode(self, str):
        return base64.b64encode(str.encode()).decode()

    def b64decode(self, str):
        return base64.b64decode(str.encode()).decode()

