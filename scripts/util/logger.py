import datetime

from sys import stdout

def timestamp(message):
    print('[TIMESTAMP][{}] {}'.format(datetime.datetime.now(), message))

def log(header, message):
    print('[{}] {}'.format(header, message))

def debug(message, force=False):
    import util.config as config
    if force is True:
        log('DEBUG', message)
    if config.get_value('developer', 'debug'):
        log('DEBUG', message)

def info(message, force=False):
    import core.config as config
    if force is True:
        log('INFO', message)
    if config.get_value('developer', 'info'):
        log('INFO', message)

def error(message):
    log('ERROR', message)