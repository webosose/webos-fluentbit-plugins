import subprocess

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
