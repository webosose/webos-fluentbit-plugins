import subprocess

FAIL='Failed to get information'

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
        header = Platform.get_header(tag)
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

    def execute(self, commands):
        for command in commands:
            result = None
            try:
                result = subprocess.check_output(command, shell=True, encoding='utf-8')
            except:
                result = FAIL
            self.write(command, result)

    def cat(self, files):
        for file in files:
            result = None
            try:
                result = subprocess.check_output('cat {}'.format(file), shell=True, encoding='utf-8')
            except:
                result = FAIL
            self.write(file, result)

if __name__ == "__main__":
    Platform.instance().open('test.txt')
    Platform.instance().execute(["uptime", "df -h", "ps aux", "date -R", "ls -l /var/luna/preferences"])
    Platform.instance().cat(["/proc/cpuinfo", "/sys/class/mmc_host/mmc0/mmc0:0001/manfid", "/sys/class/mmc_host/mmc0/mmc0:0001/oemid", "/sys/class/mmc_host/mmc0/mmc0:0001/serial", "/proc/mounts"])
    Platform.instance().close()

