import subprocess

UNKNOWN = '<unknown>'

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
        self.info['webos_release']     = self.query('OSInfo', 'webos_release')

    def query(self, category, name):
        try:
            result = subprocess.check_output(['nyx-cmd', category, 'query', name])
            result = result.decode("utf-8").rstrip()
            return result
        except:
            return UNKNOWN

    def get_info(self):
        return self.info

    def print(self):
        print('serial_number: {}'.format(self.info['serial_number']))
        print('product_id: {}'.format(self.info['product_id']))
        print('hardware_revision: {}'.format(self.info['hardware_revision']))
        print('nduid: {}'.format(self.info['nduid']))
        print('device_name: {}'.format(self.info['device_name']))
        print('webos_build_id: {}'.format(self.info['webos_build_id']))
        print('webos_imagename: {}'.format(self.info['webos_imagename']))
        print('webos_release: {}'.format(self.info['webos_release']))

if __name__ == "__main__":
    NYX.instance().print()
