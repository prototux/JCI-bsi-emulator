# Data Flash Controller
## NB: isn't used in BSI
class DFC:

    def __init__(self):
        pass

    def read(self, reg):
        print(f'[DEVICE][DFC] Trying to read 0x{reg:02x}')

    def write(self, reg, data):
        print(f'[DEVICE][DFC] Trying to write 0x{data:02x} in 0x{reg:02x}')
