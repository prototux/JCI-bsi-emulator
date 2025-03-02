# Interleaved Program Flash Memory Controller

class IFC:

    def __init__(self):
        pass

    def read(self, reg):
        print(f'[DEVICE][IFC] Trying to read 0x{reg:02x}')

    def write(self, reg, data):
        print(f'[DEVICE][IFC] Trying to write 0x{data:02x} in 0x{reg:02x}')
