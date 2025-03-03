# Interleaved Program Flash Memory Controller

from devices.device import Device

class IFC(Device):
    _name = 'IFC'
    _address = 0xFFE04000
    _size = 0x7c
    _registers = {
        'PSMR': { 'offset': 0x058, 'flags': 'R', 'default': 0x00000000 },
        'CR': { 'offset': 0x060, 'flags': 'W', 'default': 0x00000000 },
        'MR': { 'offset': 0x064, 'flags': 'RW', 'default': 0x00000080 },
        'CSR': { 'offset': 0x06C, 'flags': 'W', 'default': 0x00000000 },
        'SR': { 'offset': 0x070, 'flags': 'W', 'default': 0x00000000 },
        'IER': { 'offset': 0x074, 'flags': 'W', 'default': 0x00000000 },
        'IDR': { 'offset': 0x078, 'flags': 'W', 'default': 0x00000000 },
        'IMR': { 'offset': 0x07C, 'flags': 'W', 'default': 0x00000000 },
    }

    def __init__(self):
        # MR flags
        self.base_addr = 0x00
        self.wpr = 0
        self.standen = 0
        self.speedmode = 0

        super(IFC, self).__init__()

    # Write to CR
    def CR_W(self, data):
        sector = (data&0xfc000000)>>26
        crkey = (data&0x0000ff00)>>8
        chip_erase = (data&0x00000040)>>2
        sector_erase = (data&0x00000020)>>1

        if not crkey == 0x37:
            print('ERROR: invalid CR key')
            return

    # Write to MR handler
    def MR_W(self, data):
        mrkey = (data&0x00ff0000)>>16
        if not mrkey == 0xac:
            print('ERROR: invalid MR key')
            return

        self.base_addr = (data&0xff000000)>>24
        self.wpr = (data&0x00000080)>>7
        self.standen = (data&0x00000010)>>4 # ignored
        self.speedmode = (data&0x00000004)>>2 # ignored

        print(f'write to MR: ba={self.base_addr:x}')

