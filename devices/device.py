
# Base device
class Device:

    def __init__(self):
        self.regs = {}
        for name, data in self._registers.items():
            self.regs[data['offset']] = data['default']


    def _access(self, type, reg, data=None):
        for name, r in self._registers.items():
            if r['offset'] == reg:

                # Check flags vs access type
                if (r['flags'] == 'W' and type == 'R') or \
                   (r['flags'] == 'R' and type == 'W'):
                    print(f'[DEVICE][{self._name}] ERROR: Trying to {type} a register with {r["access"]} flags!')

                # Generic log
                print(f'[DEVICE][{self._name}] Access register {name}:{type} (0x{data:02x})')

                # Check if method exists
                method = getattr(self, f'{name}_{type}', None)
                if method and callable(method):
                    method(data) if data else method()
                # Generic access: simple write and read registers
                elif type == 'R':
                    return self.regs[r['offset']]
                elif type == 'W':
                    self.regs[r['offset']] = data


    def _read(self, reg):
        return self._access('R', reg)

    def _write(self, reg, data):
        self._access('W', reg, data)
