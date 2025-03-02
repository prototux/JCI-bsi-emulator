from unicorn import * #Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import *

from capstone import *

import hexdump

from peripherals import *


# Memory map configuration
ROM_BASE = 0x40000000 # 0x00000000
ROM_SIZE = 0x00100000  # 1MB

RAM_BASE = 0x00000000 # 0x00300000
RAM_SIZE = 0x00008000  # 32KB

DEVICE_BASE = 0xFFE00000
DEVICE_SIZE = 0x00200000 # Until the end

class ARMv7Emulator:
    def __init__(self, rom_file):
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        # Map memory
        self.mu.mem_map(ROM_BASE, ROM_SIZE)
        self.mu.mem_map(RAM_BASE, RAM_SIZE)
        self.mu.mem_map(DEVICE_BASE, DEVICE_SIZE)

        # Disasm
        self.disasm = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        # Load ROM
        with open(rom_file, 'rb') as f:
            self.rom_data = f.read()
            self.mu.mem_write(ROM_BASE, self.rom_data[:ROM_SIZE])

        # Add memory hooks
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.mem_hook)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code, None)

        # Start and skip entrypoint
        self.mu.emu_start(0x40000000, 0xffffffff, count=5)

    def dis(self, code):
        dis = self.disasm.disasm(code, 0x0)
        ret = ''
        for i in dis:
            ret += f'{i.mnemonic} {i.op_str}'
        return ret

    def hook_code(self, uc, address, size, user_data):
        if ROM_BASE <= address < ROM_BASE + ROM_SIZE:
            offset = address - ROM_BASE
            instr_bytes = self.rom_data[offset:offset+size]
            instr_hex = ' '.join(f"{b:02X}" for b in instr_bytes)
            print(f"[CODE] Executing at {hex(address)}, size: {size} bytes, instruction: {instr_hex} ({self.dis(instr_bytes)})")

    def mem_hook(self, uc, access, address, size, value, user_data):
        # Handle devices
        if address > DEVICE_BASE and address < (DEVICE_BASE + DEVICE_SIZE):
            print(f'[DEVICE] Device access @ 0x{address:02x}')

    def step(self):
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        try:
            self.mu.emu_start(pc, pc + 4, count=1)
        except Exception as e:
            print(f"[ERROR] {e}")

    def dump_memory(self, base, size, label):
        print(f"\n[Dumping {label}] {hex(base)} - {hex(base + size)}")
        data = self.mu.mem_read(base, min(size, 256))  # Limit the output size
        hexdump.hexdump(data)

    def dump_registers(self):
        registers = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                     UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                     UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR]
        print("\n[CPU Registers]")
        for reg in registers:
            print(f"{reg}: {hex(self.mu.reg_read(reg))}")

    def dump_system_state(self):
        self.dump_memory(ROM_BASE, ROM_SIZE, "ROM")
        self.dump_memory(RAM_BASE, RAM_SIZE, "RAM")
        self.dump_registers()
        print(f"\n[IFC_MR] {hex(self.ifc_mr)}, IFC Base: {hex(self.ifc_base)}")


    # Shit, should be removed
    def menu(self):
        while True:
            print("\nMenu:")
            print("1. Step Over Instruction")
            print("2. Show Memory Dump")
            print("3. Show Registers")
            print("4. Show ROM Dump")
            print("5. Exit")
            choice = input("Select an option: ")

            if choice == '1':
                self.step()
            elif choice == '2':
                self.dump_memory(RAM_BASE, RAM_SIZE, "RAM")
            elif choice == '3':
                self.dump_registers()
            elif choice == '4':
                self.dump_memory(ROM_BASE, ROM_SIZE, "ROM")
            elif choice == '5':
                sys.exit(0)
            else:
                print("Invalid option, try again.")


if __name__ == "__main__":
    emulator = ARMv7Emulator("bootloader.bin")
    emulator.menu()
