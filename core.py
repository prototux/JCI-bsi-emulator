from unicorn import * #Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import *
from capstone import *
import struct
import hexdump
import sys

from devices import *


# Memory map configuration
ROM_BASE = 0x40000000 # 0x00000000
ROM_SIZE = 0x00100000  # 1MB

RAM_BASE = 0x00000000 # 0x00300000
RAM_SIZE = 0x00008000  # 32KB

DEVICE_BASE = 0xFFE00000
DEVICE_SIZE = 0x00200000 # Until the end


class ARMv7Emulator:
    def __init__(self, rom_file):
        # Load ROM
        with open(rom_file, 'rb') as f:
            self.rom_data = f.read()

        self.mode = 'ARM'

        self.init(0x4000000)

        self.breakpoints = []

        # Start and skip entrypoint
        self.mu.emu_start(0x40000000, 0xffffffff, count=5)

    def init(self, pc):
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM|UC_MODE_THUMB)
        #self.mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB if self.mode == 'THUMB' else UC_MODE_ARM, UC_CPU_ARM_CORTEX_A15)

        # Map memory
        self.mu.mem_map(ROM_BASE, ROM_SIZE)
        self.mu.mem_map(RAM_BASE, RAM_SIZE)
        self.mu.mem_map(DEVICE_BASE, DEVICE_SIZE)

        # Disasm
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if self.mode == 'THUMB' else CS_MODE_ARM)

        # Load "flash"
        self.mu.mem_write(ROM_BASE, self.rom_data[:ROM_SIZE])

        # Add memory hooks
        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.mem_hook)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code, None)

        self.mu.reg_write(UC_ARM_REG_PC, pc)

    def dis(self, code):
        dis = self.cs.disasm(code, 0x0)
        ret = ''
        for i in dis:
            ret += f'{i.mnemonic} {i.op_str}'
        return ret

    # ARM/THUMB switch management
    def switchmode(self, newmode):
        # We didn't actually switch, all is okay
        if self.mode == newmode:
            return

        # We do switch
        print(f'[MODE] Switch from {self.mode} to {newmode}')
        self.mode = newmode
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB if newmode == 'THUMB' else CS_MODE_ARM)

    def hook_code(self, uc, address, size, user_data):
        # Handle breakpoints
        for bp in self.breakpoints:
            if address == bp:
                print(f'[BREAKPOINT] Hit bp at {address}')
                self.mu.emu_stop()
                self.breakpoints.remove(bp)

        for name, p in peripherals.items():
            if not p["handler"]:
                continue

            if hasattr(p['handler'], "update"):
                try:
                    p['handler'].update()
                except NameError:
                    print(f"[DEVICE][{name}] Handler has \"update\" but its not callable!")

        # print(f'CPSR reg: 0x{self.mu.reg_read(UC_ARM_REG_CPSR):02x}')
        if ROM_BASE <= address < ROM_BASE + ROM_SIZE:
            offset = address - ROM_BASE
            instr_bytes = self.rom_data[offset:offset+size]
            instr_hex = ' '.join(f"{b:02X}" for b in instr_bytes)

            #print(f'CPSR reg: 0x{self.mu.reg_read(UC_ARM_REG_CPSR):02x}')

            print(f"[CODE] Executing at {hex(address)}, size: {size} bytes, instruction: {instr_hex} ({self.dis(instr_bytes)})")

    def mem_hook(self, uc, access, address, size, value, user_data):
        # Handle devices, first check that we're indeed in the devices memory space
        if address >= DEVICE_BASE and address < (DEVICE_BASE + DEVICE_SIZE):
            for name, p in peripherals.items():
                if address >= p['addr'] and address < p['addr']+p['size']:

                    # Device isn't supported, get the fuck out of here
                    if not p['handler']:
                        print(f'[DEVICE] Error: device {name} is not supported!')
                        break

                    # Send request to device
                    print(f'[DEVICE] Device {name} access @ 0x{address:02x}')
                    if access == UC_MEM_READ:
                        toReadValue = p['handler']._read(address-p['addr'])
                        self.mu.mem_write(address, struct.Struct('<I').pack(toReadValue))
                    elif access == UC_MEM_WRITE:
                        p['handler']._write(address-p['addr'], value)

    def start(self):
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        if self.mode == 'THUMB':
            pc += 1
        try:
            self.mu.emu_start(pc, 0xfffffffff)
        except Exception as e:
            print(f"[ERROR] {e}")

    def step(self):
        pc = self.mu.reg_read(UC_ARM_REG_PC)
        if self.mode == 'THUMB':
            pc += 1
        try:
            self.mu.emu_start(pc, pc + 2 if self.mode == 'THUMB' else 4, count=1)
        except Exception as e:
            print(f"[ERROR] {e}")

    def dump_memory(self, base, size, label):
        print(f"\n[Dumping {label}] {hex(base)} - {hex(base + size)}")
        data = self.mu.mem_read(base, min(size, 256))  # Limit the output size
        hexdump.hexdump(data)

    def memdump(self, path):
        ram = self.mu.mem_read(0x000000000, 32*1024)
        with open(path, 'wb') as file:
            file.write(ram)

    def dump_registers(self):
        registerNames = { 3: 'CPSR', 10: 'LR', 11: 'PC', 12: 'SP', 66: 'R0', 67: 'R1', 68: 'R2', 69: 'R3', 
                 70: 'R4', 71: 'R5', 72: 'R6', 73: 'R7', 74: 'R8', 75: 'R9', 76: 'R10', 77: 'R11', 
                 78: 'R12' }
        registers = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                     UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                     UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR]
        print("\n--------[CPU Registers]---------")
        print("|   Register   |     Value     |");
        print("|--------------|---------------|");
        for reg in registers:
            registerName = registerNames[reg]
            registerSpaces = max(0, 12 - len(registerName)) * " "
            registerValue = hex(self.mu.reg_read(reg));
            registerValSpaces = max(0, 12 - len(registerValue)) * " "
            print(f"| {registerName} {registerSpaces}| {registerValue} {registerValSpaces} |")

        print("--------------------------------")

    def dump_system_state(self):
        self.dump_memory(ROM_BASE, ROM_SIZE, "ROM")
        self.dump_memory(RAM_BASE, RAM_SIZE, "RAM")
        self.dump_registers()
        print(f"\n[IFC_MR] {hex(self.ifc_mr)}, IFC Base: {hex(self.ifc_base)}")

    def manage_breakpoints(self):
        while True:
            
            print("\n|-[Breakpoints]-|")
            if len(self.breakpoints) != 0:
                print("|---------------|")
                for bp in self.breakpoints:
                    bpStr = hex(bp)
                    bpSpaces = max(0, 13 - len(bpStr)) * " "
                    print(f"| {bpStr} {bpSpaces}|")
            else:
                print("|  !! EMPTY !!  |")
            print("|---------------|")

            print("\n1. Back to main menu")
            print("2. Add Breakpoint")

            if len(self.breakpoints) != 0:
                print("3. Remove breakpoint")

            choice = input("Select an option: ")
            if choice == '1' or choice == '':
                break
            elif choice == '2':
                addr = int(input("Address: "), 16)
                self.breakpoints.append(addr)
            elif choice == '3' and len(self.breakpoints) != 0:
                print("\n|  Num  | Breakpoint |")
                print("|-------|------------|")
                counter = 0
                for bp in self.breakpoints:
                    counter += 1
                    number = str(counter)
                    bpStr = str(bp)
                    numberSpaces = max(0, 3 - len(number)) * " "
                    bpSpaces = max(0, 10 - len(bpStr)) * " "
                    print(f"| [{number}] {numberSpaces}| {bpStr} {bpSpaces}|")
                print("|-------|------------|")

                nbr = int(input("Type number to delete: ")) - 1

                if nbr < 0 or nbr >= len(self.breakpoints):
                    print("Invalid delete input!")
                    continue

                self.breakpoints.remove(self.breakpoints[nbr])



    # Shit, should be removed
    def menu(self):
        checkInstructionSet = True
        while True:
            # For whatever fucking reasion it will change instruction set when you jump address sometimes
            # idk this checkInstructionSet is also a stupid hack, why cant this just work
            if checkInstructionSet:
                self.switchmode('THUMB' if self.mu.reg_read(UC_ARM_REG_CPSR) & 0x20 else 'ARM')
            else:
                checkInstructionSet = True

            print("\nMenu:")
            print("1. Step Over Instruction")
            print("2. Start Emulation")
            print("3. Show Memory Dump")
            print("4. Show Registers")
            print("5. Show ROM Dump")
            print("6. Manage breakpoints")
            print("7. Write memdump")
            print("8. Jump to Address")
            print("0. Exit")
            choice = input("Select an option: ")

            if choice == '1' or choice == '':
                checkInstructionSet = True
                self.step()
            elif choice == '2':
                checkInstructionSet = True
                self.start()
            elif choice == '3':
                self.dump_memory(RAM_BASE, RAM_SIZE, "RAM")
            elif choice == '4':
                self.dump_registers()
            elif choice == '5':
                self.dump_memory(ROM_BASE, ROM_SIZE, "ROM")
            elif choice == '6':
                self.manage_breakpoints()
            elif choice == '7':
                self.memdump(input("File path: "))
            elif choice == '8':
                addr = int(input("Jump to: "), 16)
                self.mu.reg_write(UC_ARM_REG_PC, addr)
                checkInstructionSet = False
            elif choice == '0':
                sys.exit(0)
            else:
                print("Invalid option, try again.")

