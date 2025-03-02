#Peripherals management

from IFC import *

# List of peripherals, Devices with None handler are unsupported yet
peripherals = {
    'DFC':    { 'addr': 0xFFE00000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'IFC':    { 'addr': 0xFFE04000, 'size': 0x7c, 'handler': IFC() },
    'PWM':    { 'addr': 0xFFE08000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'ADC':    { 'addr': 0xFFE0C000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SPI0':   { 'addr': 0xFFE10000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'WD':     { 'addr': 0xFFE14000, 'size': 0x7c, 'handler': None },
    'CAN0':   { 'addr': 0xFFE18000, 'size': 0x7c, 'handler': None },
    'GPT':    { 'addr': 0xFFE1C000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'ST0':    { 'addr': 0xFFE20000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'ST1':    { 'addr': 0xFFE24000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'UART0':  { 'addr': 0xFFE28000, 'size': 0x7c, 'handler': None },
    'IOCONF': { 'addr': 0xFFE2C000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'STT':    { 'addr': 0xFFE30000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'UART1':  { 'addr': 0xFFE34000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'USART0': { 'addr': 0xFFE38000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'CAN1':   { 'addr': 0xFFE3C000, 'size': 0x7c, 'handler': None },
    'CAN2':   { 'addr': 0xFFE40000, 'size': 0x7c, 'handler': None },
    'CAN3':   { 'addr': 0xFFE44000, 'size': 0x7c, 'handler': None },
    'CAPT0':  { 'addr': 0xFFE48000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'CAPT1':  { 'addr': 0xFFE4C000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'I2C0':   { 'addr': 0xFFE50000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'I2C1':   { 'addr': 0xFFE54000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'LCDC':   { 'addr': 0xFFE58000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'ST2':    { 'addr': 0xFFE5C000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SPI1':   { 'addr': 0xFFE60000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'PIO0':   { 'addr': 0xFFE64000, 'size': 0x7c, 'handler': None },
    'PIO1':   { 'addr': 0xFFE68000, 'size': 0x7c, 'handler': None },
    'PIO2':   { 'addr': 0xFFE6C000, 'size': 0x7c, 'handler': None },
    'PIO3':   { 'addr': 0xFFE70000, 'size': 0x7c, 'handler': None },
    'SMC0':   { 'addr': 0xFFE74000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SMC1':   { 'addr': 0xFFE78000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SMC2':   { 'addr': 0xFFE7C000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SMC3':   { 'addr': 0xFFE80000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SMC4':   { 'addr': 0xFFE84000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SMC5':   { 'addr': 0xFFE88000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'EPC':    { 'addr': 0xFFFE0000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'SFM':    { 'addr': 0xFFFE4000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'CM':     { 'addr': 0xFFFE8000, 'size': 0x7c, 'handler': None },
    'IRC':    { 'addr': 0xFFFF0000, 'size': 0x7c, 'handler': None },
    'LDMAC':  { 'addr': 0xFFFF8000, 'size': 0x7c, 'handler': None }, # Unused on BSI
    'GIC':    { 'addr': 0xFFFFF000, 'size': 0x7c, 'handler': None },
}
