#Peripherals management

from DFC import *
from IFC import *


peripherals = {
    'DFC': { 'addr': 0xFFE00000, 'size': 0x7c, 'handler': DFC() },
    'IFC': { 'addr': 0xFFE04000, 'size': 0x7c, 'handler': IFC() }
}
