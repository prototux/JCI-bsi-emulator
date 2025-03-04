# Clock Manager

MASTER_OSCILLATOR_FREQ  = 4000000  # Default 4MHz
RING_OSCILLATOR_FREQ    = 1000000  # Default 1MHz

from devices.device import Device

class CM(Device):
    _name = 'CM'
    _address = 0xFFFE8000
    _size = 0x07C
    _registers = {
        'STR':    { 'offset': 0x000,  'flags': 'R',     'default': 0x00000006 },
        'WFIR':   { 'offset': 0x008,  'flags': 'RW',    'default': 0x00000000 },
        'PSTR':   { 'offset': 0x00C,  'flags': 'RW',    'default': 0x00000154 },
        'PDPR':   { 'offset': 0x010,  'flags': 'RW',    'default': 0x00000000 }, # 0x00XXXXXX
        'OSTR':   { 'offset': 0x014,  'flags': 'RW',    'default': 0x00002EE0 },
        'DIVBR':  { 'offset': 0x01C,  'flags': 'RW',    'default': 0x00077777 },
        'SELR':   { 'offset': 0x020,  'flags': 'RW',    'default': 0x00000000 },
        'RSR':    { 'offset': 0x024,  'flags': 'R',     'default': 0x00000000 }, # 0x0000000X
        'MDIVR':  { 'offset': 0x028,  'flags': 'RW',    'default': 0x000001FF },
        'LFOSCR': { 'offset': 0x02C,  'flags': 'RW',    'default': 0x00000001 },
        'CR':     { 'offset': 0x030,  'flags': 'W',     'default': 0x00000000 },
        'MR':     { 'offset': 0x064,  'flags': 'RW',    'default': 0x00000000 },
        'CSR':    { 'offset': 0x06C,  'flags': 'W',     'default': 0x00000000 },
        'SR':     { 'offset': 0x070,  'flags': 'R',     'default': 0x00000000 },
        'IER':    { 'offset': 0x074,  'flags': 'W',     'default': 0x00000000 },
        'IDR':    { 'offset': 0x078,  'flags': 'W',     'default': 0x00000000 },
        'IMR':    { 'offset': 0x07C,  'flags': 'R',     'default': 0x00000000 },
    }
    _modes = {
        0: 'NORMAL',
        1: 'HIGHSPEED',
        2: 'SLOW',
        3: 'LOWPOWER'
    }

    def __init__(self):
        super(CM, self).__init__()

        # OPERATION VALUES

        # Clocks enabled 
        self.current_mode = "NORMAL" 
        self.previous_mode = "NORMAL" 
        self.transition_in_progress = False
        self.pll_enabled = False 

        self.clock_sources = {
            # Hardware
            "MASTER": MASTER_OSCILLATOR_FREQ,
            "RINGCLK": RING_OSCILLATOR_FREQ, # LFOSCR

            # Internal
            "PLLOUT": 0,
            "DIVOUT": 0,
            
            # Outputs
            "LFCLK": 0,
            "GICCLK": 0,
            "PCLK": 0,
            "SCLK": 0,
            "ARMCLK": 0
        }

        # Stabilization emulation

        self.pll_stabilization = 0
        
        self.osc_stabilization = 0
        self.lfosc_stabilization = 0

        # REGISTER VALUES 
        # Copied from chip documentation!        
        
        # PLLST : PLL stabilization status
        self.PLLST = 0
        # OSCST : Master oscillator stabilization status 
        #This flag is set to one when the master oscillator counter has occurred at the configured value in the CM_OSTR register. 
        self.OSCST = 1
        # LFOST : Low frequency oscillator stabilization status
        # This flag is set to one when the low frequency oscillator counter has reached at the configured value in the CM_LFOSCR register.
        self.LFOST = 1
        # LFUSED : Low frequency oscillator use status 
        # This flag is set to one when the low frequency oscillator is stable and used as the low frequency clock. 
        self.LFUSED = 0

        # PCLK1 : Enable/Disable the PCLK1 clocks of peripheral clock in the HALT mode 
        self.PCLK1 = 0
        # WFIKEY[15:0] 
        # Any write in the CM_WFIR register bits will only be effective if the WFIKEY field is equal to 0x80A4
        self.WFIKEY = 0

        # PST[10:0] : PLL stabilization time
        # PST register value = (PLL stabilization time / (MCLK period × 256)) – 5
        # MCLK is the master clock from the master oscillator. The default value is the maximum startup time 0x154.
        # The stabilization time of PLL is maximum 150us.
        self.PST = 0
        # PLLKEY[15:0] : Key for write access into the CM_PSTR register
        # Any write in the CM_PSTR register bits will only be effective if the PLLKEY field is equal to 0x59C1.
        self.PLLKEY = 0

        # PMUL[7:0] : PLL multiplier parameter
        # These bits select the PLL multiplier. This value depends on the external crystal oscillator. It is not possible to write the zero value in this field.
        # In all case, the PLL output frequency must be between 12 to 40 MHz. 
        # PLL Multiplier M = PMUL[7:0] + 8 
        self.PMUL = 0
        # PLL_POST[1:0] : Post scalar parameter
        # This field configures the post scalar factor
        self.PLL_POST = 0
        # PLL_PRE[5:0] : Pre divider parameter 
        # This parameter configures the pre divider. 
        self.PLL_PRE = 0
        # PDPKEY[15:0] : Key for write access into the CM_PDPR register 
        # Any write in the CM_PDPR register bits will only be effective if the PDPKEY field is equal to 0x7AB2. 
        self.PDPKEY = 0

        # OST[15:0] : Master oscillator stabilization time 
        # This field is the number of low frequency oscillator cycle for respect the master oscillator stabilization time.
        # During reset, this register will be set at 0x2EE0 as default value (worst case). 
        self.OST = 0
        # OSTKEY[15:0] : Key for write access into the CM_OSTR register
        #  Any write in the CM_OSTR register bits will only be effective if the OSTKEY field is equal to 0xFA4B. 
        self.OSTKEY = 0

        # PCLK1DIV[2:0] : Peripheral divider
        # This field selects the division ratio between the CORECLK system clock and the peripheral clock domain. 
        self.PCLK1DIV = 0

        # CMCLK_SEL[1:0] : Select between different clocks
        # This field selects the clock manager mode. 
        self.CMCLK_SEL = 0
        # SELKEY[15:0] : Key for write access into the CM_SELR register
        #  Any write in the CM_SELR register bits will only be effective if the SELKEY field is equal to 0xD0C9. 
        self.SELKEY = 0

        # WD : Internal reset from watchdog 
        self.WD = 0
        # CM : Internal reset from Clock Monitor
        self.CM = 0
        # LVD : Internal reset from LVD
        self.LVD = 0

        # MDIV[8:0] : Master clock divider 
        # This field is used to divide the master clock in order to generate the low frequency clock. The MDIV=0 value is no effect i.e. the previous value is unchanged
        self.MDIV = 0
        # CDIV[2:0] : Core clock divider 
        # This field is used to divide the PLLOUT or MCLK clocks. 
        self.CDIV = 0
        # LDIV[2:0] : Low frequency oscillator clock divider
        # This field is used to divide the ring oscillator clock frequency in order to have a real frequency clock when ring oscillator is used for LFDIV generation. 
        self.LDIV = 0
        # MDIVKEY[15:0] : Key for write access into the CM_MDIVR register 
        # Any write in the CM_MDIVR register bits will only be effective if the MDIVKEY field is equal to 0xACDC. 
        self.MDIVKEY = 0

        # LFOSCEN : Enable/Disable the low frequency oscillator
        self.LFOSCEN = 0
        # LFSEL : Low frequency clock selection
        self.LFSEL = 0
        # LF_ST[7:0] : Low frequency stabilization time 
        # This value is the number of master clock cycles counted to wait the low frequency stabilization. When this value is reached, the LFOST bit in CM_STR is set. 
        self.LF_ST = 0
        # LFOSCKEY[15:0] : Key for write access into the CM_LFOSCR register
        # Any write in the CM_LFOSCR register bits will only be effective if the LFOSCKEY field is equal to 0xA34C

        # HALTMODE : Stop ARM clock. This bit is set only, the circuit will come out of HALT mode upon interrupt. 
        self.HALTMODE = 0
        # STOPMODE : Stop all clocks. The circuit resumes form STOPMODE mode upon external wake-up interrupt. 
        self.STOPMODE = 0
        # IDLEMODE : Stop ARM clock. All other clocks are left unchanged. This bit is set only, the circuit will come out of IDLE mode upon interrupt. 
        self.IDLEMODE = 0
        # CRKEY[15:0] : Key for write access into the CM_CR register
        # Any write in the CM_CR register bits will only be effective if the CRKEY field is equal to 0x678F
        self.CRKEY = 0

        # CM_EN : Clock Monitor Enable. 
        self.CM_EN = 0
        # MRKEY[15:0] : Key for write access into the CM_MR register 
        # Any write in the CM_MR register bits will only be effective if the MRKEY field is equal to 0x1505
        self.MRKEY = 0

        # STABLE : Clear stable interrupt 
        self.CLEAR_STABLE_IT = 0

        # STABLE : Main Clock
        self.MAIN_STABLE_IT = 0

        # STABLE : Stable interrupt enable 
        self.STABLE_IT_ENABLED = 0

        # STABLE : Stable interrupt stable 
        self.STABLE_IT_STABLE = 0

        self.recalculate_clocks()

    def STR_R(self):
        registerOffset = self._registers["STR"]["offset"]

        self.regs[registerOffset] = (self.LFUSED << 3) | (self.LFOST << 2) |  (self.OSCST << 1) | self.PLLST

    # missing STR_W because its not allowed anyways ...

    def WFIR_R(self):
        registerOffset = self._registers["WFIR"]["offset"]

        self.regs[registerOffset] = (self.WFIKEY << 16) | (self.PCLK1 << 5) 

    def WFIR_W(self, data):
        self.WFIKEY = (data >> 16) & 0xFFFF

        if self.WFIKEY == 0x59C1:
            self.PCLK1 = (data >> 5) & 0b01
            self.recalculate_clocks()
    
    def PSTR_R(self):
        registerOffset = self._registers["PSTR"]["offset"]

        self.regs[registerOffset] = (self.PLLKEY << 16) | self.PST

    def PSTR_W(self, data):
        self.PLLKEY = (data >> 16) & 0xFFFF

        if self.PLLKEY == 0x59C1:
            self.PST = data & 0x7FF
            self.pll_stabilization = (self.PST + 5) * 256

    def PDPR_R(self):
        registerOffset = self._registers["PDPR"]["offset"]

        self.regs[registerOffset] = (self.PDPKEY << 16) | (self.PLL_PRE << 10) | (self.PLL_POST << 8) | self.PMUL

    def PDPR_W(self, data):
        self.PDPKEY = (data >> 16) & 0xFFFF

        if self.PDPKEY == 0x7AB2:
            self.PLL_PRE = (data >> 10) & 0x3F
            self.PLL_POST = (data >> 8) & 0x3
            self.PMUL = data & 0xFF
            self.clock_sources["PLLOUT"] = self.calculate_pll()

    def OSTR_R(self):
        registerOffset = self._registers["OSTR"]["offset"]

        self.regs[registerOffset] = (self.OSTKEY << 16) | self.OST

    def OSTR_W(self, data):
        self.OSTKEY = (data >> 16) & 0xFFFF

        if self.OSTKEY == 0xFA4B:
            self.OST = data & 0xFFFF

    def DIVBR_R(self):
        registerOffset = self._registers["DIVBR"]["offset"]

        self.regs[registerOffset] = self.PCLK1DIV # excluded reserved shit

    def DIVBR_W(self, data):
        self.PCLK1DIV = data & 0x7

    def SELR_R(self):
        registerOffset = self._registers["SELR"]["offset"]

        self.regs[registerOffset] = (self.SELKEY << 16) | self.CMCLK_SEL 

    def SELR_W(self, data):
        self.SELKEY = (data >> 16) & 0xFFFF

        if self.SELKEY == 0xD0C9:
            self.CMCLK_SEL = data & 0x3
            self.change_mode(self.CMCLK_SEL)

    def RSR_R(self):
        registerOffset = self._registers["RSR"]["offset"]

        self.regs[registerOffset] = (self.LVD << 2) | (self.CM << 1) | self.WD 

    def RSR_W(self, data):     # Not allowed
        self.LVD = data & 0x4
        self.CM = data & 0x2
        self.WD = data & 0x1

    def MDIVR_R(self):
        registerOffset = self._registers["MDIVR"]["offset"]

        self.regs[registerOffset] = (self.MDIVKEY << 16) | (self.LDIV << 13) | (self.CDIV << 10) | self.MDIV

    def MDIVR_W(self, data):
        self.MDIVKEY = (data >> 16) & 0xFFFF

        if self.MDIVKEY == 0xACDC:
            self.LDIV = (data >> 13) & 0x7
            self.CDIV = (data >> 10) & 0x7
            self.MDIV = data & 0xFF1
    
    def LFOSCR_R(self):
        registerOffset = self._registers["LFOSCR"]["offset"]

        self.regs[registerOffset] = (self.LFOSCKEY << 16) | (self.LF_ST << 8) | (self.LFSEL << 1) | self.LFOSCEN

    def LFOSCR_W(self, data):
        if self.HALTMODE or self.STOPMODE or self.IDLEMODE:
            print("[DEVICE][CM] Invalid LFOSCR write, writing is only allowed in NORMAL mode!")

        self.LFOSCKEY = (data >> 16) & 0xFFFF

        if self.LFOSCKEY == 0xA34C:
            self.LF_ST = (data >> 8) & 0xFF
            self.LFSEL = (data >> 1) & 0x1
            self.LFOSCEN = data & 0x1

    def CR_R(self):     # Not allowed
        registerOffset = self._registers["CR"]["offset"]

        self.regs[registerOffset] = (self.CRKEY << 16) | (self.IDLEMODE << 5) | (self.STOPMODE << 4) | self.HALTMODE

    def CR_W(self, data):
        self.CRKEY = (data >> 16) & 0xFFFF

        if self.CRKEY == 0x678F:
            self.IDLEMODE = (data >> 5) & 0x1
            self.STOPMODE = (data >> 4) & 0x1
            self.HALTMODE = data & 0x1
    
    def MR_R(self):
        registerOffset = self._registers["MR"]["offset"]

        self.regs[registerOffset] = (self.MRKEY << 16) | self.CM_EN

    def MR_W(self, data):
        self.MRKEY = (data >> 16) & 0xFFFF

        if self.MRKEY == 0x1505:
            self.CM_EN = data & 0x1
    
    def CSR_R(self):     # Not allowed
        registerOffset = self._registers["CSR"]["offset"]

        self.regs[registerOffset] = self.CLEAR_STABLE_IT

    def CSR_W(self, data):
        self.CLEAR_STABLE_IT = data & 0x1
    
    def SR_R(self):
        registerOffset = self._registers["SR"]["offset"]

        self.regs[registerOffset] = self.MAIN_STABLE_IT

    def SR_W(self, data):     # Not allowed
        self.MAIN_STABLE_IT = data & 0x1

    def IER_R(self):    # Not allowed
        registerOffset = self._registers["IER"]["offset"]

        self.regs[registerOffset] = self.STABLE_IT_ENABLED

    def IER_W(self, data):
        self.STABLE_IT_ENABLED = data & 0x1

    def IDR_R(self):    # Not allowed
        registerOffset = self._registers["IDR"]["offset"]

        self.regs[registerOffset] = (self.STABLE_IT_ENABLED == 0)

    def IDR_W(self, data):
        self.STABLE_IT_ENABLED = (data & 0x1) == 0
    
    def IMR_R(self):
        registerOffset = self._registers["IMR"]["offset"]

        self.regs[registerOffset] = self.STABLE_IT_STABLE 

    def IMR_W(self, data): # Not allowed
        self.STABLE_IT_STABLE = (data & 0x1)
    

    def recalculate_clocks(self):

        # Yes I do not handle RSR and soo many other things, if you need it,  sorry ... 
        
        self.clock_sources["DIVOUT"] = self.clock_sources["MASTER"] // (self.MDIV + 1) 

        self.clock_sources["LFCLK"] = (self.clock_sources["RINGCLK"] if self.LFSEL else self.clock_sources["DIVOUT"]) // (self.LDIV + 1)

        if self.current_mode == "HIGHSPEED" and self.PLLST:
            main_clock = self.clock_sources["PLLOUT"]
        else:
            main_clock = self.clock_sources["MASTER"]
        
        self.clock_sources["ARMCLK"] = main_clock // (self.CDIV + 1)
        self.clock_sources["SCLK"] = main_clock // (self.CDIV + 1)

        # peripherial clock shit (DIVBR)
        pclk_div = self.PCLK1DIV * (self.CDIV + 1)

        self.clock_sources["PCLK"] = main_clock // (pclk_div + 1)
        self.clock_sources["GICCLK"] = main_clock // (pclk_div + 1)


    # Stabilisation emulation

    def update(self):    
        # PLL

        if self.pll_stabilization > 0:
            self.pll_stabilization -= 1
            if self.pll_stabilization <= 0:
                # If the following check fails there is an interrupt but guess what 
                # I didnt implement, an interrupt, sooo yea

                if self.calculate_pll() >= 12_000_000:
                    self.PLLST = 1 
                else:
                    # self._handle_pll_failure()
                    print("[DEVICE][CM] The PLL failed, but this isnt implemented so bugs may accur!")
                    
                    # just disable it, and move on with life. I cant spend another hour with this
                    self.PLLST = 0 
                    self.pll_enabled = False
                    self.current_mode = "NORMAL" # because highspeed just has it automaticly enabled so we rest that as well

        # MASTER clock

        if self.osc_stabilization > 0:
            self.osc_stabilization -= 1

            if self.osc_stabilization <= 0:
                self.OSCST = 1

        if self.transition_in_progress and not self.pll_stabilization and not self.osc_stabilization:
            self.transition_in_progress = False
            self.current_mode = self._modes.get(self.CMCLK_SEL, "NORMAL")

            self.MAIN_STABLE_IT = 1
            
            # check STABLE_IT_ENABLED == 1 then         # IMR
            #   # STABLE interrupt, not implemented yet

    def calculate_pll(self):
        M = self.PMUL + 8 if self.PMUL != 0 else 0
        S = 2 ** self.PLL_POST
        P = self.PLL_PRE + 2

        if (P * S) != 0: # anti-div / 0
            fout = (M * self.clock_sources["MASTER"]) // (P * S)
        else:
            fout = 0

        # check if the pll is not outside of its functioning range
        if not (12_000_000 <= fout <= 40_000_000):
            fout = 0
            self.PLLST = 0 

        return fout

    def change_mode(self, new_mode):
        target_mode = self._modes.get(new_mode, "NORMAL")

        if self.current_mode == target_mode or self.transition_in_progress:
            print("[DEVICE][CM] Invalid mode change, still in changing progress!")
            return # we are either already in this mode or we are currently changing mode 
        
        transitionTable = {
            'NORMAL':       ['HIGHSPEED',   'SLOW',         'LOWPOWER',     'HALT',         'STOP'  ],
            'HIGHSPEED':    ['NORMAL',      'SLOW',         'LOWPOWER',     'HALT'                  ],
            'SLOW':         ['NORMAL',      'HIGHSPEED',    'LOWPOWER',     'HALT'                  ],
            'LOWPOWER':     ['NORMAL',      'HIGHSPEED',    'SLOW',         'HALT'                  ],
            'HALT':         ['NORMAL',      'HIGHSPEED',    'SLOW',         'LOWPOWER'              ],
            'STOP':         ['NORMAL'                                                               ]
        }

        if target_mode not in transitionTable.get(self.current_mode, []):
            print(f"[DEVICE][CM] Error: Invalid mode transition {self.current_mode} -> {target_mode}")

        self.transition_in_progress = True
        self.previous_mode = self.current_mode

        # And because every mode has different stuff 
        if target_mode == "HIGHSPEED":
            self.pll_enabled = True
            self.pll_stabilization = (self.PST + 5) * 256
            self.PLLST = 0
        elif target_mode == "NORMAL" or target_mode == "SLOW":
            self.osc_stabilization = self.OST
        elif target_mode == "LOWPOWER":
            self.pll_enabled = False

        self.MAIN_STABLE_IT = 0