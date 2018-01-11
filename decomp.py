# -*- coding: utf-8 -*-
"""
Created on Mon Jul  3 23:42:00 2017

@author: andreas
"""


ARM_OP_INVALID = 0
ARM_OP_REG     = 1
ARM_OP_IMM     = 2
ARM_OP_MEM     = 3

readelf = "arm-none-eabi-readelf"
#legalrange = [0x08000000, 0x08020000] #entspricht 128kiB Flash Speicher
legalrange = [0x08000000, 0x08040000] # Entspricht 256kiB Flash Speicher

class pseudo_op:
    def __init__(self, address, mnemonic, value, size=4):
        self.address = address
        self.mnemonic = mnemonic
        self.value = value
        self.size = size
        if size == 1:
            self.op_str = "0x%02x"%value
        elif size == 2:
            self.op_str = "0x%04x"%value
        else:
            self.op_str = "0x%08x"%value

class testfall:
    def __init__(self, elffile, binfile, asmfile, offset, ende, basisadressen, disasm_fehler=[]):
        self.elffile          = elffile
        self.binfile          = binfile
        self.asmfile          = asmfile
        self.offset           = offset
        self.basisadressen    = basisadressen
        self.ende             = ende
        self.disasm_fehler    = disasm_fehler
        self.word_adressen    = []
        self.hword_adressen   = []
        self.byte_adressen    = []
        self.zero_adressen    = []
        self.vektor_adressen  = []
        self.jumptargets      = []
        self.functions        = []
        self.databytes        = None
        self.databytes_ref    = None
        self.konvergent       = False
        self.einsprungpunkt   = None
        self.programm         = None
        self.bin_datei_inhalt = None
        #self.data_list_ref    = None
        #self.data_list        = None
        
    def lade_bin(self):
        #Binary in den Speicher laden:
        with open(self.binfile, mode='rb') as file: # b wie binär, r wie read
            datei_inhalt = file.read()
        file.close()
        datei_inhalt = bytearray(datei_inhalt)
        self.bin_datei_inhalt = datei_inhalt
        
        self.suche_vektortabelle()        
        
        self.einsprungpunkt = read_word(self.bin_datei_inhalt, self.offset+4, self.offset)
        return self.einsprungpunkt
        
    def suche_vektortabelle(self):
        vektorende = False
        i = self.offset
        while not vektorende:
            vektorende = True
            word = read_word(self.bin_datei_inhalt, i, self.offset)
            if word == 0:
                vektorende = False
                self.vektor_adressen.append(i)
            else:
                for b in self.basisadressen:
                    if word in range(b, b+self.ende):
                        vektorende = False
                        self.vektor_adressen.append(i)
            i += 4
        
    def disassembly(self):
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        md.detail = True
        md.skipdata = False
        programm = []
        # Abkürzungen:
        offs = self.offset
        datei = self.bin_datei_inhalt
        insn_groesse = 4
        word_addr = offs + 0
        while word_addr <= self.ende - insn_groesse:
            if word_addr in self.disasm_fehler:
                word = read_word(self.bin_datei_inhalt, word_addr, offs)
                programm.append(pseudo_op(word_addr, ".bad!", word))
                insn_groesse = 4
            elif word_addr in self.vektor_adressen:
                vektor = read_word(self.bin_datei_inhalt, word_addr, offs, 4)
                programm.append(pseudo_op(word_addr, ".vector", vektor, 4))
                insn_groesse = 4
            elif word_addr in self.byte_adressen:
                dbyte = read_word(self.bin_datei_inhalt, word_addr, offs, 1)
                programm.append(pseudo_op(word_addr, ".byte", dbyte, 1))
                insn_groesse = 1
            elif word_addr in self.hword_adressen:
                hword = read_word(self.bin_datei_inhalt, word_addr, offs, 2)
                programm.append(pseudo_op(word_addr, ".hword", hword, 2))
                insn_groesse = 2
            elif word_addr in self.zero_adressen:
                programm.append(pseudo_op(word_addr, ".zero", 0, 2))
                insn_groesse = 2
            elif word_addr in self.word_adressen:
                word = read_word(self.bin_datei_inhalt, word_addr, offs)
                programm.append(pseudo_op(word_addr, ".word", word))
                insn_groesse = 4
            else:
                vierer = datei[word_addr - offs : word_addr - offs + 4]
                disasm = md.disasm(vierer, word_addr) # ein oder zwei Instruktionen
                insn = None
                try:
                    insn = next(disasm)
                except:
                    pass  ## TODO: Tritt das auf, und was heisst das?
                if insn is not None:
                    programm.append(insn)
                    insn_groesse = insn.size
            word_addr += insn_groesse
            if word_addr%2 and insn_groesse != 1:
                #print("Ungerade Adressen! Adresse = 0x%08x" %word_addr)
                pass
        self.programm = programm
        
    def schreibe_asm(self):
        # Sauberes Disassembly in Datei schreiben:
        function_addresses = [item[0] for item in self.functions]
        with open(self.asmfile, mode='w') as asm_file:
            for i in self.programm:
                if i.address in function_addresses:
                    print("", file=asm_file)
                print("0x%08x\t%s\t%s" %(i.address, i.mnemonic, i.op_str), file=asm_file)
        asm_file.close()
        
    def jumpsearch(self):
        jumptargets = []
        
        for i in self.programm:
            target = is_branch(i)
            if target is not None:
                jumptargets.append(target)
            
        jumptargets = list(set(jumptargets)) # purge duplicates
        jumptargets = sorted(jumptargets)    # sort
        #print("    Es gibt", len(jumptargets), "Sprungziele.")
        self.jumptargets = jumptargets       # apply results
        
    def check_jumps(self):
        for target in self.jumptargets:
            if target in self.word_adressen:
                print("Sprung zeigt auf Wort bei 0x%08x" %target)
            elif target in self.hword_adressen:
                print("Sprung zeigt auf Halbwort bei 0x%08x" %target)
            elif target in self.byte_adressen:
                print("Sprung zeigt auf Byte bei 0x%08x" %target)
            elif target in self.zero_adressen:
                print("Sprung zeigt auf Nullbyte bei 0x%08x" %target)
            elif target in self.vektor_adressen:
                print("Sprung zeigt auf den Vektor bei 0x%08x" %target)    
        
    def datensuche(self):
        datenwortadressen = []
        halbwortadressen = []
        byteadressen = []
        zeroadressen = []
        
        sauberes_disassembly = []
        vorige_instruktion = None
        for i in self.programm:
            if isinstance(i, pseudo_op):
                sauberes_disassembly.append(i)
            elif i.address in datenwortadressen or\
            (i.address - 2) in datenwortadressen or\
            i.address in halbwortadressen or\
            i.address in byteadressen:
                pass
                #remove instruction
            else:
                sauberes_disassembly.append(i)
                laed_dw = laed_datenwort(i)
                if laed_dw is not None:
                    zieladresse = laed_dw
                    datenwortadressen.append(zieladresse)
                else:
                    laed_ddw = laed_doppelwort(i, vorige_instruktion)
                    if laed_ddw is not None:
                        (zieladresse1, zieladresse2) = laed_ddw
                        datenwortadressen.append(zieladresse1)
                        datenwortadressen.append(zieladresse2)
                    else:
                        endsigns = self.jumptargets + self.word_adressen\
                        + self.zero_adressen
                        tbbsprung = ist_tbb_sprung(i, self.bin_datei_inhalt, self.offset, endsigns)
                        tbhsprung = ist_tbh_sprung(i, self.bin_datei_inhalt, self.offset, endsigns)
                        if tbbsprung is not None:
                            byteadressen += tbbsprung
                        elif tbhsprung is not None:
                            halbwortadressen += tbhsprung
                        elif i.mnemonic + i.op_str == "movsr0, r0":
                            zeroadressen.append(i.address)
            vorige_instruktion = i
        datenwortadressen = sorted(datenwortadressen)
        halbwortadressen = sorted(halbwortadressen)
        byteadressen = sorted(byteadressen)
        zeroadressen = sorted(zeroadressen)
        if self.word_adressen == datenwortadressen and\
        self.hword_adressen == halbwortadressen and\
        self.byte_adressen == byteadressen and\
        zeroadressen == []:
            self.konvergent = True
        else:
            self.word_adressen = datenwortadressen
            self.hword_adressen = halbwortadressen
            self.byte_adressen = byteadressen
            self.zero_adressen += zeroadressen
            self.programm = sauberes_disassembly
 
    def get_databytes_ref(self):
        databytes = []
        symboltable = []
        befehl = readelf + " -s " + self.elffile + " | grep \'$d\\|$t\'"
        import subprocess
        ausgabe = subprocess.check_output(befehl, shell=True)
        for line in ausgabe.splitlines():
            linelist = line.decode('UTF-8').split()
            #print(linelist[1], linelist[7][1])
            entry = [int(linelist[1], 16), linelist[7][1]]
            symboltable.append(entry)
        symboltable = sorted(symboltable)
        #print_symbols(symboltable)
        # Filter: only symbols within the Flash Memory area are of interest
        symboltable2 = []
        for symbol in symboltable:
            if symbol[0] >= self.offset:
                symboltable2.append(symbol)         
        #print_symbols(symboltable2)
        if symboltable2[0][0] != self.offset:
            raise ValueError("No Symbol for the start of the Flash Memory")
        state = "x"
        byteaddress = self.offset
        symbol_index = 0
        while byteaddress <= self.ende:
            if symboltable2[symbol_index][0] == byteaddress:
                state = symboltable2[symbol_index][1]
                if symbol_index < len(symboltable2)-1:
                    symbol_index += 1
                else:
                    print("Fehler! Keine Symbole mehr! symbol_index= ", symbol_index)
            elif symboltable2[symbol_index][0] < byteaddress:
                print("symboltable2[",symbol_index,"][0] = ", symboltable2[symbol_index][0] , " byteaddress= ", byteaddress)
                print("self.ende=",self.ende)
                raise ValueError("Symboltable doesn't fit the assumptions.")
            if state == "d":
                databytes.append(byteaddress)
            byteaddress += 1
        self.databytes_ref = databytes
        return databytes

    def get_databytes(self):
        databytes = []
        fours = self.disasm_fehler + self.vektor_adressen + self.word_adressen
        twos = self.hword_adressen + self.zero_adressen
        ones  = self.byte_adressen
        for i in fours:
            databytes.append(i+0)
            databytes.append(i+1)
            databytes.append(i+2)
            databytes.append(i+3)
        for i in twos:
            databytes.append(i+0)
            databytes.append(i+1)
        for i in ones:
            databytes.append(i+0)
        databytes = sorted(list(set(databytes)))
        self.databytes = databytes
        return databytes
    
    def compare_databytes(self):
        self.get_databytes()
        self.get_databytes_ref()
        fdat = []
        fops = []
        corr = []
        meml = []
        for address in range(self.offset, self.ende+1):
            meml.append(0)
        for address in self.databytes:
            meml[address-self.offset] += 1
        for address in self.databytes_ref:
            meml[address-self.offset] -= 1
        for address in range(self.offset, self.ende+1):
            value = meml[address-self.offset]
            if value == 0:
                corr.append(address)
            elif value == 1:
                fdat.append(address)
            elif value == -1:
                fops.append(address)
            else:
                raise RuntimeError("This should never happen.")
        return [corr, fdat, fops]


# Helper function to check wether an instruction is a (conditional)branch.
# Returns the potential target address.
def is_branch(insn):
    b_address = None
    branchcodes = ["b.n", "b.w", "bx", "bl", "blx", "ble.n", "ble.w",
                   "bne.n", "bne.w", "beq.n", "beq.w"]
    cbcodes = ["cbz", "cbnz"]
    if insn.mnemonic in branchcodes:
        b_address = insn.operands[0].mem.base # TODO: Check wether more 
        # then mem.base needs to be taken into account (i.e. index, scale...)
    elif insn.mnemonic in cbcodes:
        b_address = insn.operands[1].mem.base # TODO: Check wether more 
        # then mem.base needs to be taken into account (i.e. index, scale...)
    return b_address

#Hilfsfunktion um einzelne Datenworte aus der Binärdatei zu laden:
def read_word(datei_inhalt, addresse, offset, wordsize=4):
    dateiaddresse = addresse - offset
    wert = 0
    try:
        for i in range(0, wordsize):
            wert += datei_inhalt[dateiaddresse + i]*2**(i*8)
            #Achtung: Endiannes
    except:
        wert = 0
    return wert

# Enthält die übergebene Instruktion einen Hinweis auf ein Datenwort?
def laed_datenwort(i):
    zieladdresse = None
    if (i.mnemonic == "ldr" and i.mnemonic != "ldrd") or (i.mnemonic == "ldr.w"):
        (regs_read, regs_write) = i.regs_access()
        if len(regs_read) == 1: # es wird genau ein Register geladen
            if regs_read[0] == 11: # und zwar der Program Counter (=11)
                if len(i.operands) == 2: # es gibt zwei Operanden
                    op_types = []
                    op_num = 0
                    for op in i.operands:
                        op_types.append(op.type)
                        if op.type == ARM_OP_MEM and op_num == 1:
                            if op.mem.base == 11:
                                zieladdresse = i.address - i.address % 4 + op.mem.disp + 4
                            if op.mem.index != 0:
                                raise ValueError("Dieser Fall sollte nicht auftreten!")
                            if op.mem.scale != 1:
                                raise ValueError("Dieser Fall sollte nicht auftreten!")
                            if op.mem.lshift != 0:
                                raise ValueError("Dieser Fall sollte nicht auftreten!")
                        op_num += 1
                    if not (op_types[0] == 1 and op_types[1] == 3):
                        raise ValueError("Falsche Operandentypen")
    else:
        pass
    return zieladdresse
    
def laed_doppelwort(i, vorige_instruktion):
    zieladdressen = None
    if i.mnemonic == "ldrd":
        #Suche:
        if vorige_instruktion is not None:
            if vorige_instruktion.mnemonic == "adr":
                ops = []
                for op in vorige_instruktion.operands:
                    ops.append(op)
                if ops[0].type == 1 and ops[1].type == 2:
                    zieladdresse = i.address + ops[1].imm + i.address%4
                    zieladdressen = (zieladdresse, zieladdresse+4)
                    # insn.reg_name(i.reg)
                else:
                    raise ValueError("Die add->ldr Hypothese stimmt nicht!")
    else:
        pass
    return zieladdressen
    
def finde_tabelle(i):
    tabellenadresse = None
    ops = []
    for op in i.operands:
        ops.append(op)
    if len(ops) == 1:
        if ops[0].type == 3:
            if op.mem.base == 11:
                tabellenadresse = i.address + 4
                #print("    Tabelle bei 0x%08x gefunden" %tabellenadresse)
            else:
                raise ValueError("Die Tabellenadresse ergibt sich nicht aus\
                    dem pc. Dieser Fall ist (noch) nicht implementiert!")
        else:
            raise ValueError("Falscher Operandentyp")
    else:   
        raise ValueError("Zu falsche Anzahl Operanden")
    return tabellenadresse

def ist_tbb_sprung(i, bin_datei_inhalt, offset, jumptargets):
    kleinstes_sprungziel = None
    byteadressen = None
    if i.mnemonic == "tbb":
        byteadressen = []
        tabellenadresse = finde_tabelle(i)
        byteadresse = tabellenadresse
        kleinstes_sprungziel = 0xfffffffe
        while byteadresse < kleinstes_sprungziel:
            if byteadresse in jumptargets:
                print("Tabellenende-Jumptarget Kollision (TBB)!!!")
            byteinhalt = read_word(bin_datei_inhalt, byteadresse, offset, wordsize=1)
            byteadressen.append(byteadresse)
            sprungziel = byteinhalt * 2 + tabellenadresse
            if sprungziel < kleinstes_sprungziel and sprungziel > byteadresse and byteinhalt:
                kleinstes_sprungziel = sprungziel
            elif byteinhalt and sprungziel <= byteadresse:
                kleinstes_sprungziel = 0 # als Fehlerhaft markieren
                #print("Fehler! (TBB) sprungziel 0x%08x <= byteadresse 0x%08x; Tabelle bei 0x%08x"
                #      %(sprungziel, byteadresse, tabellenadresse))
                # TODO: Can we do something to correct this?!?
                # TODO: Otherwise how do we properly not there is an error here?
                if not byteadresse%2:
                    byteadressen = byteadressen[:-1] # letztes Byte entfernen,
                    # da mindestens dieses schon zu viel war.
            byteadresse += 1
            if byteadresse in jumptargets:
                byteadresse = 0xffffffff
    return byteadressen

# Erzeugt eine Liste mit den Addressen der Instruktionen die mutmaßlich auf
# .word Addressen zugreifen, sowie den vermuteten jewiligen .word Addressen.
def ist_tbh_sprung(i, bin_datei_inhalt, offset, jumptargets):
    zieladressen = []
    disassembly = []
    kleinstes_sprungziel = None
    halbwortadressen = None
    if i.mnemonic == "tbh":
        halbwortadressen = []
        tabellenadresse = finde_tabelle(i)
        halbwortadresse = tabellenadresse
        kleinstes_sprungziel = 0xfffffffe
        while halbwortadresse < kleinstes_sprungziel:
            if halbwortadresse in jumptargets:
                print("Tabellenende-Jumptarget Kollision (TBH)!!!")
            halbwortinhalt = read_word(bin_datei_inhalt, halbwortadresse, offset, wordsize=2)
            disassembly.append(pseudo_op(halbwortadresse, ".halfword", halbwortinhalt, 2))
            halbwortadressen.append(halbwortadresse)
            sprungziel = halbwortinhalt * 2 + tabellenadresse
            zieladressen.append(sprungziel)
            if sprungziel < kleinstes_sprungziel  and halbwortinhalt:
                kleinstes_sprungziel = sprungziel
            halbwortadresse += 2
            if halbwortadresse in jumptargets:
                halbwortadresse = 0xffffffff
    return halbwortadressen



objdump = "arm-none-eabi-objdump"
# Erzeugt eine Liste mit den tatsächlichen .word Adressen.
def get_datenwortadressen_ref(ref_file):
    datenwortaddressen = []
    befehl = objdump + " -d " + ref_file + " | grep .word"
    import subprocess
    ausgabe = subprocess.check_output(befehl, shell=True)
    for line in ausgabe.splitlines():
        clearline = line.decode('UTF-8').split(':')[0].strip()
        addresse = int(clearline, 16)
        datenwortaddressen.append(addresse)
    return datenwortaddressen


# Drucke Integerliste im Hexformat:
def print_hexlist(hex_liste):
    zaehler  = 0
    for i in hex_liste:
        if zaehler % 64:
            print("0x%08x " %i, end='')
        else:
            print("0x%08x" %i)
        zaehler += 1
    print()

# Zeige gebe Symboltabelle, welche im internen Format gespeichert ist, aus:
def print_symbols(symbol_liste, modulo=4):
    zaehler = 1
    for symbol in symbol_liste:
        if zaehler % modulo:
            print("0x%08x" %symbol[0], symbol[1], end=' ')
        else:
            print("0x%08x" %symbol[0], symbol[1])
        zaehler += 1
    if not zaehler % modulo:
        print()
