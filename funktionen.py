# -*- coding: utf-8 -*-
"""
Created on Tue Sep 19 16:07:22 2017

@author: andreas
"""

import decomp as decomp
# Für das erzeugen der Referenzen
objdump = "arm-none-eabi-objdump"

# Erzeugt eine Liste mit den tatsächlichen Funktionen.
def get_funktionen_ref(ref_file, ende=None, start=None):
    funktionen = []
    befehl = objdump + " -d " + ref_file + " | grep '^08'"
    import subprocess
    ausgabe = subprocess.check_output(befehl, shell=True)
    for line in ausgabe.splitlines():
        rohadresse = line.decode('UTF-8').split(' ')[0].strip()
        adresse = int(rohadresse, 16)
        rohname = line.decode('UTF-8').split('<')[1]
        name = rohname.split('>')[0]
        if ende is not None and start is not None:
            if adresse >= start and adresse <= ende:
                funktionen.append([adresse, name])
        elif ende is not None:
            if adresse <= ende:
                funktionen.append([adresse, name])
        else:
            funktionen.append([adresse, name])
    return funktionen

# Erzeugt eine Liste mit den Addressen von Funktionsanfängen, Algorithmus 1:
def get_funktionen_1(programm_code):
    funktionen = []
    for instruktion in programm_code:
        if instruktion.mnemonic == "bl":
            funktionen.append([
            instruktion.operands[0].imm,
            "bl @ 0x%08x"%instruktion.address])
    return funktionen

# Erzeugt eine Liste mit den Addressen von Funktionsanfängen, Algorithmus 2:
def get_funktionen_2(programm_code):
    funktionen = []
    vorige = [decomp.pseudo_op(0,"nop",0), decomp.pseudo_op(0,"b",0)]
    vorherige_ist_datenwort = True
    # Funktion beginnt nach .word Block:
    for i in programm_code:
        # ist i ein Datenwort?
        i_ist_dwort = False
        if isinstance(i, decomp.pseudo_op):
            if i.mnemonic == ".word":
                i_ist_dwort = True
        # wenn ja dann:
        if i_ist_dwort:
            vorherige_ist_datenwort = True
        elif isinstance(i, decomp.pseudo_op):
            vorherige_ist_datenwort = False
        else:
            if vorherige_ist_datenwort:
                if not ( vorige[0].mnemonic == "b" or\
                (vorige[0].mnemonic == "nop" and vorige[1].mnemonic == "b") ):
                    # Dieses if verhindert 5 False Positives und erzeugt ein
                    # False Negative
                    funktionen.append([i.address, "folgt Datenblock"])
            vorherige_ist_datenwort = False
            vorige[1] = vorige[0]
            vorige[0] = i
    return funktionen

# Mnemonics
push  = ["push", "push.w"]
popI  = ["pop", "pop.w"]
data  = [".word.", ".halfword", ".byte"]
bxI   = ["bx"]
logI  = ["orr", "orr.w", "orn", "orn.w", "and", "and.w", "eor", "eor.w", "bic", "bic.w"]
matI  = ["add","add.w","adds","adds.w","adc","adc.w","adcs","adcs.w"
         "sub","sub.w","subs","subs.w","sbc","sbc.w","sbcs","sbcs.w"]
extI = ["uxth","uxth.w","sxth","sxth.w","uxtb16","uxtb16.w","sxtb16","sxtb16.w"]
lsxI  = ["lsl", "lsls", "lsrs","lsrne","lsrhi"]
cmpI  = ["cmp", "cmp.w"]
cbzI  = ["cbz", "cbnz"]
ldrI  = ["ldr", "ldrh", "ldrb", "ldr.w", "ldrh.w", "ldrb.w"]
branchI = ["bxeq", "beq", "b", "bne", "bne.w"]
movI  = ["mov", "mov.w"]

# Muster
muster01 = [
[bxI,  movI, push, 1],
[data, movI, push, 1],
[popI, movI, push, 1],
[movI, push, -1]
] # korrekt, ggf. weitere Ausnahmen hinzufügen
muster02 = [
[ldrI, ldrI, cmpI, branchI, push, 4],
[ldrI, cmpI, branchI, push, 3],
[branchI, push, -1]
] # korrekt, ggf. weitere Ausnahmen hinzufügen
muster03 = [
[ldrI,    ldrI,  ldrI,  ldrI,  push, 4],
[ldrI,    ldrI,  ldrI,  push, 3],
[ldrI,    ldrI,  push,  2],
[push,    ldrI,  push, -1],
[ldrI,    push,   1],        # Ausnahme: wenn mit diesem LDR der PC modifiziert wird.
]# Korrekt, bis auf die noch fehlende Ausnahme -> Falsch Positive :(
muster04 = [
[matI, lsxI, push, 2],
[logI, lsxI, push, 2],
[lsxI, push, 1]
]# Korrekt, -lsl-push- u. -add-lsl-push- f_pos bei nicht erkanntem .word !!!
muster05 = [
[logI,    extI, push,  2],
[cmpI,    push,   1],
[cbzI,    push,   1],
[logI,    push,   1],
[matI,    push,   1],
[bxI,     push,  -1],
[push,    push,   1]
] # Korrekt
muster = muster01 + muster02 + muster03 + muster04 + muster05
 
def get_funktionen_3(programm):
    funktionen = []
    laenge = len(programm)
    i = 0
    while i < laenge:
        if programm[i].mnemonic in push:
            funktion = suche_muster(programm, i, muster)
            if funktion is not None:
                    funktionen.append(funktion)
        i += 1
    return funktionen

# suche_muster prüft ob der Pushbefehel an stelle i Teil irgend eines Musters ist,
# und gibt ggf. eine Liste der Form [adresse, musterstring] zurück
def suche_muster(programm, i, musterliste):
    lenm = len(musterliste)
    j = 0
    adresse = None
    while j < lenm:
        adresse = ist_muster(programm, i, musterliste[j])
        if adresse:
            if adresse >= 0:
                musterstring = "-"
                for element in musterliste[j][:-1]:
                    musterstring += element[0] + "-"
                if musterstring == "-ldr-push-":  # AUSNAHME!!
                    (gel, ges) = programm[i-1].regs_access()
                    if ges == [11, 12]:   # PC wird beschrieben!
                        return [programm[i].address, "ldrPC-push"]
                return [adresse, musterstring]
            else:
                return None  # Antimuster
        j += 1
    return [programm[i].address, "push"]

# ist_muster prüft ob der Pushbefehl an stelle i Teil eines gegeben Musters ist,
# und gibt ggf. die Adresse des Funktionsanfangs zurück.
def ist_muster(programm, i, muster):
    lenm = len(muster)-1
    m = muster[:-1]
    pos = muster[-1]
    j = 0
    treffer = True
    while j < lenm:
        if programm[i-lenm+1+j].mnemonic not in m[j]:
            treffer = False
        j += 1
    if treffer:
        if pos < 0:
            # ANTIMUSTER!
            return -1
        else:
            # Muster passt, Pos-Berechnung!
            return programm[i-pos].address
    else:
        # Muster passt nicht.
        return None

def get_funktionen_4(programm_code):
    funktionen = []
    vorherige_ist_zero = False
    for i in programm_code:
        i_ist_zero = False
        if isinstance(i, decomp.pseudo_op):
            if i.mnemonic == ".zero":
                i_ist_zero = True
        if i_ist_zero:
            vorherige_ist_zero = True
        else:
            if vorherige_ist_zero:
                funktionen.append([i.address, "folgt Zeropadding"])
            vorherige_ist_zero = False
    return funktionen

# Erzeugt eine Liste mit den Addressen von Funktionsanfängen, Algorithmus 4:
def get_funktionen_5(programm_code):
    funktionen = []
    for i in programm_code:
        if i.mnemonic == "str":
            if "lr" in i.op_str:
                funktionen.append([i.address, "str lr"])
    return funktionen
    # Bringt gerade mal 6 Funktionen, die alle schon anderweitig gefunden werden.
    # Bringt aber keine False Positives, also bleibt der Algo erstmal da.
    
    
    
get_funktionen = [get_funktionen_1, get_funktionen_2, get_funktionen_3, get_funktionen_4]
#get_funktionen = [get_funktionen_1, get_funktionen_2]
    


def zeige_funktionsliste(liste):
    print("[", end='')
    erstdurchlauf = True
    for i in liste:
        if erstdurchlauf:
            erstdurchlauf = False
        else:
            print(",")
            print(" ", end='')
        print("[", end='')
        print("0x%08x"%i[0], end='')
        for j in i[1:]:
            print(", ", end='')
            print(j, end='')
        print("]", end='')
    print("]")
    
def ohne_duplikate(eingangsliste):
    ausgangsliste = []
    adressenliste = []
    for i in eingangsliste:
        if i[0] not in adressenliste:
            ausgangsliste.append(i)
            adressenliste.append(i[0])
        else:
            for j in ausgangsliste:
                if j[0] == i[0]:
                    for k in i[1:]:
                        j.append(k)
    return ausgangsliste

# Füge die Listen der verschiedenen Funktionsalgorithmen zu einer eingizen
# Liste zusammen.
def kombiniere_listen(listenliste):
    masterliste = []
    for liste in listenliste:
        for i in liste:
            masterliste.append(i)
    masterliste = ohne_duplikate(masterliste)
    masterliste = sorted(masterliste)       # sortieren
    return masterliste

# Erzeuge Listenliste, deren Listen jeweils nur die Treffer enthalten, die in
# keiner der anderen Listen vorkommen.
def einzigartige(listenliste):
    anz = len(listenliste) # Anzahl der Algorithmen
    ergebnis = []
    for i in range(0, anz):
        lislis = listenliste[i+1:] + listenliste[:i]
        testliste = listenliste[i]
        refliste = kombiniere_listen(lislis)
        einzige = ref_vergleich(refliste, testliste)[2]
        ergebnis.append(einzige)
    return ergebnis
    
# Erzeugt Listen mit den korrekten, falsch-negativ und falsch-postiv gefundenen
# Funktionen.
def ref_vergleich(referenz, gefunden):
    refi = ohne_duplikate(referenz)
    gefi = ohne_duplikate(gefunden)
    korrekt   = []
    f_pos     = []
    f_neg     = []
    refadressen = []
    for i in refi:
        refadressen.append(i[0])
        gefunden = False
        for j in gefi:
            if i[0] == j[0]:
                # korrekt erkannt:
                i.append(j[1:])
                korrekt.append(i)
                gefunden = True
        if not gefunden:
            # falsch negativ:
            f_neg.append(i)
    for j in gefi:
        if j[0] not in refadressen:
            # falsch positiv:
            f_pos.append(j)
    if len(f_pos) + len(korrekt) != len(gefi):
        print("f_pos = %i" %len(f_pos))
        print("f_neg = %i" %len(f_neg))
        print("korrekt = %i" %len(korrekt))
        print("gefi = %i" %len(gefi))
        print("refi = %i" %len(refi))
        raise UserWarning("Anzahl gefundener Funktionen stimmt nicht!")
    if len(f_neg) + len(korrekt) != len(refi):
        print("f_pos = %i" %len(f_pos))
        print("f_neg = %i" %len(f_neg))
        print("korrekt = %i" %len(korrekt))
        print("gefi = %i" %len(gefi))
        print("refi = %i" %len(refi))
        raise UserWarning("Anzahl der Referenzfunktionen stimmt nicht!")
    ausgabe = [korrekt, f_neg, f_pos]
    return ausgabe
