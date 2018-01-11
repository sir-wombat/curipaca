# -*- coding: utf-8 -*-
"""
Created on Thu Aug 31 14:34:41 2017

@author: andreas
"""

import decomp as decomp
import funktionen as fnkn


def statelist(liste):
    j = 1
    for i in liste:
        if j % 4:
            print(i[1], "0x%08x " %i[0], end='')
        else:
            print(i[1], "0x%08x" %i[0])
        j += 1
    print()

print()
print()
print("Curipaca Decompiler")
print()

basisadressen = [0x08000000, 0x20000000]

fall1 = decomp.testfall("Testreihen/serprog-O0.elf",
                        "Testreihen/serprog-O0.bin",
                        "Testreihen/serprog-O0.s",
                        0x08000000,
                        0x080025f7,
                        basisadressen
                        )
                        
fall2 = decomp.testfall("Testreihen/serprog-O3.elf",
                        "Testreihen/serprog-O3.bin",
                        "Testreihen/serprog-O3.s",
                        0x08000000,
                        0x080025cf,
                        basisadressen
                        )
                        
fall3fehler =  [4*x for x in range(0x08000400//4, (0x080020ec+4)//4)]
fall3fehler += [0x080141c2, 0x0801425e, 0x08014382]
fall3 = decomp.testfall("Testreihen/gnuk-O1.elf",
                        "Testreihen/gnuk-O1.bin",
                        "Testreihen/gnuk-O1.s",
                        0x08000000,
                        0x08015e43,
                        basisadressen,
                        fall3fehler
                        )
                        
fall4fehler =  [4*x for x in range(0x08000800//4, (0x080020ec+4)//4)]  
fall4fehler += [0x08019bd2, 0x08019c6e, 0x08019e22]                   
fall4 = decomp.testfall("Testreihen/gnuk-O3.elf",
                        "Testreihen/gnuk-O3.bin",
                        "Testreihen/gnuk-O3.s",
                        0x08000000,
                        0x0801c7d3,
                        basisadressen,
                        fall4fehler
                        )
                        
            
fall5 = decomp.testfall("Testreihen/blackmagic-O0.elf",
                        "Testreihen/blackmagic-O0.bin",
                        "Testreihen/blackmagic-O0.s",
                        0x08002000,
                        0x08015679,
                        basisadressen
                        )

fall6 = decomp.testfall("Testreihen/blackmagic-O3.elf",
                        "Testreihen/blackmagic-O3.bin",
                        "Testreihen/blackmagic-O3.s",
                        0x08002000,
                        0x08013431,
                        basisadressen
                        )

fall7fehler =  [4*x for x in range(0x08000400//4, (0x080020ec+4)//4)]
fall7fehler += [0x08004bd2, 0x08004c6e, 0x08004d92]
fall7 = decomp.testfall("Testreihen/neug-O1.elf",
                        "Testreihen/neug-O1.bin",
                        "Testreihen/neug-O1.s",
                        0x08000000,
                        0x08006511,
                        basisadressen,
                        fall7fehler
                        )
                        
fall8fehler =  [4*x for x in range(0x08000800//4, (0x080020ec+4)//4)]
fall8fehler += [0x08005222, 0x080052be, 0x08005472]
fall8 = decomp.testfall("Testreihen/neug-O3.elf",
                        "Testreihen/neug-O3.bin",
                        "Testreihen/neug-O3.s",
                        0x08000000,
                        0x080079c1,
                        basisadressen,
                        fall8fehler
                        )
                        
fall9fehler = [0x0800480c]
fall9 = decomp.testfall("Testreihen/demsys-O0.elf",
                        "Testreihen/demsys-O0.bin",
                        "Testreihen/demsys-O0.s",
                        0x08000000,
                        0x08008c31,
                        basisadressen,
                        fall9fehler
                        )
                        
fall10fehler = [0x080030a2]
fall10 = decomp.testfall("Testreihen/demsys-O3.elf",
                        "Testreihen/demsys-O3.bin",
                        "Testreihen/demsys-O3.s",
                        0x08000000,
                        0x08007371,
                        basisadressen,
                        fall10fehler
                        )


faelle = [fall1, fall2, fall3, fall4, fall5, fall6, fall7, fall8, fall9, fall10]
#faelle = [fall5, fall6, fall9, fall10]
#faelle = [fall5, fall6]

tabelle1 = [] # Für die Übersichtstabelle am Ende
tabelle2 = []
fallzaehler = 0  
for fall in faelle:
    fallzaehler += 1
    print("Testfall Nr. %i" %fallzaehler, "(%s)" %fall.binfile)
    einsprung = fall.lade_bin()
    print("  Erzeuge Disassembly und suche Daten...")
    iterationen = 0
    while not fall.konvergent:
        print("    %i. Iteration..." %iterationen)
        fall.disassembly()
        fall.jumpsearch()
        fall.datensuche()
        datenlisten = fall.compare_databytes()
        print("    kor=%i" %len(datenlisten[0]), end='')
        print(" fdat=%i"   %len(datenlisten[1]), end='')
        print(" fops=%i"   %len(datenlisten[2]), end='')
        gesbytes = len(datenlisten[0])+len(datenlisten[1])+len(datenlisten[2])
        relcorr = 100.0 * len(datenlisten[0]) / gesbytes
        print(" %5.2f%% korrekt" %relcorr)
        iterationen += 1
    last_byte = 0
    """
    print("    Falsch als Daten (fdat):")
    for x in datenlisten[1]:
        if x-1 > last_byte:
            if last_byte != 0:
                print("      End:   0x%08x" %last_byte)
                print()
            print("      Start: 0x%08x" %x)
        last_byte = x
    """
    fall.check_jumps()
    #fall.schreibe_asm() # passiert jetzt nach der Funktionssuche
    
    # fälschlich als Daten bewertete Adressen anzeigen:
    #  decomp.print_hexlist(datenlisten[2])
    # fälschlich als Instruktionen bewertete Adressen anzeigen:
    #  decomp.print_hexlist(datenlisten[1])
    
    print("  Suche nach Funktionen...")
    ref_liste = fnkn.get_funktionen_ref(fall.elffile, fall.ende)
    
    # Überprüfung wie viele Funktionen in falsch als Code/Daten klassifizierten
    # Bereichen liegen:
    liegt_in_daten = []
    liegt_in_code  = []
    for funktion in ref_liste:
        if funktion[0] in datenlisten[1]:
            liegt_in_daten.append(funktion)
        elif funktion[0] in datenlisten[2]:
            liegt_in_code.append(funktion)
    print("    %i Funktionen in falschen Datenbereichen" %len(liegt_in_daten))
    #fnkn.zeige_funktionsliste(liegt_in_daten)
    print("    %i Funktionen in falschen Codebereichen" %len(liegt_in_code))
    #fnkn.zeige_funktionsliste(liegt_in_code)
    # Ende der Code/Daten-Fehler Funktionsprüfung    
    
    ges_liste = []        # Alle gefundenen Funktionen zu diesem Fall    
    algo_listen = []      # Listen der von den Algorithmen gefundenen Funktionen zu diesem Fall
    algo_verg_listen = [] # Listen der von den Algorithmen gefundenen Funktionen verglichen mit der Referenz    
    algo_einz_listen = [] # Listen der von jew. nur einem Algorithmus gefundenen Funktionen zu diesem Fall
   
    algo_anz = len(fnkn.get_funktionen)
    algozaehler = 0    
    for i in range(0, algo_anz): #erste Schleife über die Algos
        algozaehler += 1
        f_liste = fnkn.get_funktionen[i](fall.programm) # Funktionen die mit einem
                                                        # Algorithmus gefunden wurden.
        algo_listen.append(f_liste)                     # Liste mit Listen mit Funktionen
        vergleich = fnkn.ref_vergleich(ref_liste, f_liste) 
        algo_verg_listen.append(vergleich)
        
    ges_liste = fnkn.kombiniere_listen(algo_listen)  # enthält ALLE Funktionen
    #fnkn.zeige_funktionsliste(ges_liste)
    
    fall.functions = ges_liste
    fall.schreibe_asm() 
    
    for i in range(0, algo_anz): # zweite Schleife über die Algos
        verg_listen = algo_listen[i+1:] + algo_listen[:i]
        verg_liste = fnkn.kombiniere_listen(verg_listen)
        einzigartige = fnkn.ref_vergleich(verg_liste, algo_listen[i])[2]
        algo_einz_listen.append( fnkn.ref_vergleich(ref_liste ,einzigartige) )
        
    vergleich = fnkn.ref_vergleich(ref_liste, ges_liste)
    #f-pos anzeigen:        
    for i in range(0, algo_anz): # zweite Schleife über die Algos
        verg_listen = algo_listen[i+1:] + algo_listen[:i]
        verg_liste = fnkn.kombiniere_listen(verg_listen)
 
    # fälschlich gefundene Funktionen anzeigen:
    #fnkn.zeige_funktionsliste(vergleich[2])
    # nicht gefundene Funktionen:
    #fnkn.zeige_funktionsliste(vergleich[1])
    
    algo_verg_listen.append(vergleich)
    tabelle1.append(algo_verg_listen)
    
    if tabelle2 == []: # ersten Fall hinzufügen
        for i in range(0, algo_anz):
            algo_bewertung = [len(algo_verg_listen[i][0]),
                              len(algo_verg_listen[i][2]),
                              len(algo_einz_listen[i][0]),
                              len(algo_einz_listen[i][2])]
            tabelle2.append(algo_bewertung)
    else:  # weitere Fälle hinzufügen
        for i in range(0, algo_anz):
            tabelle2[i][0] += len(algo_verg_listen[i][0])
            tabelle2[i][1] += len(algo_verg_listen[i][2])
            tabelle2[i][2] += len(algo_einz_listen[i][0])
            tabelle2[i][3] += len(algo_einz_listen[i][2])
    
    print("  Fertig.")
    print()


##############################################
## Anzeigen der ersten Tabelle:

def tab1_inhalt(fall, alg, eig, tabelle):
    inhalt = len(tabelle[fall][alg][eig])
    print("%i\t" %inhalt, end='')    

zeilen = len(tabelle1[0])*2 +1 +1  +1 # +1 für die Zeile mit den Fallnummern
# +1 für die vorletze Zeile mit den falsch Negativen
# +1 für die letzte Zeile mit der Gesamtzahl an Funktionen
# *2 für jeweils korrekt u. falsch-positiv
spalten = len(tabelle1) +1 # +1 für die Spalte mit den Beschreibungen
#print("Zeilen = %i;" %zeilen, "Spalten = %i;" %spalten)
print()
for i in range(0, zeilen):
    for j in range(0, spalten):
        if i == 0:       # erste Zeile
            if j == 0:   # erste Spalte
                print("\t\t", end='')
            else:        # Weitere Spalten: Algorithmen
                print("Fall %i\t" %j, end='')
            if j == spalten-1: #letzte Spalte:
                print()
        elif i == zeilen - 4: # vorvorvorletzte Zeile
            zeile = i//2+1
            if j == 0:
                print("Gesamt korrekt\t", end='')
            else:
                tab1_inhalt(j-1, zeile-1, 0, tabelle1)
            if j == spalten-1:
                print()
        elif i == zeilen - 3: # vorvorletzte Zeile
            zeile = i//2            
            if j == 0:
                print("Gesamt f.-pos.\t", end='')
            else:
                tab1_inhalt(j-1, zeile-1, 2, tabelle1)
            if j == spalten-1:
                print()
        elif i == zeilen - 2: # vorletzte Zeile
            zeile = i//2            
            if j == 0:
                print("Gesamt f.-neg.\t", end='')
            else:
                tab1_inhalt(j-1, zeile-1, 1, tabelle1)
            if j == spalten-1:
                print()
        elif i == zeilen - 1: # letzte Zeile
            zeile = i//2 
            if j == 0:
                print("Gesamtanzahl\t", end='')
            else:
                inhalt = len(tabelle1[j-1][zeile-2][0])
                inhalt+= len(tabelle1[j-1][zeile-2][1])
                print("%i\t" %inhalt, end='')  
            if j == spalten-1:
                print()
        elif i%2:        # ungerade Zeilen: korrekte Ergebnisse
            zeile = i//2 +1
            if j == 0:
                print("Algo %i korrekt\t" %zeile, end='')
            else:
                tab1_inhalt(j-1, zeile-1, 0, tabelle1)
            if j == spalten-1:
                print()
        else:
            zeile = i//2
            if j == 0:
                print("Algo %i f.-pos.\t" %zeile, end='')
            else:
                tab1_inhalt(j-1, zeile-1, 2, tabelle1)
            if j == spalten-1:
                print()

print()
print()


################################################
## Anzeigen der zweiten Tabelle:

def erste_spalte(zeile):
    if zeile == 1:
        print("insg. korrekt\t", end = '')
    elif zeile == 2:
        print("insg. f-pos.\t", end = '')
    elif zeile == 3:
        print("einz. korrekt\t", end = '')
    elif zeile == 4:
        print("einz. f-pos.\t", end = '')
        
zeilen = 5 # Überschrift, allg-kor, allg-f-pos, einz-kor, einz-f-pos
spalten = len(tabelle2) +1 # Anzahl der Algorithmen + 1
for i in range(0, zeilen):
    if i == 0:
        for j in range(0, spalten):
            if j == 0:
                print("\t\t", end = '')
            else:
                print("Algo %i\t" %j, end = '')
                if j == spalten - 1:
                    print()
    else:
        for j in range(0, spalten):
            if j == 0:
                erste_spalte(i)
            else:
                print("%i\t" %tabelle2[j-1][i-1], end='')
                if j == spalten - 1:
                        print()
