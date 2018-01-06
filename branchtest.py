#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Jan  3 00:40:01 2018

@author: andreas
"""

def is_branch(insn):
    b_address = None
    branchcodes = ["b", "bx", "bl", "blx", "ble"]
    cbcodes = ["cbz", "cbnz"]
    if insn.mnemonic in branchcodes:
        print("  branch")
        b_address = insn.operands[0].mem.base # TODO: Check wether more 
        # then mem.base needs to be taken into account (i.e. index, scale...)
    elif insn.mnemonic in cbcodes:
        print("  cbranch")
        b_address = insn.operands[1].mem.base # TODO: Check wether more 
        # then mem.base needs to be taken into account (i.e. index, scale...)
    return b_address



offset = 0x08000000
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
md.detail = True
md.skipdata = False
vierer = b"\xd8\xbb"  + b"\x4f\xf0\x00\x01\xbd\xe8\x00\x88" + b"\x01\xe0"
disasm = md.disasm(vierer, offset) # ein oder zwei Instruktionen
for insn in disasm:
    print("%s\t%s" %(insn.mnemonic, insn.op_str))
    adress = is_branch(insn)
    if adress is not None:
        print("  0x%08x" %adress)

