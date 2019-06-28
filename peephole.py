from dataclasses import dataclass
from angr import options
import angr
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.core.locationdb import LocationDB
from collections import Counter
from copy import deepcopy, copy
import pyvex

addr_main = 0x08049574
addr_end_alu_eq = 0x08049657
addr_end_load_jmp_regs = 0x08049731

proj = angr.Project("bin/test_mov_strip.bin", auto_load_libs=False)
main = proj.factory.block(addr_main)

"""
* restore symbols
* work with symbols
"""

known_constants = Counter()
histogram = Counter()
maxlen = 20

def update_constants(ir_statement):
    
    if len(ir_statement.constants) == 0:
        return
    
    for c in ir_statement.constants:
        
        value = str(hex(c.value))
        known_constants[value] += 1

def allocate_registers(current_state, statement):
    
    offset = statement.offset
    offsets = list(current_state.values())

    if offset in offsets:
        
        for k,_ in current_state.items():

            if current_state[k] == offset:
                reg = proj.arch.get_register_offset(k)
                return current_state, reg

        raise Exception("allocate_register: no key found")

    else:
        # find first free register
        for k,_ in current_state.items():

            if current_state[k] == -1:
                reg = proj.arch.get_register_offset(k)
                current_state[k] = reg
                return current_state, reg

        raise Exception("allocate_register: no free register left")

def allocate_tmp(current_state, expr):
    
    offset = expr.tmp
    offsets = list(current_state.values())

    if offset in offsets:
        
        for k,_ in current_state.items():

            if current_state[k] == offset:
                return current_state, k

        raise Exception("allocate_tmp: no key found")

    else:
        # find first free register
        for k,_ in current_state.items():

            if current_state[k] == -1:
                current_state[k] = offset
                return current_state, k

        raise Exception("allocate_tmp: no free register left")



"""
    @param instructions : type is IRSB
"""
def canonicalize(instructions):
    
    new_instructions = []
    available_registers = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi']
    allocated_registers = dict.fromkeys(available_registers, -1)
    allocated_tmp = dict.fromkeys(range(maxlen*2), -1)

    for ins in instructions:
        #ins.pp()
        #ins = copy(ins)
        if ins.tag in ["Ist_IMark"]:
            continue
        
        if ins.tag == "Ist_Put":

            if proj.arch.translate_register_name(ins.offset) == "eip":
                continue

        if ins.tag == "Ist_WrTmp":
            # t190 = LDle:I32(t187)
            # maximum two "tmp", ein ins.tmp and ins.data.addr.tmp
            allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins)
            ins.tmp = new_tmp

            if hasattr(ins.data, "addr") and not ins.data.addr.tag == "Iex_Const":
                allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins.data.addr)
                # ins.data is an immutable Load object
                new_RdTmp = pyvex.expr.RdTmp(new_tmp)
                #new_load = pyvex.expr.Load(ins.data.end, ins.data.ty, new_RdTmp)
                ins.data.addr = new_RdTmp
                #ins.replace_expression(ins.data.addr, new_RdTmp)
            
            if ins.data.tag == "Iex_Binop":

                for i in range(len(ins.data.args)):

                    if ins.data.args[i].tag == "Iex_RdTmp":
                        allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins.data.args[i])
                        new_RdTmp = pyvex.expr.RdTmp(new_tmp)
                        ins.data.args[i] = new_RdTmp
            
            new_instructions += [ins]
            continue
            
        if hasattr(ins, "offset"):
            allocated_registers, ins.offset = allocate_registers(allocated_registers, ins)

        if hasattr(ins, "addr") and not hasattr(ins.addr, "tag"):
            ins.pp()

        if hasattr(ins, "addr") and not ins.addr.tag == "Iex_Const":
            allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins.addr)
            if ins.addr.tag == "Iex_RdTmp":
                new_RdTmp = pyvex.expr.RdTmp(new_tmp)
                ins.replace_expression(ins.addr, new_RdTmp)
            else:
                raise Exception("bug")
        
        if hasattr(ins, "data") and hasattr(ins.data, "tmp"):
            allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins.data)
            if ins.data.tag == "Iex_RdTmp":
                new_RdTmp = pyvex.expr.RdTmp(new_tmp)
                ins.replace_expression(ins.data, new_RdTmp)
            else:
                raise Exception("bug")

        new_instructions += [ins]
    
    return new_instructions

def print_canonicalized_sequence(sequence):

    print("-"*20)
    for ins in sequence:
        ins.pp()
    
    print("-"*20)
        
def gen_histogram():

    instructions = []

    # filter out the junk
    for ins in main.vex.statements:
        if ins.tag in ["Ist_IMark"]:
            continue
        
        if ins.tag == "Ist_Put":

            if proj.arch.translate_register_name(ins.offset) == "eip":
                continue
        instructions += [ins]

    for i in range(len(instructions)):

        st = instructions[i]
        expr = list(st.expressions)
        update_constants(st)
        
        # For each sequence of l ength j+1...
        for j in range(1,maxlen+1):
            
            if i + j + 1 > len(instructions):
                return

            seq = canonicalize(instructions[i:i+j+1])
            if len(seq) > 0:
                prettyprint = ""
                for x in seq:
                    prettyprint += x.__str__() + "\n"
                #histogram[tuple(seq)] += 1
                histogram[prettyprint] += 1

print(known_constants)

gen_histogram()

i = 0
for seq in histogram.most_common():
    if len(seq[0]) >= 2:
        i+= 1
        if i > 40:
            break
            #pass

        print(f"Pattern found {seq[1]} times:")
        #print_canonicalized_sequence(seq[0])
        print(seq[0])


most_common = histogram.most_common()
