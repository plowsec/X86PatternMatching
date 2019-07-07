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
import logging
#from birdseye import eye

from InstructionVisitor import *

addr_main = 0x08049574
addr_end_alu_eq = 0x08049657
addr_end_load_jmp_regs = 0x08049731

proj = angr.Project("bin/test_mov_strip.bin", auto_load_libs=False)
main = proj.factory.block(addr_main)

"""
* restore symbols
* work with symbols
todo:
* canonicalize memory addresses (done)
* add filter heuristic: among the most found ones, keep the longest, trim the instructions that does nothing
* add filter heuristic: if pattern is complete, keep it, discard the others that are similar.
* whole program disassembly (done) (only for movfuscated binaries)
* find a valid criteria for automated disassembly stop
* recognize patterns and put labels (P1)
* simplify
* patterns must be complete:
    - if a register is referenced but not assigned in the pattern, fetch its assignment
    - may really extend the pattern.....
"""

histogram = Counter()
maxlen = 20

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
    
    try:
        offset = expr.tmp
    except:
        print(type(expr))
        print(expr.value)
        print("tag = " + str(expr.tag))
        raise Exception("bug")
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

def allocate_addr(current_state, expr):
    
    offset = expr.con.value
    offsets = list(current_state.values())

    if offset in offsets:
        
        for k,_ in current_state.items():

            if current_state[k] == offset:
                return k

        raise Exception("allocate_addr: no key found")

    else:
        # find first free register
        for k,_ in current_state.items():

            if current_state[k] == -1:
                current_state[k] = offset
                return k

        raise Exception("allocate_addr: no free register left")

def handle_const(addr, allocated_addr):

   
    if type(addr) == pyvex.expr.Const:

        new_addr = allocate_addr(allocated_addr, addr)
        return new_addr

    else:
        raise Exception("Bug not implemented")



"""
    @param instructions : type is IRSB

    todo: re-think that whole function, so horrible to read
"""
#@eye
def canonicalize(instructions):
    
    new_instructions = []  
    available_registers = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi']
    allocated_registers = dict.fromkeys(available_registers, -1)
    allocated_tmp = dict.fromkeys(range(maxlen*2), -1)
    allocated_addr = dict.fromkeys(range(0x08000000,0x08050000, 0x1000), -1)

    for ins in instructions:
        #ins.pp()
        ins = deepcopy(ins)
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

            # seems hackish but there is apprently no other way.
            if hasattr(ins.data, "addr") and not ins.data.addr.tag in ["Iex_Const", "Ico_U32", "Ico_U8", "Ico_U16"]:
                
                allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins.data.addr)
                # ins.data is an immutable Load object
                new_RdTmp = pyvex.expr.RdTmp(new_tmp)
                ins.data.addr = new_RdTmp
            
            elif hasattr(ins.data, "addr") and type(ins.data.addr) == pyvex.expr.Const:
                new_addr = handle_const(ins.data.addr, allocated_addr)
                ins.data.addr = pyvex.expr.Const(pyvex.const.U32(new_addr))
                #ins.pp()
            
            if ins.data.tag == "Iex_Binop":

                for i in range(len(ins.data.args)):

                    if ins.data.args[i].tag == "Iex_RdTmp":
                        allocated_tmp, new_tmp = allocate_tmp(allocated_tmp, ins.data.args[i])
                        new_RdTmp = pyvex.expr.RdTmp(new_tmp)
                        ins.data.args[i] = new_RdTmp
                    elif type(ins.data.args[i]) == pyvex.expr.Const:
                        new_addr = handle_const(ins.data.args[i], allocated_addr)
                        ins.data.args[i] = pyvex.expr.Const(pyvex.const.U32(new_addr))
            
            new_instructions += [ins]
            continue
            
        elif ins.tag == "Ist_Store":

            if type(ins.addr) == pyvex.expr.Const:

                new_addr = handle_const(ins.addr, allocated_addr)
                ins.addr = pyvex.expr.Const(pyvex.const.U32(new_addr))
                #ins.pp()
            if type(ins.data) == pyvex.expr.Const:
                new_addr = handle_const(ins.data, allocated_addr)
                ins.data = pyvex.expr.Const(pyvex.const.U32(new_addr))
                #ins.pp()   

        if hasattr(ins, "offset"):
            allocated_registers, ins.offset = allocate_registers(allocated_registers, ins)

        if hasattr(ins, "addr") and not hasattr(ins.addr, "tag"):
            
            ins.pp()
            raise Exception("bug")

        if hasattr(ins, "addr") and hasattr(ins.addr, "tag") and not ins.addr.tag in ["Iex_Const", "Ico_U32", "Ico_U8", "Ico_U16"]:
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
        
#         
def gen_histogram(block):

    instructions = []

    # filter out the junk
    for ins in block.vex.statements:
        if ins.tag in ["Ist_IMark"]:
            continue
        
        if ins.tag == "Ist_Put":

            if proj.arch.translate_register_name(ins.offset) == "eip":
                continue
        instructions += [ins]

    for i in range(len(instructions)):
       
        # For each sequence of l ength j+1...
        for j in range(1,maxlen+1):
            
            if i + j + 1 > len(instructions):
                return

            realloc_analysis = ReallocationVisitor(maxlen, proj)
            seq = realloc_analysis.canonicalize(instructions[i:i+j+1])
            tmp_analysis = TmpTrackingVisitor()
            if len(seq) > 0 and tmp_analysis.is_pattern_complete(seq):
                prettyprint = ""
                for x in seq:
                    prettyprint += x.__str__() + "\n"
                #histogram[tuple(seq)] += 1
                histogram[prettyprint] += 1

def whole_program_analysis():

    current_block = main

    while True:

        logging.warning("Analyzing pattern in VEX basic block %x-%x",\
            current_block.vex.instruction_addresses[0],\
            current_block.vex.instruction_addresses[-1])

        gen_histogram(current_block)
        break

        # todo: find out how to locate the last basic block when no function where found
        if main.vex.direct_next:
            last_address = current_block.vex.instruction_addresses[-1]

            if last_address > 0x0804A078:
                logging.critical("Bad stop, would have gone into an infinite loop")
                break
            current_block = proj.factory.block(last_address)

        else:
            print("End of program")
            return

def run():
    logging.basicConfig(level=logging.INFO)

    whole_program_analysis()

    i = 0
    clean_histogram = Counter()
    all_keys = list(histogram.keys())
    filtered = 0

    # remove overlapping patterns (slow!)
    for i in range(len(all_keys)):
        
        key = all_keys[i]   
        overlapped = False

        for j in range(len(all_keys)):

            if i == j:
                continue
            
            if key in all_keys[j] and histogram[all_keys[j]] > 1:
                
                if len(key.split("\n")) <= 4:
                    filtered += 1
                    overlapped = True
                    break
                else:
                    occurrences_pattern1 = histogram[key]
                    occurrences_pattern2 = histogram[all_keys[j]]
                    if occurrences_pattern1 < occurrences_pattern2:
                        filtered += 1
                        overlapped = True
                        break

        if not overlapped:

            clean_histogram[key] = histogram[key]

        
    if filtered > 0:
        logging.warning("Filtered %d patterns", filtered)

    most_common = clean_histogram.most_common()
    print(most_common[0])
    print(most_common[0][0])
    print(len(most_common[0][0]))
    print(most_common[0][1])
    most_common = sorted(clean_histogram.items(), key=lambda x: 200*x[1] + (1-len(x[0])), reverse=True)

    logging.warning("Identified %d patterns, here are the most interesting ones:", len(clean_histogram))
    for seq in most_common:

        if not seq[1] > 1:
            continue
        print(f"Pattern found {seq[1]} times:")
        #print_canonicalized_sequence(seq[0])
        print(seq[0])

if __name__ == "__main__":
    run()