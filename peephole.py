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

maxlen = 20

""" Removes the useless instructions such Ist_IMark
and the update made to the EIP register.

@param instructions list of pyvex statements
@return the filter list of pyvex statements

"""
def filter_junk_instructions(instructions: list) -> list:
    new_instructions = []

    for ins in instructions:
        if ins.tag in ["Ist_IMark"]:
            continue
        
        if ins.tag == "Ist_Put":

            if proj.arch.translate_register_name(ins.offset) == "eip":
                continue

        new_instructions += [ins]
    
    return new_instructions

""" Computes an histogram of recurring sequences
of instructions.

To do that, each instruction is canonicalised to be
resilient against registers renaming, and the list
of resulting patterns is filtered so as to produce
only "stand-alone" patterns.
"""
def gen_histogram(block: angr.block.Block) -> dict:

    instructions = filter_junk_instructions(block.vex.statements)
    histogram = Counter()

    for i in range(len(instructions)):
       
        # For each sequence of l length j+1...
        for j in range(1,maxlen+1):
            
            if i + j + 1 > len(instructions):
                break

            realloc_analysis = ReallocationVisitor(maxlen, proj)
            seq = realloc_analysis.canonicalize(instructions[i:i+j+1])
            tmp_analysis = TmpTrackingVisitor()
            
            if len(seq) > 0 and tmp_analysis.is_pattern_complete(seq):
                prettyprint = ""
                
                for x in seq:
                    prettyprint += x.__str__() + "\n"
                
                histogram[prettyprint] += 1

        # no loop labels in python ;(
        else: # break was not executed
            continue
        break

    return histogram

""" Computes the histogram over the whole program.
This function is obviously incorrect. We will need to:
- List the functions recognized by angr
- Iterate over all of their basic blocks.

In case no function is found, hmmm do smthing.
"""
def whole_program_analysis() -> dict:

    current_block = main
    global_histogram = Counter()
    while True:

        logging.warning("Analyzing pattern in VEX basic block %x-%x",\
            current_block.vex.instruction_addresses[0],\
            current_block.vex.instruction_addresses[-1])

        global_histogram += gen_histogram(current_block)
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
            break

    return global_histogram

""" Removes overlapping patterns and those
occuring less than 2 times.
"""
def filter_patterns(histogram: dict) -> dict:
    
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
                    overlapped = True
                    break
                else:
                    occurrences_pattern1 = histogram[key]
                    occurrences_pattern2 = histogram[all_keys[j]]
                    if occurrences_pattern1 < occurrences_pattern2:
                        overlapped = True
                        break

        # keep only non-overlapping pattern that occur more than 1 time
        if not overlapped and histogram[key] > 1:

            clean_histogram[key] = histogram[key]
        else:
            filtered += 1

    if filtered > 0:
        logging.warning("Filtered %d patterns", filtered)

    return clean_histogram

def run():

    logging.basicConfig(level=logging.INFO)

    # compute the histogram over the whole program
    histogram = whole_program_analysis()

    # filter them
    clean_histogram = filter_patterns(histogram)
    
    # take the n most common ones and sort them (the ones with many insns are more interesting)
    most_common = clean_histogram.most_common()
    most_common = sorted(clean_histogram.items(), key=lambda x: 200*x[1] + (1-len(x[0])), reverse=True)

    logging.warning("Identified %d patterns, here are the most interesting ones:", len(clean_histogram))
    
    # print the patterns
    for seq in most_common:

        print(f"Pattern found {seq[1]} times:")
        print(seq[0])

if __name__ == "__main__":
    run()