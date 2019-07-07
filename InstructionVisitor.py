from dataclasses import dataclass
from copy import deepcopy
import pyvex
import sys

class InstructionVisitor:

    def callback_read_tmp(self, ins, parent=None):
        
        return [ins]

    def callback_write_tmp(self, ins, parent=None):
        
        return [ins]

    def callback_multi_changes(self, lhs, rhs, parent=None):
        
        return lhs + rhs
     
    def callback_reg(self, ins, parent=None):
        return [ins]

    def callback_offset(self, ins, parent=None):
        return [ins]

    def visit_RdTmp(self, ins, parent=None):

        return self.callback_read_tmp(ins, parent)

    def visit_Binop(self, ins, parent=None):

        lhs = ins.args[0]
        rhs = ins.args[1]

        l = self.visit_Generic(lhs, ins)
        r = self.visit_Generic(rhs, ins)

        parent.data.args[0] = l
        parent.data.args[1] = r
        return self.callback_multi_changes(l, r, parent)

    def visit_Store(self, ins, parent=None):

        lhs = self.visit_Generic(ins.addr, parent)
        rhs = self.visit_Generic(ins.data, parent)

        parent.addr = lhs
        parent.data = rhs
        return self.callback_multi_changes(lhs, rhs, parent)

    def visit_Put(self, ins, parent=None):
        reg = self.callback_reg(ins, parent)
        new_data = self.visit_Generic(ins.data, ins)
        ins.data = new_data
        return self.callback_multi_changes(reg, new_data, ins)


    def visit_Const(self, ins, parent=None):
        
        return self.callback_offset(ins, parent)

    def visit_Get(self, ins, parent=None):
        return self.callback_reg(ins, parent)

    def visit_Load(self, ins, parent=None):
  
        new_addr =  self.visit_Generic(ins.addr, ins)
        ins.addr = new_addr
        return new_addr

    def visit_Generic(self, ins, parent=None):

        if ins.tag == "Ist_WrTmp":
            lhs = self.callback_write_tmp(ins, parent)
            rhs = self.visit_Generic(ins.data, parent)
            return self.callback_multi_changes(lhs, rhs, parent)
        
        elif ins.tag == "Iex_Binop":

            return self.visit_Binop(ins, parent)

        elif ins.tag == "Iex_RdTmp":
            
            return self.visit_RdTmp(ins, parent)

        elif ins.tag == "Ist_Store":

            return self.visit_Store(ins, ins)

        elif ins.tag == "Ist_Put":
          
            return self.visit_Put(ins, parent)

        elif ins.tag == "Iex_Load":
          
          return self.visit_Load(ins, parent)

        elif ins.tag == "Iex_Get":
            return self.visit_Get(ins, parent)

        elif ins.tag == "Iex_Const":
            return self.visit_Const(ins, parent)

        else:
            print("Unhandled instruction type: " + ins.tag)
            return ins


class ReallocationVisitor(InstructionVisitor):

    state_tmp: dict # maps encountered vraible names and reallocated ones.
    state_registers: dict # maps encountered registers names and reallocated ones
    state_offsets: dict # maps encountered memory addresses or constants and realloc. ones.
    _available_registers = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi']

    def __init__(self, maxlen, proj):
        self.state_registers = dict.fromkeys(self._available_registers, -1)
        self.state_tmp = dict.fromkeys(range(maxlen*2), -1)
        self.state_offsets = dict.fromkeys(range(0x08000000,0x08050000, 0x1000), -1)
        self.proj = proj

    def allocate_registers(self, statement):
        
        offset = statement.offset
        offsets = list(self.state_registers.values())

        if offset in offsets:
            
            for k,_ in self.state_registers.items():

                if self.state_registers[k] == offset:
                    reg = self.proj.arch.get_register_offset(k)
                    return reg

            raise Exception("allocate_register: no key found")

        else:
            # find first free register
            for k,_ in self.state_registers.items():

                if self.state_registers[k] == -1:
                    reg = self.proj.arch.get_register_offset(k)
                    self.state_registers[k] = reg
                    return reg

            raise Exception("allocate_register: no free register left")

    def allocate_tmp(self, expr):
        
        offset = expr.tmp
        offsets = list(self.state_tmp.values())

        if offset in offsets:
            
            for k,_ in self.state_tmp.items():

                if self.state_tmp[k] == offset:
                    return k

            raise Exception("allocate_tmp: no key found")

        else:
            # find first free register
            for k,_ in self.state_tmp.items():

                if self.state_tmp[k] == -1:
                    self.state_tmp[k] = offset
                    return k

            raise Exception("allocate_tmp: no free register left")

    def allocate_addr(self, expr: pyvex.expr.Const):
        
        offset = expr.con.value
        offsets = list(self.state_offsets.values())

        if offset in offsets:
            
            for k,_ in self.state_offsets.items():

                if self.state_offsets[k] == offset:
                    return k

            raise Exception("allocate_addr: no key found")

        else:
            # find first free register
            for k,_ in self.state_offsets.items():

                if self.state_offsets[k] == -1:
                    self.state_offsets[k] = offset
                    return k

            raise Exception("allocate_addr: no free register left")

    def callback_read_tmp(self, ins, parent):
        new_tmp = self.allocate_tmp(ins)
        new_RdTmp = pyvex.expr.RdTmp(new_tmp)
        parent.replace_expression(ins, new_RdTmp)
        return new_RdTmp

    def callback_write_tmp(self, ins, parent):
        new_tmp = self.allocate_tmp(ins)

        parent.tmp = new_tmp
        ins.tmp = new_tmp
        return ins

    def callback_reg(self, ins, parent):

        new_reg = self.allocate_registers(ins)

        ins.offset = new_reg

    def callback_offset(self, ins, parent):

        if type(ins.con) != pyvex.const.U32:
            return ins

        if ins.con.value == 0:
            return ins

        new_offset = self.allocate_addr(ins)

        return pyvex.expr.Const(pyvex.const.U32(new_offset))

    def callback_multi_changes(self, lhs, rhs, parent):

        return parent
    

    def canonicalize(self, instructions: list):
        
        new_instructions = []

        for ins in instructions:
            ins = deepcopy(ins)

            new_instructions += [self.visit_Generic(ins, ins)]
        
        return new_instructions

class TmpTrackingVisitor(InstructionVisitor):

    @dataclass
    class State:
        state: str
        id: int

    variables: dict

    def callback_read_tmp(self, tmp, parent=None):
        return [TmpTrackingVisitor.State("read", tmp.tmp)]

    def callback_write_tmp(self, tmp, parent=None):
        return [TmpTrackingVisitor.State("declared", tmp.tmp)]

    def track_data_states(self, instructions: list) -> dict:
                 
        variables = {}

        for ins in instructions:
            
            ins = deepcopy(ins)
            states = self.visit_Generic(ins, ins)

            for state in states:

                if not type(state) == TmpTrackingVisitor.State:
                    continue

                if state.id in variables:
                    variables[state.id] += [state.state]

                else:
                    variables[state.id] = [state.state]

        return variables

    def is_pattern_complete(self, instructions: list) -> bool:
           
        complete = True
        variables = self.track_data_states(instructions)

        for k, v in variables.items():

            if not sorted(v) == v:
                print(f"Found invalid state order in variable t{k}: {v}", file=sys.stderr)
                complete = False
            
            if not "declared" in v:
                print(f"Found an uninitialized read in t{k}: {v}", file=sys.stderr)
                complete = False

            if not "read" in v:
                print(f"Found unused variable: t{k}", file=sys.stderr)
                complete = False

        return complete