from dataclasses import dataclass


class InstructionVisitor:

    def callback_read_tmp(self, tmp: int):
        
        return tmp

    def callback_write_tmp(self, tmp: int):
        return tmp

    def visit_RdTmp(self, ins):

        #return [State("read", ins.tmp)]
        return self.callback_read_tmp(ins.tmp)

    def visit_Binop(self, ins):

        lhs = ins.args[0]
        rhs = ins.args[1]

        l = self.visit_Generic(lhs)
        r = self.visit_Generic(rhs)

        return l + r

    def visit_Store(self, ins):

        lhs = self.visit_Generic(ins.addr)
        rhs = self.visit_Generic(ins.data)

        return lhs + rhs

    """
        returns a list of State objects
        May be None
    """
    def visit_Generic(self, ins):

        # expects a variable declaration in LHS, maybe
        # variable read in RHS.
        if ins.tag == "Ist_WrTmp":
            
            #lhs = [State("declared", ins.tmp)]
            lhs = self.callback_write_tmp(ins.tmp)
            return lhs + self.visit_Generic(ins.data)
            #return lhs + self.visit_Generic(ins.data)
        
        elif ins.tag == "Iex_Binop":

            return self.visit_Binop(ins)

        elif ins.tag == "Iex_RdTmp":
            
            return self.visit_RdTmp(ins)

        elif ins.tag == "Ist_Store":

            return self.visit_Store(ins)

        elif ins.tag == "Ist_Put":

            return self.visit_Generic(ins.data)

        elif ins.tag == "Iex_Load":
            
            return self.visit_Generic(ins.addr)
        
        else:
            # todo: Get
            return []


class ReallocationVisitor(InstructionVisitor):

    state_tmp: dict # maps encountered vraible names and reallocated ones.
    state_registers: dict # maps encountered registers names and reallocated ones
    state_offsets: dict # maps encountered memory addresses or constants and realloc. ones.
    _available_registers = ['eax', 'ecx', 'edx', 'ebx', 'esi', 'edi']

    def __init__(self, maxlen):
        state_registers = dict.fromkeys(self._available_registers, -1)
        state_tmp = dict.fromkeys(range(maxlen*2), -1)
        state_offsets = dict.fromkeys(range(0x08000000,0x08050000, 0x1000), -1)


class TmpTrackingVisitor(InstructionVisitor):

    @dataclass
    class State:
        state: str
        id: int

    variables: dict

    def callback_read_tmp(self, tmp: int):
        return [TmpTrackingVisitor.State("read", tmp)]

    def callback_write_tmp(self, tmp: int):
        return [TmpTrackingVisitor.State("declared", tmp)]

    def is_pattern_complete(self, instructions: list) -> bool:
           
        variables = {}
        complete = True

        for ins in instructions:
            
            states = self.visit_Generic(ins)

            for state in states:

                if state is None:
                    continue

                if state.id in variables:
                    variables[state.id] += [state.state]

                else:
                    variables[state.id] = [state.state]

        for k, v in variables.items():

            if not sorted(v) == v:
                print(f"Found invalid state order in variable t{k}: {v}")
                complete = False
            
            if not "declared" in v:
                print(f"Found an uninitialized read in t{k}: {v}")
                complete = False

            if not "read" in v:
                print(f"Found unused variable: t{k}")
                complete = False

        return complete