import pytest
import pyvex
from peephole import canonicalize

"""
20 | t73 = GET:I32(eax)
21 | t72 = Shl32(t73,0x02)
22 | t71 = Add32(t72,0x0804f600)
23 | t74 = LDle:I32(t71)
"""
def test_register_realloc():

    # arrange

    instructions = []    
    a = pyvex.stmt.Get(8, "Ity_I32")
    b = pyvex.stmt.WrTmp(73, a)

    instructions += [b]

    shl_op = "Iop_Shl32"
    c = pyvex.const.U8(2)
    d = pyvex.expr.RdTmp(73)
    e = pyvex.expr.Binop(shl_op, [d,c])
    f = pyvex.stmt.WrTmp(72, e)
    instructions += [f]

    add_op = "Iop_Add32"
    c = pyvex.const.U32(134542848)
    d = pyvex.expr.RdTmp(72)
    e = pyvex.expr.Binop(add_op, [d,c])
    f = pyvex.stmt.WrTmp(71, e)
    instructions += [f]

    d = pyvex.expr.RdTmp(71)
    e = pyvex.expr.Load("Iend_LE", "Ity_I32", d)
    f = pyvex.stmt.WrTmp(74, e)
    instructions += [f]

    solution = """t0 = GET:I32(offset=8)
t1 = Shl32(t0,0x02)
t2 = Add32(t1,0x0804f600)
t3 = LDle:I32(t2)\n"""

    # act
    seq = canonicalize(instructions)
    result = ""
    for i in seq:
        result += i.__str__() + "\n"

    # assert
    assert(result == solution)

def test_register_realloc2():
    """
    t0 = LDle:I32(0x083f5168)
    STle(0x081f4ff0) = t0
    STle(0x081f4ff4) = 0x88049574
    PUT(offset=8) = 0x00000000
    PUT(offset=12) = 0x00000000
    t1 = LDle:I8(0x081f4ff0)
    PUT(offset=8) = t2
    t3 = GET:I32(offset=8)
    t4 = Shl32(t5,0x02)"""

    """
    original:
    01 | t67 = LDle:I32(0x083f5168)
    05 | STle(0x081f4ff0) = t67
    08 | STle(0x081f4ff4) = 0x88049574
    10 | PUT(eax) = 0x00000000
    13 | PUT(edx) = 0x00000000
    16 | t70 = LDle:I8(0x081f4ff0)
    17 | PUT(al) = t70
    20 | t73 = GET:I32(eax)
    21 | t72 = Shl32(t73,0x02)
    """
    instructions = []
    d = pyvex.const.U32(0x083f5168)
    e = pyvex.expr.Load("Iend_LE", "Ity_I32", d)
    f = pyvex.stmt.WrTmp(67, e)
    instructions += [f]

    d = pyvex.expr.RdTmp(67)
    e = pyvex.stmt.Store(pyvex.const.U32(0x081f4ff0), d, "Iend_LE")
    instructions += [e]

    d = pyvex.const.U32(0x88049574)
    e = pyvex.stmt.Store(pyvex.const.U32(0x081f4ff4), d, "Iend_LE")
    instructions += [e]

    d = pyvex.const.U32(0x00000000)
    e = pyvex.stmt.Put(d, 8)
    instructions += [e]    

    d = pyvex.const.U32(0x00000000)
    e = pyvex.stmt.Put(d, 16)
    instructions += [e]    

    d = pyvex.const.U8(0x081f4ff0)
    e = pyvex.expr.Load("Iend_LE", "Ity_I8", d)
    f = pyvex.stmt.WrTmp(70, e)
    instructions += [f]    

    d = pyvex.expr.RdTmp(70)
    e = pyvex.stmt.Put(d, 8)
    instructions += [e]       

    a = pyvex.stmt.Get(8, "Ity_I32")
    b = pyvex.stmt.WrTmp(73, a)    
    instructions += [b]

    shl_op = "Iop_Shl32"
    c = pyvex.const.U8(2)
    d = pyvex.expr.RdTmp(73)
    e = pyvex.expr.Binop(shl_op, [d,c])
    f = pyvex.stmt.WrTmp(72, e)
    instructions += [f]

    solution = """t0 = LDle:I32(0x083f5168)
STle(0x081f4ff0) = t0
STle(0x081f4ff4) = 0x88049574
PUT(offset=8) = 0x00000000
PUT(offset=12) = 0x00000000
t1 = LDle:I8(0x81f4ff0)
PUT(offset=8) = t1
t2 = GET:I32(offset=8)
t3 = Shl32(t2,0x02)\n"""

    for i in instructions:
        i.pp()
    # act
    seq = canonicalize(instructions)
    result = ""
    for i in seq:
        result += i.__str__() + "\n"

    # assert
    assert(result == solution)    