# X86PatternMatching
Finds similar sequences of instructions in binaries, using angr and pyvex, intended for program deobfuscation.

# Disclaimer

Work in progress, limited to 32-bit binaires for now.

# Todo

* Remove overlapping patterns (P1).
* Symbolically execute each pattern and try to synthetize it.

# Example output

Example run over only 1 basic block of a "Movfusacted" binary:

```
ipython -i peephole.py
Python 3.7.3 (default, Mar 26 2019, 21:43:19) 
Type 'copyright', 'credits' or 'license' for more information
IPython 7.5.0 -- An enhanced Interactive Python. Type '?' for help.
WARNING | 2019-06-28 15:03:48,666 | cle.elf | Segment PT_LOAD is empty at 0x804b000!
Pattern found 4 times:
t0 = GET:I32(offset=8)
t1 = Shl32(t0,0x02)
t2 = Add32(t1,0x08000000)
t3 = LDle:I32(t2)
t4 = LDle:I8(0x08001000)
PUT(offset=12) = t4
t5 = GET:I32(offset=16)
t6 = Add32(t3,t5)
t7 = LDle:I8(t6)
PUT(offset=16) = t7

Pattern found 4 times:
t0 = LDle:I8(0x08000000)
PUT(offset=8) = t0
t1 = GET:I32(offset=8)
t2 = Shl32(t1,0x02)
t3 = Add32(t2,0x08001000)
t4 = LDle:I32(t3)
t5 = LDle:I8(0x08002000)
PUT(offset=12) = t5
t6 = GET:I32(offset=16)
t7 = Add32(t4,t6)
t8 = LDle:I8(t7)
PUT(offset=16) = t8

Pattern found 4 times:
t0 = GET:I32(offset=8)
t1 = Shl32(t0,0x02)
t2 = Add32(t1,0x08000000)
t3 = LDle:I32(t2)
t4 = LDle:I8(0x08001000)
PUT(offset=12) = t4
t5 = GET:I32(offset=16)
t6 = Add32(t3,t5)
t7 = LDle:I8(t6)
PUT(offset=16) = t7
t8 = GET:I32(offset=16)
STle(0x08002000) = t8

Pattern found 3 times:
t0 = GET:I32(offset=8)
STle(0x08000000) = t0
t1 = LDle:I8(0x08001000)
PUT(offset=8) = t1

Pattern found 4 times:
t0 = LDle:I8(0x08000000)
PUT(offset=8) = t0
t1 = GET:I32(offset=8)
t2 = Shl32(t1,0x02)
t3 = Add32(t2,0x08001000)
t4 = LDle:I32(t3)
t5 = LDle:I8(0x08002000)
PUT(offset=12) = t5
t6 = GET:I32(offset=16)
t7 = Add32(t4,t6)
t8 = LDle:I8(t7)
PUT(offset=16) = t8
t9 = GET:I32(offset=16)
STle(0x08003000) = t9

Pattern found 3 times:
t0 = LDle:I32(0x08000000)
t1 = LDle:I32(0x08001000)
t2 = Shl32(t0,0x02)
t3 = Add32(t2,0x08002000)
t4 = LDle:I32(t3)
t5 = Shl32(t1,0x02)
t6 = Add32(t4,t5)
t7 = LDle:I32(t6)
STle(0x08000000) = t7

Pattern found 3 times:
t0 = GET:I32(offset=8)
STle(0x08000000) = t0
t1 = LDle:I8(0x08001000)
PUT(offset=8) = t1
t2 = GET:I32(offset=8)
t3 = Shl32(t2,0x02)
t4 = Add32(t3,0x08002000)
t5 = LDle:I32(t4)
t6 = LDle:I8(0x08003000)
PUT(offset=12) = t6
t7 = GET:I32(offset=16)
t8 = Add32(t5,t7)
t9 = LDle:I8(t8)
PUT(offset=16) = t9

Pattern found 3 times:
t0 = GET:I32(offset=8)
t1 = Shl32(t0,0x02)
t2 = Add32(t1,0x08000000)
t3 = LDle:I32(t2)
t4 = LDle:I8(0x08001000)
PUT(offset=12) = t4
t5 = GET:I32(offset=16)
t6 = Add32(t3,t5)
t7 = LDle:I8(t6)
PUT(offset=16) = t7
t8 = GET:I32(offset=16)
STle(0x08002000) = t8
t9 = LDle:I8(0x08003000)
PUT(offset=8) = t9

Pattern found 3 times:
t0 = LDle:I8(0x08000000)
PUT(offset=8) = t0
t1 = GET:I32(offset=8)
t2 = Shl32(t1,0x02)
t3 = Add32(t2,0x08001000)
t4 = LDle:I32(t3)
t5 = LDle:I8(0x08002000)
PUT(offset=12) = t5
t6 = GET:I32(offset=16)
t7 = Add32(t4,t6)
t8 = LDle:I8(t7)
PUT(offset=16) = t8
t9 = GET:I32(offset=16)
STle(0x08003000) = t9
t10 = LDle:I8(0x08004000)
PUT(offset=8) = t10

Pattern found 3 times:
t0 = GET:I32(offset=8)
STle(0x08000000) = t0
t1 = LDle:I8(0x08001000)
PUT(offset=8) = t1
t2 = GET:I32(offset=8)
t3 = Shl32(t2,0x02)
t4 = Add32(t3,0x08002000)
t5 = LDle:I32(t4)
t6 = LDle:I8(0x08003000)
PUT(offset=12) = t6
t7 = GET:I32(offset=16)
t8 = Add32(t5,t7)
t9 = LDle:I8(t8)
PUT(offset=16) = t9
t10 = GET:I32(offset=16)
STle(0x08004000) = t10

Pattern found 2 times:
t0 = GET:I32(offset=8)
STle(0x08000000) = t0
t1 = LDle:I8(0x08001000)
PUT(offset=8) = t1
t2 = GET:I32(offset=8)
t3 = Shl32(t2,0x02)
t4 = Add32(t3,0x08002000)
t5 = LDle:I32(t4)
t6 = LDle:I8(0x08003000)
PUT(offset=12) = t6
t7 = GET:I32(offset=16)
t8 = Add32(t5,t7)
t9 = LDle:I8(t8)
PUT(offset=16) = t9
t10 = GET:I32(offset=16)
STle(0x08004000) = t10
t11 = LDle:I8(0x08005000)
PUT(offset=8) = t11

Pattern found 2 times:
t0 = LDle:I32(0x08000000)
t1 = LDle:I32(0x08001000)
t2 = Shl32(t0,0x02)
t3 = Add32(t2,0x08002000)
t4 = LDle:I32(t3)
t5 = Shl32(t1,0x02)
t6 = Add32(t4,t5)
t7 = LDle:I32(t6)
STle(0x08000000) = t7
t8 = LDle:I32(0x08000000)
t9 = LDle:I32(0x08003000)
t10 = Shl32(t8,0x02)
t11 = Add32(t10,0x08002000)
t12 = LDle:I32(t11)
t13 = Shl32(t9,0x02)
t14 = Add32(t12,t13)
t15 = LDle:I32(t14)
STle(0x08000000) = t15
