# X86PatternMatching
Finds similar sequences of instructions in binaries, using angr and pyvex, intended for program deobfuscation.

# Disclaimer

Work in progress, limited to 32-bit binaires for now.

# Todo

* Remove overlapping patterns (P1).
* Symbolically execute each pattern and try to synthetize it.

# Example output

```
ipython -i peephole.py
Python 3.7.3 (default, Mar 26 2019, 21:43:19) 
Type 'copyright', 'credits' or 'license' for more information
IPython 7.5.0 -- An enhanced Interactive Python. Type '?' for help.
WARNING | 2019-06-28 15:03:48,666 | cle.elf | Segment PT_LOAD is empty at 0x804b000!
Counter()
Pattern found 8 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=16)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=8)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=8)
t2 = Shl32(t3,0x02)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=8)
t2 = Shl32(t3,0x02)
t4 = Add32(t5,0x0804f600)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=8)
t2 = Shl32(t3,0x02)
t4 = Add32(t5,0x0804f600)
t6 = LDle:I32(t7)

Pattern found 4 times:
t0 = GET:I32(offset=8)
t1 = Shl32(t2,0x02)

Pattern found 4 times:
t0 = GET:I32(offset=8)
t1 = Shl32(t2,0x02)
t3 = Add32(t4,0x0804f600)

Pattern found 4 times:
t0 = GET:I32(offset=8)
t1 = Shl32(t2,0x02)
t3 = Add32(t4,0x0804f600)
t5 = LDle:I32(t6)

Pattern found 4 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804f600)

Pattern found 4 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804f600)
t4 = LDle:I32(t5)

Pattern found 4 times:
t0 = Add32(t1,0x0804f600)
t2 = LDle:I32(t3)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=16)
t2 = Add32(t3,t4)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=16)
t2 = Add32(t3,t4)
t5 = LDle:I8(t6)

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=16)
t2 = Add32(t3,t4)
t5 = LDle:I8(t6)
PUT(offset=12) = t7

Pattern found 4 times:
PUT(offset=8) = t0
t1 = GET:I32(offset=16)
t2 = Add32(t3,t4)
t5 = LDle:I8(t6)
PUT(offset=12) = t7
t8 = GET:I32(offset=16)

Pattern found 4 times:
t0 = GET:I32(offset=16)
t1 = Add32(t2,t3)

Pattern found 4 times:
t0 = GET:I32(offset=16)
t1 = Add32(t2,t3)
t4 = LDle:I8(t5)

Pattern found 4 times:
t0 = GET:I32(offset=16)
t1 = Add32(t2,t3)
t4 = LDle:I8(t5)
PUT(offset=8) = t6

Pattern found 4 times:
t0 = GET:I32(offset=16)
t1 = Add32(t2,t3)
t4 = LDle:I8(t5)
PUT(offset=8) = t6
t7 = GET:I32(offset=16)

Pattern found 4 times:
t0 = Add32(t1,t2)
t3 = LDle:I8(t4)

Pattern found 4 times:
t0 = Add32(t1,t2)
t3 = LDle:I8(t4)
PUT(offset=8) = t5

Pattern found 4 times:
t0 = Add32(t1,t2)
t3 = LDle:I8(t4)
PUT(offset=8) = t5
t6 = GET:I32(offset=16)

Pattern found 4 times:
t0 = LDle:I8(t1)
PUT(offset=8) = t2

Pattern found 4 times:
t0 = LDle:I8(t1)
PUT(offset=8) = t2
t3 = GET:I32(offset=16)

Pattern found 4 times:
STle(0x081f4fe0) = t0
t1 = LDle:I32(0x081f4fe0)

Pattern found 4 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x083f5170)

Pattern found 4 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x083f5170)
t4 = LDle:I32(t5)

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)
t4 = LDle:I32(t5)

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)
t4 = LDle:I32(t5)
t6 = Shl32(t7,0x02)

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)
t4 = LDle:I32(t5)
t6 = Shl32(t7,0x02)
t8 = Add32(t9,t10)

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)
t4 = LDle:I32(t5)
t6 = Shl32(t7,0x02)
t8 = Add32(t9,t10)
t11 = LDle:I32(t12)

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)
t4 = LDle:I32(t5)
t6 = Shl32(t7,0x02)
t8 = Add32(t9,t10)
t11 = LDle:I32(t12)
STle(0x081f4fe0) = t13

Pattern found 3 times:
t0 = Shl32(t1,0x02)
t2 = Add32(t3,0x0804c0a0)
t4 = LDle:I32(t5)
t6 = Shl32(t7,0x02)
t8 = Add32(t9,t10)
t11 = LDle:I32(t12)
STle(0x081f4fe0) = t13
t14 = LDle:I32(0x081f4fe0)

Pattern found 3 times:
t0 = Add32(t1,0x0804c0a0)
t2 = LDle:I32(t3)

Pattern found 3 times:
t0 = Add32(t1,0x0804c0a0)
t2 = LDle:I32(t3)
t4 = Shl32(t5,0x02)

Pattern found 3 times:
t0 = Add32(t1,0x0804c0a0)
t2 = LDle:I32(t3)
t4 = Shl32(t5,0x02)
t6 = Add32(t7,t8)

Pattern found 3 times:
t0 = Add32(t1,0x0804c0a0)
t2 = LDle:I32(t3)
t4 = Shl32(t5,0x02)
t6 = Add32(t7,t8)
t9 = LDle:I32(t10)

Pattern found 3 times:
t0 = Add32(t1,0x0804c0a0)
t2 = LDle:I32(t3)
t4 = Shl32(t5,0x02)
t6 = Add32(t7,t8)
t9 = LDle:I32(t10)
STle(0x081f4fe0) = t11

Pattern found 3 times:
t0 = Add32(t1,0x0804c0a0)
t2 = LDle:I32(t3)
t4 = Shl32(t5,0x02)
t6 = Add32(t7,t8)
t9 = LDle:I32(t10)
STle(0x081f4fe0) = t11
t12 = LDle:I32(0x081f4fe0)
