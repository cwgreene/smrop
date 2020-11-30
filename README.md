# Smooth ROPerator
Smooth ROPerator is a tool that makes it easier for
me to build ropchains. There are a number of solutions
for this (and `ROPgadget` itself has some support for this)
as well as `angrop` and `ropalyzer`. This tool really
doesn't bring much more to the table beyond providing
a specific interface that I want for a different project.

# Installation Instructions

```
pip install git+git://github.com/cwgreene/smrop.git
```

# Example Usage
```
from pwn import *
import smrop

r = process("./test")

bin = ELF("./binary")
libc = ELF("./libc.so.6")

sm = smrop.Smrop(binary=bin, libc=libc)

# calls to ret ensure that the stack
# is properly 16 byte aligned
payload = sm.prefix(b"A"*16)
            .pop_rdi(bin.bss()) # will search for appropriate ROP
            .ret("gets")

# program returns location of main and gets
binary_location = int(r.recvline(),16) - bin.symbols["main"]
libc_location = int(r.recvline(),16) - libc.symbols["gets"]

# throws an exception if ROP cannot be easily satisfied.
payload_bytes = payload.resolve(binary=binary_location, libc=libc_location)
r.send(payload_bytes)
```
