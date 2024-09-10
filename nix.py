from pwn import *

binary = args.BIN

e = context.binary = ELF(binary)
r = ROP(e)

#p = process("./chal")
p = remote("nix.ctf.csaw.io", 1000)

## decompiler output ##
# read(unicode_input_sum + -0x643,buf,0x20);
# cmp = strcmp("make every program a filter\n",buf);
##

# want to read from stdin (0) and then send value of buf
# so have to make unicode_input_sum + -0x643 = 0
# 0x643 -> 1603

# 12 ~ 1512
# 1 [ 91
# another ~ because it doesnt read the first char for some reason

payload = b'~~~~~~~~~~~~~['

p.sendlineafter(b': ', payload)

p.sendline(b'make every program a filter')

p.interactive()
