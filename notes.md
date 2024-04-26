We want to identify when we are
- REG -> MEM
- MEM -> REG
- (REG -> REG)

rax = read(0x100)
rbx = 1
rax = rbx
0x100 = write(rax)


i, j are counter
rax = addr + i
...
addr + j = rax

Every memory addr -> 1 node
Every register -> 1 node per REGISTER USE

for (int i = 0; i < 2; ++i)
   a[i] = i

load 0 into rax
store rax at a[0]
rax += 1
store rax at a[1]

reg -> a[0]1
reg -> a[1]1