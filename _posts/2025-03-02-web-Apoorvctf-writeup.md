---
title: ApoorvCTF 2025 Writeup  
date: 2025-03-02  
categories: [CTF, Writeups, HTB]  
tags: [ctf, security, jwt, oidc, race-condition, api-exploitation, jwk-injection]  
description: A detailed walkthrough of the ApoorvCTF challenges, covering SEO flaws, OIDC misconfigurations, JWT manipulation, and API exploits.  
author: spidey  
---

# SEO CEO

They're optimizing SEO to show this garbage?!

> **Author:** _proximuz_

[https://seo-opal.vercel.app](https://seo-opal.vercel.app/)

## Understanding the Web’s Inner Workings

When I think of SEO, my mind immediately jumps to **robots.txt** after all, that’s where the secrets usually hide, right? And sure enough, it didn’t disappoint. A quick look revealed a **flake flag**, which was a solid start.

## Following the Digital Trail

Next, I turned my attention to **sitemap.xml**—because if you want to be discovered, you need a map. That’s when I stumbled upon an oddly named endpoint:

 **/goofyahhroute**

With a name like that, I knew something was up.

## The Mystery of the “Goofy Ahh Route”

Curious, I visited the page and was greeted with a cryptic message:

> "Tell it to the URL then, blud."

Blud? Alright, challenge accepted.

Thinking like a CTF player, I decided to "talk" to the URL. I added `**?flag=yes**` at the end of the address, hit enter, and just like that—the flag appeared:

 **apoorvctf{s30_1snT_0pt1onaL}**


# Blog 1: The Quest for the Ultimate Reward

In the vast digital realm, **Blog-1** awaited brave developers. The mission? Craft a captivating blog filled with enchanting posts, lively comments, and secure user authentication. But there was a catch—only one blog per day! The clock was ticking. Ready for the **Blog-1 adventure**?

> **Author:** _Rhul_

[https://chals1.apoorvctf.xyz:5001/](https://chals1.apoorvctf.xyz:5001/)

---

## **Understanding the Web’s Inner Workings**

Before diving into the challenge, let’s break down the **rules of the game**:

- There’s a **register** and **login** page. Simple enough.
- Once logged in, you can **post a blog**—but only **one per day** (talk about self-control).
- A **daily rewards** system exists, but there’s a twist: to claim your prize, you must **post five blogs**.
- Do you **wait five days** for the reward? Sure. But by then, the **CTF would be over**. 😭

Clearly, patience was _not_ an option.

---

## **Breaking the System with a Race Condition**

Like any good hacker, I smelled an exploit. **Race condition** came to mind, so I fired up **Burp Suite** faster than you can say "CTF." 🚀

### **The Plan:**

1. **Intercept** the blog post request.
2. **Send it to the Repeater** (because once is never enough).
3. **Fire off six identical requests simultaneously.**

### **The Execution:**

Boom! Here's what happened:

![Race Condition in Action](/assets/images/race.png)

After sending the requests in parallel…

![Success!](/assets/images/success.png)
🎉 **Did I get the reward?** Nope. Instead, I got **Skibidi Toilet!** 🚽🤣

But I wasn’t done yet.

---

## **API Version Downgrade for the Win**

While accessing the gift, I noticed this sneaky endpoint:

`http://chals1.apoorvctf.xyz:5001/api/v2/gift`

So, I did what any self-respecting CTF player would do—**downgraded the API version** to **v1**.

And just like that,  **FLAG SECURED!** 

 `apoorvctf{s1gm@_s1gm@_b0y}`

---



# Blog 2

After Blog-1's failure, Blud started making blog-2. This time with efficient and new Auth system based on OIDC. Little did bro know.... His Design was a DISASTER.
**authentication system**. Lil’ did bro know… 💀 **his design was more fragile than my GPA.**

> **Author:** _Rhul_

🔗 [Blog-2 Link](https://blog-2-omega.vercel.app/)

---

##  The Hint:

> "Bro was that dumb to validate ___ in j__..."

Hmmm, let’s play fill in the blanks. 🤔

- **Same functionality as Blog-1** but **now with "strong" OIDC auth** instead of that useless restriction system? 
- Ohhh, **OIDC?!** Bro, I literally wrote a blog about it during **NITECCTF 2024**.
- Let's check if `/.well-known/openid-configuration` exists! 

### Discovery Phase:

BOOM. Found this:



```
{"scopes_supported":["basic","sigma_viewer_blogs"],"id_token_signing_alg_values_supported":["HS256"]}
```

**HS256?** Bro signed his tokens with a symmetric key... we're SO back. 😂

- Exploring the functionality further, the **decoded JWT** looked like this:

```
{"iss":"OIDC","exp":1740930029,"userId":"67c47abe152b5cfebeb94221","username":"spidey@spidey.com","scope":"basic","iat":1740929729}
```



**Problem:** The scope is `basic`. 
**Goal:** Change it to `sigma_viewer_blogs` to unlock the goodies. 

---

##  The Breakthrough: JWK Header Injection

Remember the hint? Let’s complete it:

-  **JWK**  
-  **JWT**

This means one thing... **JWK header injection time!** 🎯

### **🎭 Forging the Magic Token** (Use JWT Editor tool)

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



---
