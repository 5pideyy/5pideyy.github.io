---
title: Manipulating OAuth Scopes in Oogle and Ooguth, A niteCCTF 2024 Web Exploit
date: 2024-12-17
categories: [CTF, Writeups]
tags: [oauth,oauth, jwt, security, nitectf, challenge, scope-manipulation]
author: spideyy
description: A deep dive into the OAuth and JWT manipulation techniques used in the Oogle and Ooguth CTF challenge, and how scope tampering can lead to uncovering hidden flags.
---


#### **Challenge Description**

![Challenge description](/assets/images/Pasted%20image%2020241217120045.png)

In this challenge, OAuth and JWTs are put to the test, and with a little scope manipulation, we can uncover a hidden flag. Strap in as we break down this CTF, filled with OAuth flows, JWT tampering, and some strategic exploration.

### **The Setup:**

We are given the following URL:  
`http://yankdeal.ooguth.chalz.nitectf2024.live/`

Upon visiting the site, we are greeted with an invitation to **login with Oogle**. A bit of a cheeky twist on Google, right?



Clicking the **Login with Oogle** button redirects us to another page hosted at:  
`oogle.ooguth.chalz.nitectf2024.live/login`

Here, we’re asked to complete the login process, after which we’re redirected back to the original site via the callback URL: `http://yankdeal.ooguth.chalz.nitectf2024.live/callback`

#### ** Oogle OAuth Page**

![oogle Login](/assets/images/Pasted%20image%2020241217120440.png)

### **What Did We Learn?**

Upon registering, I noticed the **scope** parameter was set to `profile`:


```
POST /login?redirectTo=http://yankdeal.ooguth.chalz.nitectf2024.live/callback&scope=profile HTTP/2
```

#### **What Exactly is "Scope" in OAuth?**

**Scope** is a key concept in OAuth 2.0. It defines the level of access the application has to the user's data. In this case, the `profile` scope limits access to basic user information. Simple, right?

> "Scope is a mechanism in OAuth 2.0 to limit an application's access to a user's account."  
> – [OAuth 2.0 Docs](https://oauth.net/2/scope/)

The app is requesting the `profile` scope when we log in. Not surprising — it’s the most common scope for basic information.

### **Digging Deeper:**

After logging in with Oogle, I was able to **add items to the cart**, **view the cart**, and **log out**. But when I tried accessing the `/profile` endpoint, I was greeted with a **404: Not Found** error. Hmm, something fishy here.

Three cookies were set: `tokenC`, `session`, and `token`.

By decoding the JWT in the `token` cookie, I realized the **scope** was also embedded in the token itself. This was a big clue — I could change the scope to gain more access.

### **Finding Available Scopes:**

Now that I understood I needed to manipulate the scope, I **googled** how to find available scopes in OAuth. I stumbled upon two standard endpoints that often hold the key to this treasure trove:

- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`

And where did I learn this secret? From a **gold mine for web exploiters**:  
[PortSwigger’s OAuth guide](https://portswigger.net/web-security/oauth).

With this knowledge, I uncovered a list of juicy scopes that could potentially unlock hidden parts of the app.

![/.well-known/openid-configuration got scopes](/assets/images/Pasted%20image%2020241217123951.png)

### **Time for Scope Tampering:**

I realized the scope was embedded in the JWT, but without the secret key, I tried brute-forcing it with the **rockyou** wordlist — no luck there. So, I decided to **tamper with the scope directly**.

I modified the scope parameter during registration and login, setting **every possible scope** I could find. After all, why settle for one scope when you can have them all?

![Setting every scopes](/assets/images/Pasted%20image%2020241217124407.png)

Success! The JWT now contained all the scopes I needed.

![Decoded JWT](/assets/images/Pasted%20image%2020241217124556.png)

### **Now, Where’s the Flag?**

With all scopes set, I started exploring the app’s endpoints. I accessed `/payment_details`, and voila! The **flag** was revealed:



```
Flag: nite{y0u_c4nt_h4ck_wh47_y0u_c4n7_f1nd_5550-1309-6672-6224}
```

---

### **Takeaways:**

- **OAuth** scopes can limit what data an app can access — but they can also be manipulated.
- **JWT tampering** can help you bypass certain restrictions when done carefully.
- A little bit of exploration and **scope experimentation** goes a long way.

Until next time, happy hacking! 👾  

