---
title: No More Thug Life, Kid – How We Busted a Fake Outlook Scam
date: 2025-03-21
categories: [Cybersecurity, Scams, Ethical Hacking]
tags: [Outlook, Scam, Cybersecurity, Forensics]
author: l4tmur
image:
  path: /assets/images/thuglife-cover.png
---

Hey, you can check the screenshot of our DM with thug_lifeatkct to understand what went down and why we sent that message. Read the full blog to see how we tracked them down and exposed their game.

**What we told them:**  
![dm](/assets/images/dm.png)\
*"Nice try, kid. We respect the effort, but if you're gonna scam, at least do it right. This takes skill—something you clearly don't have. Next time, don't forget who's watching."*

~😘 Team NOVA 

---

## Introduction

Some students dream of becoming ethical hackers. Others… well, they create fake Outlook apps to scam their way into getting hostel outpasses even charging students for it and earning thousands per month. And then they get caught because they left their home folder in the APK.

*Note: The kid's name starts with D, so let's call him D*\*\*\* .

Yes, this actually happened.

**NOVA**, recently uncovered a fake Outlook system designed to generate approval emails for hostel outpasses. The masterminds? A group of "developers" who thought they had pulled off the perfect scam—until we checked their `libapp.so` file and found their system path.

**Spoiler alert:** It even had their name in it.

---

## The Technical Breakdown – How We Found Them

When we first heard about this "fake" Outlook app, we got curious. If it could send official-looking outpass approvals, we knew something was shady. Time for some forensics.

### Step 1: Decompiling the APK with JADX-GUI

First, we decompiled the APK using **JADX-GUI**, a tool that helps break down Android apps and analyze their source code.

#### **Why JADX?**

- It allows us to reverse-engineer APKs, extract important files, and inspect how an app functions.
- If there are hardcoded API keys, credentials, or sensitive file paths, we can see them.

### Step 2: Examining `libapp.so` – The Key to the Mystery  
![jadx-ui](/assets/images/jadx-ui.png)

In mobile forensics, `.so` (shared object) files are always worth checking. We focused on `libapp.so`.



#### **Why?**

- These files contain compiled native code and often reveal sensitive paths, hardcoded strings, or debugging logs left by developers.
- Many developers clean up their code before publishing, but these guys didn't—which made our job easier.

### Step 3: The Smoking Gun – The File Path That Exposed Them

We ran the following command to check for any hardcoded secrets:

```bash
strings libapp.so | grep -iE 'password|passwd|file://|key|username|firebase|auth|token|apikey|secret|oauth|bearer|jwt|client_id|client_secret|access_token|refresh_token|ftp|sftp|admin|private|ssh|db_password|db_user|root|credentials|aws_access_key|aws_secret|google_api_key|facebook_app_id|twilio|slack_token|webhook|encryption|keystore|cert|certificate|proxy|debug|log'
```

And guess what? Jackpot. They didn't even clean up their build files properly. We found this:  
![strings-result](/assets/images/strings-result.png)



📂 `/home/<d********>/Dev/thuglife/Redacted%20institutions/outlook/.dart_tool/flutter_build/dart_plugin_registrant.dart`

That's right. **Thug life ended in a single decompile.**

#### **Their biggest mistakes?**

- They left their **system username** in the app.
- The project folder literally said **"thuglife."**
- The app was built under **"Redacted institutions"**—so even the college name was there.

They basically signed their own confession.

---

## Their Biggest Mistakes (A Free Cybersecurity Lesson)

Besides leaving a trail a toddler could follow, these guys made some classic rookie mistakes:

1. **Leaving system paths in the APK** – Congrats, you doxxed yourself.
2. **Not securing their backend** – If you're gonna fake Outlook, at least do it right.
3. **Thinking they wouldn't get caught** – Bro, some hackers are literally roaming around our college. What did you expect?

---

## The Aftermath – The ₹7 Scam

At first, we thought, *“Okay, just some students messing around.”* But then we found out they were charging for these fake outpasses. 💀

**₹7 per request**—seriously? They had a whole underground outpass black market running from their fake app.

And to top it off, instead of keeping quiet, they ran their mouths. So yeah, it was time for some fun.

---

## Final Thoughts

This was a lesson in **why cybersecurity matters.** If you're building something shady, at least don't leave your name in it. More importantly, don't scam people at all—especially in a place full of hackers. 


---

### Want to reach out?

Curious about real cybersecurity? Connect with **l4tmur** on [LinkedIn](https://www.linkedin.com/in/0xl4tmur). No mentorship just lessons learned the hard way.

Better luck next time, D\*\*\*\*.
