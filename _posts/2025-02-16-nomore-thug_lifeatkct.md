---
title: No More Thug Life in KCT – How We Busted a Fake Outlook Scam
date: 2025-02-16
categories: [Cybersecurity, Scams, Ethical Hacking]
tags: [Outlook, Scam, Cybersecurity, Forensics]
author: l4tmur
---

## No More Thug Life, Kid

After finding their system path, we decided to DM them—just to see their reaction. Of course, we took screenshots.

**What we told them:**  
"Nice try, kid. We respect the effort, but if you're gonna scam, at least do it right. This takes skill—something you clearly don’t have. Next time, don’t forget who’s watching."

~😘 Team NOVA (Real Thug)

![dm](/assets/images/dm.png)

**No more thug life at KCT, Mr. D(kid)**

Next time, scam properly.  
And clean up your code.

## Introduction

Some students dream of becoming ethical hackers. Others… well, they create fake Outlook apps to scam their way to get hostel outpasses. And then get caught because they left their home folder in the APK.

Note: The kid's name starts with D, so let's call him D****

Yes, this actually happened.

Our college cyber team, NOVA, recently uncovered a fake Outlook system designed to generate approval emails for hostel outpasses. The masterminds? A group of "developers" who thought they had pulled off the perfect scam—until we checked their `libapp.so` file and found their system path.

**Spoiler alert:** It even had their name in it.

## The Technical Breakdown – How We Found Them

When we first heard about this "fake" Outlook app, we got curious. If it could send official-looking outpass approvals, we knew something was shady. Time for some forensics.

### Step 1: Decompiling the APK with JADX-GUI

First things first, we decompiled the APK using **JADX-GUI** a tool that helps break down Android apps and analyze their source code.

**Why JADX?**
- It allows us to reverse-engineer APKs, extract important files, and inspect how an app functions.
- If there are hardcoded API keys, credentials, or sensitive file paths, we can see them.

### Step 2: Looking at `libapp.so` – Why This File?

In mobile forensics, we always check shared object files (.so) like `libapp.so`.

![jadx-ui](/assets/images/jadx-ui.png)

**Why?**
- These files contain compiled native code and can sometimes reveal sensitive paths, hardcoded strings, or debugging logs left by the developers.
- Many developers clean up their code before publishing, but these guys didn’t—which made our job easier.

### Step 3: The Smoking Gun – The File Path That Exposed Them

Buried inside `libapp.so`, we ran the following command to check for any juicy hardcoded secrets:

```bash
strings libapp.so | grep -iE 'password|passwd|file://|key|username|firebase|auth|token|apikey|secret|oauth|bearer|jwt|client_id|client_secret|access_token|refresh_token|ftp|sftp|admin|private|ssh|db_password|db_user|root|credentials|aws_access_key|aws_secret|google_api_key|facebook_app_id|twilio|slack_token|webhook|encryption|keystore|cert|certificate|proxy|debug|log'
```

And guess what? Jackpot.

They didn’t even clean up their build files properly, leaving traces of their system path right inside the compiled binary. That’s how we found:

![strings-result](/assets/images/strings-result.png)

📂 `/home/<d********>/Dev/thuglife/kumaraguru institutions/outlook/.dart_tool/flutter_build/dart_plugin_registrant.dart`

That’s right. Thug life ended in a single decompile.

**Their biggest mistakes?**
- They left their system username in the app.
- The project folder literally said "thuglife."
- The app was built under "kumaraguru institutions"—so even the college name was there.

They basically signed their own confession.

## Their Biggest Mistakes (A Free Cybersecurity Lesson)

Besides leaving a trail a toddler could follow, these guys made some classic rookie mistakes:

1. Leaving system paths in the APK – Congrats, you doxxed yourself.
2. Not securing their backend – If you’re gonna fake Outlook, at least do it right.
3. Thinking they wouldn’t get caught – Bro, some hackers are literally roaming around in our college. What did you expect?

## The Aftermath – The ₹5 Scam

At first, we thought, “Okay, just some students messing around.” But then we found out they used to charge for these fake outpasses. 💀

**₹5-7 per request**—seriously? They had a whole underground outpass black market running from their fake app.

And to top it off, instead of keeping quiet, they ran their mouths. So yeah, it was time for some fun.

