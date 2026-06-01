# level01

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2001(level01) gid=2001(level01) groups=2001(level01),100(users)
```

**2. Where are we ?**
```sh
$ ls -laR
.:
total 12
dr-x------ 1 level01 level01  100 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level01 level01  220 Apr  3  2012 .bash_logout
-r-x------ 1 level01 level01 3518 Aug 30  2015 .bashrc
-r-x------ 1 level01 level01  675 Apr  3  2012 .profile
```

**3. My owned files**
```sh
$ find / \( -path /proc -o -path /usr -o -path /dev \) -prune -o -user $USER -print 2>/dev/null
# nothing
```

**4. Privileged account owned files** 👀
```sh
$ find / -user flag01 \( -perm -o=r -o -perm -o=w \) -print 2>/dev/null
# nothing
```

**5.1 User password files (shadow)**
```sh
$ ls -la /etc/shadow
-rw-r----- 1 root shadow 4428 Mar  6  2016 /etc/shadow
```

**5.2 User password files (passwd)** 👀
```sh
$ ls -la /etc/passwd
-rw-r--r-- 1 root root 2477 Mar  5  2016 /etc/passwd

$ grep flag01 /etc/passwd
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash
```

## Solution

#### Scanning step 5.2

On modern systems, hashes are stored in the `/etc/shadow` file and mapped to `/etc/passwd` files when the `x` character is used as specified [here](https://man7.org/linux/man-pages/man5/passwd.5.html). Some older systems would hash their passwords and store them directly in the `/etc/passwd` file. That would mean they are accessible and readable by anyone.
Here, `flag01`'s password hash is exposed. This behaviour is unusual and a sign of insecurity. We can try to dehash it.

As seen [here](https://man7.org/linux/man-pages/man8/pam_unix.8.html), the default encryption method for passwd is SHA512.  
But the hashed password is `42hDRfypTqqnw` and it doesn't match the expected format.
```sh
$ grep ENCRYPT_METHOD /etc/login.defs
# This variable is deprecated. You should use ENCRYPT_METHOD.
ENCRYPT_METHOD SHA512
# Only used if ENCRYPT_METHOD is set to SHA256 or SHA512.
```

First, we want to identify which hashing algorithm could have produced this value. For that, we use [hashcat](https://hashcat.net/hashcat/) with its `--identify` option.
```sh
$ docker run --interactive --tty --rm dizcza/docker-hashcat:pocl hashcat --identify "42hDRfypTqqnw"
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1500 | descrypt, DES (Unix), Traditional DES                      | Operating System
```

Hashcat identifies the algorithm as `Traditional DES` (cf. man 3 crypt).
From there, we can try to recover the password with strategies such as straight attacks, combinator attacks, mask attacks, or brute-force attacks, and any combination of these.

Since this is an exercise, and we may not have access to the GPU or its drivers at school, we choose to run the attack on the CPU and start with a well-known wordlist such as [rockyou.txt](https://weakpass.com/wordlists/rockyou.txt) that we downloaded and stored [here](./wordlists/rockyou.txt).
```sh
$ docker run --rm -it -v "./wordlists/rockyou.txt:/wordlist.txt:ro" -v "./out:/out:rw" dizcza/docker-hashcat:pocl hashcat --attack-mode 3 --hash-type 1500 "42hDRfypTqqnw" /wordlist.txt -o /out/cracked.txt
# This takes just 
```




On modern systems, hashes are stored in `/etc/shadow` and mapped to `/etc/passwd` such as specified [here](https://man7.org/linux/man-pages/man5/passwd.5.html). Older systems would hash their passwords and put them directly in the `/etc/passwd`.
Here, `flag01`'s password hash is exposed in a suspicious way. This needs deeper investigation (PS: We love that the hash starts with 42).

As seen [here](https://man7.org/linux/man-pages/man8/pam_unix.8.html), the default encryption method for passwd is SHA512.  
But the hashed password is `42hDRfypTqqnw` and it doesn't match the expected format.
```sh
$ grep ENCRYPT_METHOD /etc/login.defs
# This variable is deprecated. You should use ENCRYPT_METHOD.
ENCRYPT_METHOD SHA512
# Only used if ENCRYPT_METHOD is set to SHA256 or SHA512.
```

To identify in a quick fashion the present hashing algorythm we use [hashcat](https://hashcat.net/hashcat/) (in CPU mode to remain GPU driver agnostic) with the `--identify` flag on the host machine.
```sh
$ docker run --interactive --tty --rm dizcza/docker-hashcat:pocl hashcat --identify "42hDRfypTqqnw"
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1500 | descrypt, DES (Unix), Traditional DES                      | Operating System
```

We next use [hashcat](https://hashcat.net/hashcat/) to try to guess the password.
As we are in the context of an exercice we assume the password will be weak and available in public available wordlists such as [rockyou.txt](https://weakpass.com/wordlists/rockyou.txt).
For portability reasons we refuse to use the GPU (thing that would enforce installation of drivers) so we crack the password using our CPU.
```sh
$ docker run --rm -it -v "$(pwd)/wordlists/rockyou.txt:/wordlist.txt:ro" -v "$(pwd)/out:/out:rw" dizcza/docker-hashcat:pocl hashcat --attack-mode 3 --hash-type 1500 "42hDRfypTqqnw" /wordlist.txt -o /out/cracked.txt
# Cracks the password in ~2min.
$ cat ./out/cracked.txt | tail -n 1 | awk -F ':' '{print $NF}'
abcdefg
```

We then could access, using that password, the target `flag01` account and get the flag using the `getflag` command.
