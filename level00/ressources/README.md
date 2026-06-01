# level00

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2000(level00) gid=2000(level00) groups=2000(level00),100(users)
```

**2. Where are we ?**
```sh
$ ls -laR
.:
total 12
dr-xr-x---+ 1 level00 level00  100 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-xr-x---+ 1 level00 level00  220 Apr  3  2012 .bash_logout
-r-xr-x---+ 1 level00 level00 3518 Aug 30  2015 .bashrc
-r-xr-x---+ 1 level00 level00  675 Apr  3  2012 .profile
```

**3. My owned files**
```sh
$ find / \( -path /proc -o -path /usr -o -path /dev \) -prune -o -user level00 -print 2>/dev/null
# nothing
```

**4. Privileged account owned files** 👀
```sh
$ find / -user flag00 \( -perm -o=r -o -perm -o=w \) -print 2>/dev/null
/usr/sbin/john
/rofs/usr/sbin/john
```

## Solution

#### Scanning step 4

We found a suspect file called `/usr/sbin/john` and it's counterpart `/rofs/usr/sbin/john` we'll ignore.
It contains encrypted text suspicious enough to look like a password.

We played around with it a bit and found out that using [this tool](https://www.dcode.fr/caesar-cipher) it was encrypted using Cesar's Cypher through an `alphabetic rot-15 right shift` and gave us the result `nottoohardhere`.

We then could access, using that password, the target `flag00` account and get the flag using the `getflag` command.
