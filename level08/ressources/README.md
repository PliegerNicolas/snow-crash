# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2008(level08) gid=2008(level08) groups=2008(level08),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 28
dr-xr-x---+ 1 level08 level08  140 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level08 level08  220 Apr  3  2012 .bash_logout
-r-x------  1 level08 level08 3518 Aug 30  2015 .bashrc
-rwsr-s---+ 1 flag08  level08 8617 Mar  5  2016 level08
-r-x------  1 level08 level08  675 Apr  3  2012 .profile
-rw-------  1 flag08  flag08    26 Mar  5  2016 token
```

## Solution

We found two suspicious file:
- `/home/user/level08/level08` a binary with the setuid flag set.
It is a binary file.
