# level01

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2002(level02) gid=2002(level02) groups=2002(level02),100(users)
```

**2. Where are we ?** 👀
```sh
.:
total 24
dr-x------ 1 level02 level02  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level02 level02  220 Apr  3  2012 .bash_logout
-r-x------ 1 level02 level02 3518 Aug 30  2015 .bashrc
----r--r-- 1 flag02  level02 8302 Aug 30  2015 level02.pcap
-r-x------ 1 level02 level02  675 Apr  3  2012 .profile
```

## Solution

#### Scanning step 2

Le fichier `$HOME/level02.pcap` est un binaire probablement généré via une application telque .
Une lecture de cette dernière laisse entrevoir des tentatives de connexion:
```
$ grep -a "wwwbugs login" $HOME/level02.pcap
wwwbugs login: @f&NV.B'̊$E4��@@J<;���;��ߙO/Y�t���
                                                �s�
wwwbugs login: df&N�%
                     B'̊$E4�@@J;���;��ߙO/Y�����L�sܽ
$ grep -a "Password" $HOME/level02.pcap
Password: Nf&NatB'̊$E4��@@J-;���;��ߙO/Y�{���%�s��
```