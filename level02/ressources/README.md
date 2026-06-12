# level02

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

The file `~/level02.pcap` is binary. It is probably generated through applications such as [wireshark](https://www.wireshark.org/).
The `.pcap` file format describes captured network traffic. It stands for `packet capture`.

The file can be copied locally doing something such as:
```sh
$ sshpass -p "$(cat ../../level01/flag)" scp -P 4242 level02@localhost:~/level02.pcap ./level02.pcap
```

When we try to read the file using an ASCII interpreter such as `cat` or `grep -a`, we see something noticable.
The presence of readable text confirms the packets were not encrypted.
```sh
$ grep -a "wwwbugs login" ./level02.pcap
wwwbugs login: @f&NV.B'̊$E4��@@J<;���;��ߙO/Y�t���
                                                �s�
wwwbugs login: df&N�%
                     B'̊$E4�@@J;���;��ߙO/Y�����L�sܽ
$ grep -a "Password" ./level02.pcap
Password: Nf&NatB'̊$E4��@@J-;���;��ߙO/Y�{���%�s��
```

We decide to use [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) to process the `.pcap` file further.
We first try to identify what kind of network it is. TCP is highly probable so we tried that first.
```sh
$ docker run --rm -v "./level02.pcap:/in.pcap:ro" parrotsec/tshark:latest -r "/in.pcap" -q -z conv,tcp
Running as user "root" and group "root". This could be dangerous.
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
59.233.235.218:39247       <-> 59.233.235.223:12121            43 3112 bytes      52 3646 bytes      95 6758 bytes     0.000000000        42.1102
================================================================================
```
This tells us:
- The traffic is confirmed as TCP.
- There was a 42s long session between `59.233.235.218:39247` and `59.233.235.223:12121`. This indicates interactive session login.
- We assume the stream id is 0 as there is only one "conversation".

Based on this we try to extract the TCP payloads and convert it to ASCII to retrieve the connexion attempt.
```sh
$ hex_tcp_traffic=$(docker run --rm -v "./level02.pcap:/in.pcap:ro" parrotsec/tshark:latest -r "/in.pcap" -Y "tcp.payload && tcp.stream==0" -T fields -e tcp.payload);
$ ascii_tcp_traffic=$(echo "$hex_tcp_traffic" | xxd -r -p);
$ echo "$ascii_tcp_traffic" | grep -a "Password: ";
Password: ft_wandrNDRelL0L
```

We then could access, using that password, the target `flag01` account and get the flag using the `getflag` command.
