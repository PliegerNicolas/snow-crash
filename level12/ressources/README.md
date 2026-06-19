# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2012(level12) gid=2012(level12) groups=2012(level12),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 16
dr-xr-x---+ 1 level12 level12  120 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level12 level12  220 Apr  3  2012 .bash_logout
-r-x------  1 level12 level12 3518 Aug 30  2015 .bashrc
-rwsr-sr-x+ 1 flag12  level12  464 Mar  5  2016 level12.pl
-r-x------  1 level12 level12  675 Apr  3  2012 .profile
```

## Solution

We found a suspicious file: `/home/user/level12/level12.pl`.

### Privileges

```sh
$ getfacl ./level12.pl 
# file: level12.pl
# owner: flag12
# group: level12
# flags: ss-
user::rwx
group::r-x
group:flag12:rwx		#effective:r-x
mask::r-x
other::r-x
```

We determined `/home/user/level12/level12.pl` is a prime candidate for privilege escalation because:
- It is owned by `flag12` (our target).
- The group owner is `level12` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level12`, the privilege state is as follows:  
- Real UID: `level12`
- Real GUID: `level12`
- Effective UID: `flag12`
- Effective GUID: `level12`

### Script behaviour(s)

`/home/user/level12/level12.pl` is a [perl](https://www.perl.org/) script.
As it is an interpreted language it can be read as is.
```pl
#!/usr/bin/env perl
# localhost:4646
use CGI qw{param};
print "Content-type: text/html\n\n";

sub t {
  $nn = $_[1];
  $xx = $_[0];
  $xx =~ tr/a-z/A-Z/; 
  $xx =~ s/\s.*//;
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }    
}

n(t(param("x"), param("y")));
```

### Vulnerability
