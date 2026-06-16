# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2010(level10) gid=2010(level10) groups=2010(level10),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 28
dr-xr-x---+ 1 level10 level10   140 Mar  6  2016 .
d--x--x--x  1 root    users     340 Aug 30  2015 ..
-r-x------  1 level10 level10   220 Apr  3  2012 .bash_logout
-r-x------  1 level10 level10  3518 Aug 30  2015 .bashrc
-rwsr-sr-x+ 1 flag10  level10 10817 Mar  5  2016 level10
-r-x------  1 level10 level10   675 Apr  3  2012 .profile
-rw-------  1 flag10  flag10     26 Mar  5  2016 token
```

## Solution

We found two suspicious file:
- `/home/user/level10/level10` a binary with the setuid flag set.
- `/home/user/level10/token` a file would contain a sensible token. But it seems encoded or encrypted. 

### Privileges

We determined `/home/user/level10/level10` is a prime candidate for privilege escalation because:
- It is owned by `flag10` (our target).
- The group owner is `level10` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level10`, the privilege state is as follows:  
- Real UID: `level10`
- Real GUID: `level10`
- Effective UID: `flag10`
- Effective GUID: `level10`

```sh
$ getfacl ./level10 
# file: level10
# owner: flag10
# group: level10
# flags: ss-
user::rwx
group::---
group:level10:r-x
group:flag10:r-x
mask::r-x
other::r-x
```

`/home/user/level10/token` is only readable and writable by `flag10` so it would force us to use it's effective permissions.

### Script(s) behaviour(s)

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to disassemble and analyze it's content to an equivalent of **C** to understand it's behaviour. We added additionnal comments for additional information.
```c
int main(int argc,char **argv)
{
  char *param1;
  uint16_t uVar1;
  int iVar2;
  int iVar3;
  ssize_t sVar4;
  size_t __n;
  int *piVar5;
  char *pcVar6;
  int in_GS_OFFSET;
  undefined1 local_1024 [4096];
  sockaddr local_24;
  int local_14;
  
                    /* Unresolved local var: char * file@[DW_OP_breg4(ESP): +40]
                       Unresolved local var: char * host@[DW_OP_breg4(ESP): +44] */
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  // 1. Enforce the presence of 2 additional arguments.
  if (argc < 3) {
    printf("%s file host\n\tsends file to host if you have access to it\n",*argv);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pcVar6 = argv[1];
  param1 = argv[2];
  // 2. Verifies if the REAL USER (RUID) can read the file path name.
  iVar2 = access(argv[1],4);
  if (iVar2 == 0) {

                    /* Unresolved local var: int fd@[DW_OP_breg4(ESP): +48]
                       Unresolved local var: int ffd@[DW_OP_breg4(ESP): +52]
                       Unresolved local var: int rc@[DW_OP_breg4(ESP): +56]
                       Unresolved local var: sockaddr_in sin@[DW_OP_breg4(ESP): +4156]
                       Unresolved local var: char[4096] buffer@[DW_OP_breg4(ESP): +60] */

    // 3. Prepare a TCP connection to argv[2]:6969.
    printf("Connecting to %s:6969 .. ",param1);
    fflush(stdout);
    iVar2 = socket(2,1,0);
    local_24.sa_data[2] = '\0';
    local_24.sa_data[3] = '\0';
    local_24.sa_data[4] = '\0';
    local_24.sa_data[5] = '\0';
    local_24.sa_data[6] = '\0';
    local_24.sa_data[7] = '\0';
    local_24.sa_data[8] = '\0';
    local_24.sa_data[9] = '\0';
    local_24.sa_data[10] = '\0';
    local_24.sa_data[0xb] = '\0';
    local_24.sa_data[0xc] = '\0';
    local_24.sa_data[0xd] = '\0';
    local_24.sa_family = 2;
    local_24.sa_data[0] = '\0';
    local_24.sa_data[1] = '\0';
    local_24.sa_data._2_4_ = inet_addr(param1);
    uVar1 = htons(0x1b39);
    local_24.sa_data[0] = (char)uVar1;
    local_24.sa_data[1] = (char)(uVar1 >> 8);
    iVar3 = connect(iVar2,&local_24,0x10);
    if (iVar3 == -1) {
      printf("Unable to connect to host %s\n",param1);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }

    // 4. Send Protocol Banner: Sends a generic handshake string to the listener.
    sVar4 = write(iVar2,".*( )*.\n",8);
    if (sVar4 == -1) {
      printf("Unable to write banner to host %s\n",param1);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    printf("Connected!\nSending file .. ");
    fflush(stdout);
    // 5. Open the file using EUID to open the provided file.
    iVar3 = open(pcVar6,0);
    if (iVar3 == -1) {
      puts("Damn. Unable to open file");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }

    // 6. Read up to 4096 bytes from the file (to prevent buffer overflows) and transmit over socket.
    __n = read(iVar3,local_1024,0x1000);
    if (__n == 0xffffffff) {
      piVar5 = __errno_location();
      pcVar6 = strerror(*piVar5);
      printf("Unable to read from file: %s\n",pcVar6);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    write(iVar2,local_1024,__n);
    iVar2 = puts("wrote file!");
  }
  else {
    iVar2 = printf("You don\'t have access to %s\n",pcVar6);
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar2;
}
```

