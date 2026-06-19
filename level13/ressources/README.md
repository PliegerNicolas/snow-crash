# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2013(level13) gid=2013(level13) groups=2013(level13),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 20
dr-x------ 1 level13 level13  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level13 level13  220 Apr  3  2012 .bash_logout
-r-x------ 1 level13 level13 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag13  level13 7303 Aug 30  2015 level13
-r-x------ 1 level13 level13  675 Apr  3  2012 .profile
```

## Solution

We found a suspicious binary file: `/home/user/level13/level13`.

### Privileges

We determined `/home/user/level13/level13` is a prime candidate for privilege escalation because:
- It is owned by `flag13` (our target).
- The group owner is `level13` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level13`, the privilege state is as follows:  
- Real UID: `level13`
- Real GUID: `level13`
- Effective UID: `flag13`
- Effective GUID: `level13`

### Script(s) behaviour(s)

**`/home/user/level13/level13`**:  

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to deassemble and analyze it's content to an equivalent of **C** to understand it's behaviour.
```c
char * ft_des(char *param_1) {
  char cVar1;
  char *pcVar2;
  uint uVar3;
  char *pcVar4;
  byte bVar5;
  uint local_20;
  int local_1c;
  int local_18;
  int local_14;
  
  bVar5 = 0;
  pcVar2 = strdup(param_1);
  local_1c = 0;
  local_20 = 0;
  do {
    uVar3 = 0xffffffff;
    pcVar4 = pcVar2;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar3 - 1 <= local_20) {
      return pcVar2;
    }
    if (local_1c == 6) {
      local_1c = 0;
    }
    if ((local_20 & 1) == 0) {
      if ((local_20 & 1) == 0) {
        for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14 = local_14 + 1) {
          pcVar2[local_20] = pcVar2[local_20] + -1;
          if (pcVar2[local_20] == '\x1f') {
            pcVar2[local_20] = '~';
          }
        }
      }
    }
    else {
      for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18 = local_18 + 1) {
        pcVar2[local_20] = pcVar2[local_20] + '\x01';
        if (pcVar2[local_20] == '\x7f') {
          pcVar2[local_20] = ' ';
        }
      }
    }
    local_20 = local_20 + 1;
    local_1c = local_1c + 1;
  } while( true );
}

void main(void) {
  __uid_t _Var1;
  char *param1;
  
  _Var1 = getuid();
  if (_Var1 != 0x1092) {
    _Var1 = getuid();
    printf("UID %d started us but we we expect %d\n",_Var1,0x1092);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  param1 = ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I");
  printf("your token is %s\n",param1);
  return;
}
```

The script seems to:
1. Verify if the current **RUID** is 4242.
2. If it is, run `ft_des()` to decrypt a specific embedded string.
3. Print the resulting token.

### Vulnerability

Contrary to what we noticed in [level09](../../level09/ressources//README.md)