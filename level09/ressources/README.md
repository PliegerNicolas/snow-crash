# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2009(level09) gid=2009(level09) groups=2009(level09),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 24
dr-x------ 1 level09 level09  140 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level09 level09  220 Apr  3  2012 .bash_logout
-r-x------ 1 level09 level09 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag09  level09 7640 Mar  5  2016 level09
-r-x------ 1 level09 level09  675 Apr  3  2012 .profile
----r--r-- 1 flag09  level09   26 Mar  5  2016 token
```

## Solution

We found two suspicious file:
- `/home/user/level09/level09` a binary with the setuid flag set.
- `/home/user/level09/token` a file would contain a sensible token. But it seems encoded or encrypted. 

### Privileges

We determined `/home/user/level09/level09` is a prime candidate for privilege escalation because:
- It is owned by `flag09` (our target).
- The group owner is `level09` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level09`, the privilege state is as follows:  
- Real UID: `level09`
- Real GUID: `level09`
- Effective UID: `flag09`
- Effective GUID: `level09`

### Script(s) behaviour(s)

The program takes a single argument and returns a deterministic result.  
The output exhibits a distinct pattern. Specifically, when provided wutg an alphabetically ordered string. It results in an output that shifts and scales in a consistent, predictable manner.

After a bit of reflection it seems to follow a pattern than can be mathematically described such as `x = c[i] + i` where c represents something such as a letter part of the ascii table.

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to disassemble and analyze it's content to an equivalent of **C** to understand it's behaviour. We added additionnal comments for additional information.
```c
size_t main(int param_1,int param_2)
{
  char cVar1;
  bool bVar2;
  long lVar3;
  size_t sVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int in_GS_OFFSET;
  byte bVar8;
  char *pcVar9;
  FILE *pFVar10;
  int iVar11;
  uint local_120;
  char local_114 [256];
  int local_14;
  
  bVar8 = 0;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  bVar2 = false;
  local_120 = 0xffffffff;
  iVar11 = 1;
  pFVar10 = (FILE *)0x0;
  // 1. Ensure the program is not traced.
  lVar3 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar3 < 0) {
    pcVar9 = "You should not reverse this";
    puts("You should not reverse this");
    sVar4 = 1;
  }
  else {
    // 2. Verify if LD_PRELOAD is undefined.
    pcVar9 = getenv("LD_PRELOAD");
    if (pcVar9 == (char *)0x0) {
      iVar11 = open("/etc/ld.so.preload",0);
      if (iVar11 < 1) {
        iVar5 = syscall_open();
        if (iVar5 == -1) {
          iVar11 = 0x46;
          pFVar10 = (FILE *)0x1;
          pcVar9 = "/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n";
          fwrite("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n",1,0x46,
                 stderr);
          sVar4 = 1;
        }
        else {
          do {
            do {
              while( true ) {
                pFVar10 = (FILE *)0x100;
                pcVar9 = local_114;
                iVar11 = iVar5;
                uVar7 = syscall_gets((int)pcVar9,0x100);
                sVar4 = 0;
                if (uVar7 == 0) goto LAB_08048a77;
                iVar6 = isLib(local_114,0x8048c2b);
                if (iVar6 == 0) break;
                bVar2 = true;
              }
            } while (!bVar2);
            iVar6 = isLib(local_114,0x8048c30);
            if (iVar6 != 0) {
              if (param_1 == 2) goto LAB_08048996;
              iVar11 = 0x22;
              pFVar10 = (FILE *)0x1;
              pcVar9 = "You need to provied only one arg.\n";
              sVar4 = fwrite("You need to provied only one arg.\n",1,0x22,stderr);
              goto LAB_08048a77;
            }
            pcVar9 = afterSubstr(local_114,0x8048c57);
          } while (pcVar9 != (char *)0x0);
          iVar11 = 0x30;
          pFVar10 = (FILE *)0x1;
          pcVar9 = "LD_PRELOAD detected through memory maps exit ..\n";
          sVar4 = fwrite("LD_PRELOAD detected through memory maps exit ..\n",1,0x30,stderr);
        }
      }
      else {
        iVar11 = 0x25;
        pFVar10 = (FILE *)0x1;
        pcVar9 = "Injection Linked lib detected exit..\n";
        fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
        sVar4 = 1;
      }
    }
    else {
      iVar11 = 0x25;
      pFVar10 = (FILE *)0x1;
      pcVar9 = "Injection Linked lib detected exit..\n";
      fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
      sVar4 = 1;
    }
  }
LAB_08048a77:
  if (local_14 == *(int *)(in_GS_OFFSET + 0x14)) {
    return sVar4;
  }
                    /* WARNING: Subroutine does not return */

  __stack_chk_fail(pcVar9,pFVar10,iVar11);
LAB_08048996:
  local_120 = local_120 + 1;
  uVar7 = 0xffffffff;
  pcVar9 = *(char **)(param_2 + 4);
  do {
    if (uVar7 == 0) break;
    uVar7 = uVar7 - 1;
    cVar1 = *pcVar9;
    pcVar9 = pcVar9 + (uint)bVar8 * -2 + 1;
  } while (cVar1 != '\0');
  if (~uVar7 - 1 <= local_120) goto code_r0x080489ca;
  putchar((int)*(char *)(local_120 + *(int *)(param_2 + 4)) + local_120);
  goto LAB_08048996;
code_r0x080489ca:
  pcVar9 = (char *)0xa;
  pFVar10 = stdout;
  sVar4 = fputc(10,stdout);
  goto LAB_08048a77;
}
```

The program seems heavily protected but relies on function calls whoes return values could be overwritten using debugging tools such as [GDB](https://sourceware.org/gdb/).
- It attempts to prevents the process from being traced by debugging tools such as GDB and ltrace.
- Il attempts to prevent injection of shared libraries by checking the absence of the `LD_PRELOAD` env var, the absence of `/etc/ld.so.preload` file and inspecting currently loaded libraries in memory through `/proc/self/maps`.
- It relies on common protection mechanisms introduced by traditionnal compilers such as stack canaries.

After all these checks it executes a loop that could be translated to something such as
```c
for (size_t i = 0; i < strlen(argv[1]); i++)
  putchar(argv[1][i] + i);
```

We decided to try to reverse engineer the encryption algorythm who seems rather simple.
```sh
char_to_decimal() {
    char="$1";

    case "$char" in
        ?)
            printf "%d" "'$char";
            ;;
        *)
            log "Error: char_to_decimal: invalid char value: $char" >&2;
            return 1;
            ;;
    esac
}

decimal_to_char() {
    decimal="$1";

    case "$decimal" in
        '' | *[!0-9]*)
            log "Error: decimal_to_char: invalid decimal value: $decimal" >&2;
            return 1;
            ;;
        *)
            printf "%b" "\\$(printf '%03o' "$decimal")";
            ;;
    esac
}

decode() {
    encoded_str="$1";
    decoded_str="";

    if [ -z "$encoded_str" ]; then
        log "Error: decode: missing encoded string" >&2;
        return 1;
    fi

    char_shift=0;
    while [ ! -z "$encoded_str" ]; do
        char="${encoded_str%${encoded_str#?}}"; # Get first char.
        encoded_str="${encoded_str#?}"; # Strip first char.

        decimal_char=$(char_to_decimal "$char");
        normalized_decimal_char=$(((decimal_char - char_shift % 128 + 128) % 128));
        shifted_char=$(decimal_to_char $normalized_decimal_char);

        decoded_str="${decoded_str}${shifted_char}";

        char_shift=$((char_shift + 1));
    done

    echo "$decoded_str";
}

decode "$encoded_str"
```

We got the token an can now login as `flag09` and get the flag.
