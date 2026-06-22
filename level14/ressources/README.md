# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2014(level14) gid=2014(level14) groups=2014(level14),100(users)
```

**2. Where are we ?**
```sh
$ ls -laR
.:
total 12
dr-x------ 1 level14 level14  100 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level14 level14  220 Apr  3  2012 .bash_logout
-r-x------ 1 level14 level14 3518 Aug 30  2015 .bashrc
-r-x------ 1 level14 level14  675 Apr  3  2012 .profile
```

**3. My owned files**
```sh
$ find / \( -path /proc -o -path /usr -o -path /dev \) -prune -o -user $USER -print 2>/dev/null
# nothing
```

**4. Privileged account owned files**
```sh
$ find / -user flag14 \( -perm -o=r -o -perm -o=w \) -print 2>/dev/null
# nothing
```

**5.1. User password files (shadow)**
```sh
$ ls -la /etc/shadow
-rw-r----- 1 root shadow 4428 Mar  6  2016 /etc/shadow
```

**5.2. User password files (passwd)**
```sh
$ ls -la /etc/passwd
-rw-r--r-- 1 root root 2477 Mar  5  2016 /etc/passwd
$ grep flag14 /etc/passwd
# Nothing suspect
```

**6. Running processes**
```sh
level14@SnowCrash:~$ pgrep -u flag14
# Nothing
level14@SnowCrash:~$ pgrep -U flag14
# Nothing
```

**7. Environment variables**
```sh
$ env
TERM=xterm-256color
SHELL=/bin/bash
SSH_CLIENT=10.0.2.2 38964 4242
SSH_TTY=/dev/pts/0
USER=level14
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
MAIL=/var/mail/level14
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
PWD=/home/user/level14
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/user/level14
LOGNAME=level14
SSH_CONNECTION=10.0.2.2 38964 10.0.2.15 4242
LESSOPEN=| /usr/bin/lesspipe %s
LESSCLOSE=/usr/bin/lesspipe %s %s
OLDPWD=/home/user/level14
_=/usr/bin/env
```

**8. Cron** 

```sh
$ crontab -l
no crontab for level14
$ cat /etc/crontab
# Standard output.
$ ls /etc/cron.*
# Standard output.
```

## Solution

We didn't find any suspect files with traditional methods.  
We started wondering where the tokens that `/bin/getflag` provide are stored and how they are hashed/encrypted.  

We decided to use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to deassemble and analyze it's content to an equivalent of **C** and understand it's behaviour.
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

undefined4 main(void) {
  bool bVar1;
  long lVar2;
  undefined4 uVar3;
  int iVar4;
  __uid_t _Var5;
  uint uVar6;
  int in_GS_OFFSET;
  char *pcVar7;
  FILE *pFVar8;
  int iVar9;
  char local_114 [256];
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  bVar1 = false;
  iVar9 = 1;
  pFVar8 = (FILE *)0x0;
  lVar2 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar2 < 0) {
    pcVar7 = "You should not reverse this";
    puts("You should not reverse this");
    uVar3 = 1;
  }
  else {
    pcVar7 = getenv("LD_PRELOAD");
    if (pcVar7 == (char *)0x0) {
      iVar9 = open("/etc/ld.so.preload",0);
      if (iVar9 < 1) {
        iVar4 = syscall_open();
        if (iVar4 == -1) {
          iVar9 = 0x46;
          pFVar8 = (FILE *)0x1;
          pcVar7 = "/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n";
          fwrite("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n",1,0x46,
                 stderr);
          uVar3 = 1;
        }
        else {
          do {
            do {
              while( true ) {
                pFVar8 = (FILE *)0x100;
                pcVar7 = local_114;
                iVar9 = iVar4;
                uVar6 = syscall_gets((int)pcVar7,0x100);
                if (uVar6 == 0) goto LAB_08048ead;
                iVar9 = isLib(local_114,0x8049063);
                if (iVar9 == 0) break;
                bVar1 = true;
              }
            } while (!bVar1);
            iVar9 = isLib(local_114,0x8049068);
            if (iVar9 != 0) {
              iVar9 = 0x20;
              fwrite("Check flag.Here is your token : ",1,0x20,stdout);
              _Var5 = getuid();
              pFVar8 = stdout;
              if (_Var5 == 0xbbe) {
                pcVar7 = ft_des("H8B8h_20B4J43><8>\\ED<;j@3");
                fputs(pcVar7,pFVar8);
              }
              else if (_Var5 < 0xbbf) {
                if (_Var5 == 0xbba) {
                  pcVar7 = ft_des("<>B16\\AD<C6,G_<1>^7ci>l4B");
                  fputs(pcVar7,pFVar8);
                }
                else if (_Var5 < 0xbbb) {
                  if (_Var5 == 3000) {
                    pcVar7 = ft_des("I`fA>_88eEd:=`85h0D8HE>,D");
                    fputs(pcVar7,pFVar8);
                  }
                  else if (_Var5 < 0xbb9) {
                    if (_Var5 == 0) {
                      iVar9 = 0x21;
                      fwrite("You are root are you that dumb ?\n",1,0x21,stdout);
                    }
                    else {
LAB_08048e06:
                      iVar9 = 0x38;
                      fwrite("\nNope there is no token here for you sorry. Try again :)",1,0x38,
                             stdout);
                    }
                  }
                  else {
                    pcVar7 = ft_des("7`4Ci4=^d=J,?>i;6,7d416,7");
                    fputs(pcVar7,pFVar8);
                  }
                }
                else if (_Var5 == 0xbbc) {
                  pcVar7 = ft_des("?4d@:,C>8C60G>8:h:Gb4?l,A");
                  fputs(pcVar7,pFVar8);
                }
                else if (_Var5 < 0xbbd) {
                  pcVar7 = ft_des("B8b:6,3fj7:,;bh>D@>8i:6@D");
                  fputs(pcVar7,pFVar8);
                }
                else {
                  pcVar7 = ft_des("G8H.6,=4k5J0<cd/D@>>B:>:4");
                  fputs(pcVar7,pFVar8);
                }
              }
              else if (_Var5 == 0xbc2) {
                pcVar7 = ft_des("74H9D^3ed7k05445J0E4e;Da4");
                fputs(pcVar7,pFVar8);
              }
              else if (_Var5 < 0xbc3) {
                if (_Var5 == 0xbc0) {
                  pcVar7 = ft_des("bci`mC{)jxkn<\"uD~6%g7FK`7");
                  fputs(pcVar7,pFVar8);
                }
                else if (_Var5 < 0xbc1) {
                  pcVar7 = ft_des("78H:J4<4<9i_I4k0J^5>B1j`9");
                  fputs(pcVar7,pFVar8);
                }
                else {
                  pcVar7 = ft_des("Dc6m~;}f8Cj#xFkel;#&ycfbK");
                  fputs(pcVar7,pFVar8);
                }
              }
              else if (_Var5 == 0xbc4) {
                pcVar7 = ft_des("8_Dw\"4#?+3i]q&;p6 gtw88EC");
                fputs(pcVar7,pFVar8);
              }
              else if (_Var5 < 0xbc4) {
                pcVar7 = ft_des("70hCi,E44Df[A4B/J@3f<=:`D");
                fputs(pcVar7,pFVar8);
              }
              else if (_Var5 == 0xbc5) {
                pcVar7 = ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I");
                fputs(pcVar7,pFVar8);
              }
              else {
                if (_Var5 != 0xbc6) goto LAB_08048e06;
                pcVar7 = ft_des("g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|");
                fputs(pcVar7,pFVar8);
              }
              pcVar7 = (char *)0xa;
              pFVar8 = stdout;
              fputc(10,stdout);
              goto LAB_08048ead;
            }
            pcVar7 = afterSubstr(local_114,0x8049281);
          } while (pcVar7 != (char *)0x0);
          iVar9 = 0x30;
          pFVar8 = (FILE *)0x1;
          pcVar7 = "LD_PRELOAD detected through memory maps exit ..\n";
          fwrite("LD_PRELOAD detected through memory maps exit ..\n",1,0x30,stderr);
LAB_08048ead:
          uVar3 = 0;
        }
      }
      else {
        iVar9 = 0x25;
        pFVar8 = (FILE *)0x1;
        pcVar7 = "Injection Linked lib detected exit..\n";
        fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
        uVar3 = 1;
      }
    }
    else {
      iVar9 = 0x25;
      pFVar8 = (FILE *)0x1;
      pcVar7 = "Injection Linked lib detected exit..\n";
      fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
      uVar3 = 1;
    }
  }
  if (local_14 == *(int *)(in_GS_OFFSET + 0x14)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(pcVar7,pFVar8,iVar9);
}
```

We tried to translate this output to something more readable.
```c
char * ft_des(char *encoded_str) {

}

int main(void) {
  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
    puts("You should not reverse this");
    return 1;
  }

  if (getenv("LD_PRELOAD") != NULL) {
    fprintf(stderr, "Injection Linked lib detected exit..\n");
    return 1;
  }

  if ((int fd = open("/etc/ld.so.preload", O_RDONLY)) >= 0) {
    fprintf(stderr, "Injection Linked lib detected exit..\n");
    close(fd);
    return 1;
  }

  int   maps_fd = open("/proc/self/maps", O_RDONLY);
  bool  blacklisted_library_found = false;
  if (maps_fd == -1) {
    fprintf(stderr, "/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n");
    return 1;
  }
  // Loop that verifies if /proc/self/maps contains blacklisted libraries.
  close(maps_fd);

  if (blacklisted_library_found) {
    fprintf(stderr, "LD_PRELOAD detected through memory maps exit ..\n");
    return 1;
  }

  uid_t uid = getuid();
  printf("Check flag.Here is your token : ");

  switch (uid) {
    case 0: puts("You are root are you that dumb ?\n"); break;
    // case XXXX: puts(ft_des(HASH)); break;
    default: puts("\nNope there is no token here for you sorry. Try again :)"); break;
  }

  return 0;
}
```

### Vulnerability

Even though the script seems heavily protected. No kernel-side checks are needed and it all rely on function return values.
Using debugging tools such as [gdb](https://sourceware.org/gdb/), we can:
- We can alter the return values of the protective functions (`ptrace()`, getenv(`LD_PRELOAD`), ...).
- We can alter the value of the current uid to one of the hardecoded recognized values.
We could also attempt to:
- Reverse-engineer the `ft_des()` function and apply it on the hardcoded encrypted strings.

When running the script with [gdb](https://sourceware.org/gdb/), the only protection we trigger is `ptrace()`.  
But as it is a runtime check, we can modify its return value using our debugging tool. In other workds, check is **superficial**.

```sh
$ cat << 'EOF' > /tmp/exploit.gdb
set confirm off
set pagination off
set print elements 0

define goto
    tbreak $arg0
    continue
end
define goto_exec
    goto $arg0
    finish
end
define goto_exec_assign
    goto_exec $arg0
    nexti
end

file /bin/getflag
start
goto_exec ptrace
set $eax = 0
goto_exec getuid
set $eax = 3014

continue
quit

$ gdb -x /tmp/exploit.gdb
```

And there is the flag !
