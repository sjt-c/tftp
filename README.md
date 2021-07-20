# RFC1350 tftp server and client

This was built on FreeBSD.  It has also been tested on Debian.

IPv4 and IPv6 are supported.

## Building

FreeBSD
---

	% make
	
Linux
---

To build on linux will require the BSD make tool.  This can normally be found in the **bmake** package for your distribution.

	$ bmake
	
Build Options
---

Two options can be passed to the makefile:

- -DDEBUG : Produce more verbose output during execution of both the server and client.
- SERVER_PORT=*port#* : Override the default tftp port (69).

Output
---

Two binaries are produced in the same diretory as the makefile:

- **tftpd** The tftp server
- **tftp** The tftp client

Cleaning
---

There is a **clean** target in the *makefile* for removing the binaries and object files.

## Executing

tftpd
---

These are the command line options available for the server:

- -p *port#* : An alternative port number to the one built with.
- -T : Redirect output to **stdout**
- -D : Daemonize the server
- -C : Path the daemonized server will chroot into

If **-D** is specified, **-C** must also be specified.

tftp
---

The command line for the client follows a specified format:

tftp *server_ip* [*port#*] *command* *file*

- *server_ip* is the address of the tftp server
- *port#* is an optional port number
- *command* is either **GET** or **PUT** (case insensitive)
- *file* is the name of the file to send or receive

## Notes

Only mode **octet** is supported by the server and client.  An error will be returned by the server if anything else is requested.

Logging defaults to syslog unless **-T** is specified.

Link-local addresses are ignored by the server when creating sockets.

tftpd only has access to the directory it is executed from.  Paths are stripped from the file name by the server.

As this is an RFC1350 implementation the maximum file size is 33553919 bytes. ((2^16 - 1) * 512) - 1.
