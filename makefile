.include "vars.mak"

#
# make [-DDEBUG] [SERVER_PORT=<port#>]
# make clean
#

SRVOBJ	= server.o tftp.o auxmath.o auxnet.o
CLNTOBJ	= client.o tftp.o auxmath.o auxnet.o

.ifdef (DEBUG)
SRVOBJ	+= iso_iec_646.o byte.o
CLNTOBJ	+= iso_iec_646.o byte.o
.endif

.MAIN: .depend tftpd tftp

.depend:
	$(MAKE) -f $(DEPS_MAK)

tftpd: $(SRVOBJ)
	$(CC) -o $(.TARGET) $(LDFLAGS) $(.ALLSRC)

tftp: $(CLNTOBJ)
	$(CC) -o $(.TARGET) $(LDFLAGS) $(.ALLSRC)

.c.o:
	$(CC) $(CFLAGS) -c $(.IMPSRC)

clean:
	rm -f .depend *.core *.o tftpd tftp
