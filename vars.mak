DEPS_MAK	= "deps.mak"

.SUFFIXES	= .c .o

SRCS	!= ls *.c
#LIB	= -L../lib
#INC	= -I../include
#LIBS	=

INC		= -I.
LIB		=
LIBS	=

UNAME	!= which uname
OS		!= $$(which uname) -s | tr "[:lower:]" "[:upper:]"

MAKE	!= which make

.if $(OS) == "FREEBSD"
CC		!= which clang
.else
CC		!= which gcc
MAKE	!= which bmake
.endif

CFLAGS	= -std=c90 -O2 -Wall $(INC) -DOS=$(OS)
LDFLAGS	= $(LIB) $(LIBS)

.ifdef (DEBUG)
CFLAGS	+= -DDEBUG
.endif

.ifdef (SERVER_PORT)
CFLAGS	+= -DSERVER_PORT=\"$(SERVER_PORT)\"
.endif
