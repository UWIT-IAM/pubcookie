#defaults
#
# $Id: Makefile,v 1.1 1998-02-14 08:24:41 willey Exp $
#

CC=gcc
CFLAGS=-Wall -I/usr/local/ssl/include
LDFLAGS=-L/usr/local/ssl/lib -lcrypto

all:	create verify

create:		create.o base64.o
		$(CC) -o $@ create.o base64.o $(LDFLAGS)

verify:		verify.o base64.o
		$(CC) -o $@ verify.o base64.o $(LDFLAGS)

create.o: create.c
verify.o: verify.c
base64.o: base64.c

clean:
	rm -f *.o *~ core

realclean: 
	rm -f *.o *~ core create
