#defaults
#
# $Id: Makefile,v 1.2 1998-06-25 03:00:58 willey Exp $
#

CC=gcc
CFLAGS=-g -Wall -I/usr/local/src/ssl/include -Issl_include
#CFLAGS=-g -I/usr/local/src/ssl/include -Issl_include
LDFLAGS=-L/usr/local/src/ssl/lib -lcrypto
GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h 
MAKEFILE=Makefile
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c 
ALLHEAD=${GEN_HEAD} pbc_version.h

#all:	create verify mod_pubcookie.o
all:	pbc_create pbc_verify base64.o

pbc_create:	pbc_create.o libpubcookie.o
		$(CC) ${CFLAGS} -o $@ pbc_create.o libpubcookie.o $(LDFLAGS)

pbc_verify:	pbc_verify.o libpubcookie.o
		$(CC) ${CFLAGS} -o $@ pbc_verify.o libpubcookie.o $(LDFLAGS)

pbc_create.o: pbc_create.c ${GEN_HEAD} ${MAKEFILE}
pbc_verify.o: pbc_verify.c ${GEN_HEAD} ${MAKEFILE}
base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}
libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}

#mod_pubcookie.o: mod_pubcookie.c

clean: 
	rm -f *.o *~ core pbc_create pbc_verify
