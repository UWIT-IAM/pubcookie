#defaults
#
# $Id: Makefile,v 1.4 1998-07-31 21:08:13 willey Exp $
#

CC=gcc
CFLAGS=-g -Wall -Issleay/include
LDFLAGS=-L./ssleay -lRSAglue -lcrypto ./rsaref/build/rsaref.a
GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h

MAKEFILE=Makefile
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c
ALLHEAD=${GEN_HEAD}

default:	pbc_create pbc_verify base64.o

all:	pbc_create pbc_verify candv dtest

test_apps:	candv dtest

pbc_create:	pbc_create.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ pbc_create.o libpubcookie.o base64.o $(LDFLAGS)

pbc_verify:	pbc_verify.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ pbc_verify.o libpubcookie.o base64.o $(LDFLAGS)

candv:	candv.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ candv.o libpubcookie.o base64.o $(LDFLAGS)

dtest:		dtest.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ dtest.o libpubcookie.o base64.o $(LDFLAGS)

t:		t.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ t.o libpubcookie.o base64.o $(LDFLAGS)

key1:		key1.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ key1.o libpubcookie.o base64.o $(LDFLAGS)

libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}

pbc_create.o: pbc_create.c ${GEN_HEAD} ${MAKEFILE}
pbc_verify.o: pbc_verify.c ${GEN_HEAD} ${MAKEFILE}

dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
t.o: t.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
key1.o: key1.c ${GEN_HEAD} ${MAKEFILE}

mod_pubcookie.o: mod_pubcookie.c

# to purify candv (then run a.out)
#purify gcc ./candv.o libpubcookie.o base64.o -L./ssleay -lRSAglue -lcrypto ./rsaref/build/rsaref.a

clean: 
	rm -f *.o *~ core pbc_create pbc_verify test candv dtest out
