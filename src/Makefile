#defaults
#
# $Id: Makefile,v 1.5 1999-01-09 00:10:35 willey Exp $
#

CC=gcc
CFLAGS=-g -Wall -Issleay/include
LDFLAGS=-L./ssleay -lssl -lRSAglue -lcrypto ./rsaref/build/rsaref.a

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c libpubcookie.c  base64.c dtest.c candv.c
MISC=README pubcookie.txt Makefile

TARFILE=pubcookie-v1.tar

MAKEFILE=Makefile
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c
ALLHEAD=${GEN_HEAD}

default:	base64.o

all:	candv dtest test_local_c_key

test_apps:	candv dtest test_local_c_key

candv:	candv.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ candv.o libpubcookie.o base64.o $(LDFLAGS)

dtest:		dtest.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ dtest.o libpubcookie.o base64.o $(LDFLAGS)

test_local_c_key:	test_local_c_key.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ test_local_c_key.o libpubcookie.o base64.o $(LDFLAGS)

tar:
	export STUFF; \
	for i in $(SRC) $(GEN_HEAD) $(MISC) ;\
	do \
	STUFF="$$STUFF $$i"; \
	done; \
	tar cf $(TARFILE) $$STUFF; \
       	gzip -f $(TARFILE)

libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}

dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
test_local_c_key.o: test_local_c_key.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}

mod_pubcookie.o: mod_pubcookie.c

clean: 
	rm -f *.o *~ core test candv dtest out test_local_c_key

