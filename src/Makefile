#defaults
#
# $Id: Makefile,v 1.7 1999-01-09 01:38:46 willey Exp $
#

CC=gcc
CFLAGS=-g -Wall -Issleay/include
LDFLAGS=-L./ssleay -lssl -lRSAglue -lcrypto ./rsaref/build/rsaref.a

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c base64.c dtest.c candv.c
MISC=README pubcookie.txt Makefile Makefile.tmpl

BASENAME=pubcookie
VERSION=v1
NAME=$(BASENAME)-$(VERSION)
TARFILE=$(BASENAME)-$(VERSION).tar

MAKEFILE=Makefile
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c
ALLHEAD=${GEN_HEAD}

TAR=tar
RM=rm
GZIP=gzip

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
	mkdir $(NAME); \
	for i in $(SRC) $(GEN_HEAD) $(MISC) ;\
	do \
		cp $$i $(NAME); \
	done; \
	$(TAR) cf $(TARFILE) $(NAME); \
	$(GZIP) -f $(TARFILE); \
	$(RM) -rf $(NAME);

libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}

dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
test_local_c_key.o: test_local_c_key.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}

mod_pubcookie.o: mod_pubcookie.c

clean: 
	$(RM) -f *.o *~ core test candv dtest out test_local_c_key

