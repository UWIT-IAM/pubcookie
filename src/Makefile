#defaults
#
# $Id: Makefile,v 1.18 1999-07-22 22:49:18 willey Exp $
#

CC=gcc
CFLAGS=-g -Wall -Issleay/include
LDFLAGS=-L./ssleay -lssl -lRSAglue -lcrypto ./rsaref/build/rsaref.a

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c base64.c dtest.c candv.c
MISC=README \
     CHANGES \
     Makefile \
     Makefile.tmpl \
     Makefile.apxs \
     pubcookie_granting.cert \
     cookie_blanking_patch.apache1.3.6

BASENAME=pubcookie
#sed -e '/^#define PBC_VERSION/!d' -e '/^#define PBC_VERSION/s/^#define PBC_VERSION "\(a2\)".*$/\1/' pbc_version.h` \

VERSION=a5release2
DIR_NAME=$(BASENAME)-$(VERSION)
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

h2ph:
	co -l *.ph; \
	h2ph -d . *.h; \
	ci -mauto_update -u *.ph

tar:
	rm -rf $(DIR_NAME); \
	mkdir $(DIR_NAME); \
	for i in $(SRC) $(GEN_HEAD) $(MISC) ;\
	do \
		cp $$i $(DIR_NAME); \
		chmod 664 $(DIR_NAME)/$$i; \
	done; \
	$(TAR) cf $(TARFILE) $(DIR_NAME); \
	$(GZIP) -f $(TARFILE); \
	$(RM) -rf $(DIR_NAME);

libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}

dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
test_local_c_key.o: test_local_c_key.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}

mod_pubcookie.o: mod_pubcookie.c

clean: 
	$(RM) -f *.o *~ core test candv dtest out test_local_c_key

