################################################################################
#
#   Copyright 1999, University of Washington.  All rights reserved.
#
#    ____        _                     _    _
#   |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
#   | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
#   |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
#   |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|
#
#
#   All comments and suggestions to pubcookie@cac.washington.edu
#   More info: https:/www.washington.edu/pubcookie/
#   Written by the Pubcookie Team
#
#   This is the pubcookie general Makefile.  It is not for the Apache module
#   or the IIS filter.  See Makefile.tmpl or Makefile.apxs for Apache makefiles
#
################################################################################
#
#   $Id: Makefile,v 1.21 1999-09-01 17:20:41 willey Exp $
#

# your compiler here
CC=egcs
# choose your flags.
#   for convenience i make symlinks to the openssl and rsaref directorys
#   the two openssl include directories compensate for a openssl
#     file location shuffling.
CFLAGS=-O3 -g -Wall -Iopenssl/include/openssl -Iopenssl/include
# order is important here
LDFLAGS=-L./openssl -L./rsaref -lssl -lcrypto -lRSAglue -lrsaref

# hopefully you don't have to change anything below here
################################################################################

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
ALLHEAD=${GEN_HEAD}
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c base64.c dtest.c candv.c
MISC=README \
     CHANGES \
     Makefile \
     Makefile.tmpl \
     Makefile.apxs \
     pubcookie_granting.cert

BASENAME=pubcookie
#sed -e '/^#define PBC_VERSION/!d' -e '/^#define PBC_VERSION/s/^#define PBC_VERSION "\(a2\)".*$/\1/' pbc_version.h` \

VERSION=a5release5
DIR_NAME=$(BASENAME)-$(VERSION)
TARFILE=$(BASENAME)-$(VERSION).tar

MAKEFILE=Makefile
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c
ALLHEAD=${GEN_HEAD}

TAR=tar
RM=rm
GZIP=gzip


default:	candv dtest test_local_c_key base64.o

admin:	pbc_create pbc_verify base64.o

all:	pbc_create pbc_verify candv dtest mkc_key_generic mkc_key_local make_crypted_bit test_local_c_key candv dtest test_local_c_key

test_apps:	candv dtest test_local_c_key

candv:	candv.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ candv.o libpubcookie.o base64.o $(LDFLAGS)

dtest:		dtest.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ dtest.o libpubcookie.o base64.o $(LDFLAGS)

test_local_c_key:	test_local_c_key.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ test_local_c_key.o libpubcookie.o base64.o $(LDFLAGS)

pbc_create:	pbc_create.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ pbc_create.o libpubcookie.o base64.o $(LDFLAGS)

pbc_verify:	pbc_verify.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ pbc_verify.o libpubcookie.o base64.o $(LDFLAGS)

t:		t.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ t.o libpubcookie.o base64.o $(LDFLAGS)

mkc_key_generic:	mkc_key_generic.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ mkc_key_generic.o libpubcookie.o base64.o $(LDFLAGS)

mkc_key_local:	mkc_key_local.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ mkc_key_local.o libpubcookie.o base64.o $(LDFLAGS)

make_crypted_bit:	make_crypted_bit.o libpubcookie.o 
		$(CC) ${CFLAGS} -o $@ make_crypted_bit.o libpubcookie.o base64.o $(LDFLAGS)

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

base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
make_crypted_bit.o: make_crypted_bit.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
mkc_key_generic.o: mkc_key_generic.c ${GEN_HEAD} ${MAKEFILE}
mkc_key_local.o: mkc_key_local.c ${GEN_HEAD} ${MAKEFILE}
mod_pubcookie.o: mod_pubcookie.c
pbc_create.o: pbc_create.c ${GEN_HEAD} ${MAKEFILE}
pbc_verify.o: pbc_verify.c ${GEN_HEAD} ${MAKEFILE}
t.o: t.c ${GEN_HEAD} ${MAKEFILE}
test_local_c_key.o: test_local_c_key.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}

clean: 
	$(RM) -f *.o *~ core test candv dtest out test_local_c_key mod_pubcookie.so pbc_create pbc_verify t make_crypted_bit

# to purify candv (then run a.out)
#purify gcc ./candv.o libpubcookie.o base64.o -L./ssleay -lRSAglue -lcrypto ./rsaref/build/rsaref.a
