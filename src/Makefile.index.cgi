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
#   $Id: Makefile.index.cgi,v 1.2 2000-03-03 01:52:24 willey Exp $
#

# your compiler here
CC=gcc
# choose your flags.
#   for convenience i make symlinks to the openssl and rsaref directorys
#   the two openssl include directories compensate for a openssl
#     file location shuffling.
CFLAGS=-O3 -Wall -I. -Iopenssl/include/openssl -Iopenssl/include -I/usr/local/include
# order is important here
LDFLAGS=-L./openssl -L./rsaref -lssl -lcrypto -lRSAglue -lrsaref -lkrb5

# hopefully you don't have to change anything below here
################################################################################

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
ALLHEAD=${GEN_HEAD}
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c base64.c dtest.c candv.c

BASENAME=pubcookie
#sed -e '/^#define PBC_VERSION/!d' -e '/^#define PBC_VERSION/s/^#define PBC_VERSION "\(a2\)".*$/\1/' pbc_version.h` \

VERSION=a5release5
DIR_NAME=$(BASENAME)-$(VERSION)
TARFILE=$(BASENAME)-$(VERSION).tar

MAKEFILE=Makefile
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c  securid_ping.c  securid_securid.c securid_server.c
ALLHEAD=${GEN_HEAD}

TAR=tar
RM=rm
GZIP=gzip

default:	index.cgi

all:	index.cgi

index.cgi:	index.cgi.o  securid_ping.o securid_securid.o securid_server.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ index.cgi.o libpubcookie.o base64.o securid_ping.o securid_securid.o securid_server.o /usr/local/lib/libcgic.a $(LDFLAGS)

uwnetid_stub:	uwnetid_stub.o  uwnetid_stub.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ uwnetid_stub.o libpubcookie.o base64.o $(LDFLAGS)

securid_stub:	securid_stub.o  securid_ping.o securid_securid.o securid_server.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ securid_stub.o libpubcookie.o base64.o securid_ping.o securid_securid.o securid_server.o $(LDFLAGS)

h2ph:
	co -l *.ph; \
	h2ph -d . *.h; \
	ci -mauto_update -u *.ph

base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
make_crypted_bit.o: make_crypted_bit.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
mkc_key_generic.o: mkc_key_generic.c ${GEN_HEAD} ${MAKEFILE}
mkc_key_local.o: mkc_key_local.c ${GEN_HEAD} ${MAKEFILE}
mod_pubcookie.o: mod_pubcookie.c libpubcookie.o ${MAKEFILE}
index.cgi.o: index.cgi.c index.cgi.h libpubcookie.o ${MAKEFILE} /usr/local/lib/libcgic.a 
securid_ping.o: securid_ping.c securid_securid.h ${GEN_HEAD} ${MAKEFILE}
securid_securid.o: securid_securid.c securid_securid.h ${GEN_HEAD} ${MAKEFILE}
securid_server.o: securid_server.c securid_securid.h ${GEN_HEAD} ${MAKEFILE}

clean: 
	$(RM) -f index.cgi.o securid_*.o core index.cgi libpubcookie.o uwnetid_stub securid_stub

# to purify candv (then run a.out)
#purify gcc ./candv.o libpubcookie.o base64.o -L./ssleay -lRSAglue -lcrypto ./rsaref/build/rsaref.a
