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
#   More info: http://www.washington.edu/pubcookie/
#   Written by the Pubcookie Team
#
#   This is the pubcookie general Makefile.  It is not for the Apache module
#   or the IIS filter.  See Makefile.tmpl or Makefile.apxs for Apache makefiles
#
################################################################################
#
#   $Id: Makefile,v 1.42 2001-12-09 09:10:06 willey Exp $
#

# your compiler here
CC=gcc
# choose your flags.
CFLAGS=-O3 -Wall -I. -I/usr/local/ssl/include/openssl -I/usr/local/ssl/include/ -I/usr/local/include -DDEBUG
# order is important here
LDFLAGS=-L/usr/local/ssl/lib -lssl -lcrypto -ldl
# nfast stuff
#LDFLAGS=-L/usr/local/ssl/lib -lssl -lcrypto -L/opt/nfast/gcc/lib -lnfstub

# hopefully you don't have to change anything below here
################################################################################

GENERALHEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
MODULEHEAD=
LOGINHEAD=index.cgi.h \
          securid.h
TESTHEAD=
ALLHEAD=${GENERALHEAD} ${LOGINHEAD} ${MODULEHEAD} ${TESTHEAD}

GENERALSRC=libpubcookie.c \
           base64.c
MODULESRC=mod_pubcookie.c
LOGINSRC=index.cgi.c \
	 index.cgi_krb.c \
	 index.cgi_securid.c \
	 securid.c \
         login_templates/login_part1 \
         login_templates/login_part2 \
         login_templates/nonpost_redirect \
         login_templates/notok_part1 \
         login_templates/notok_part2 \
	 make_crypted_blob.c \
	 pbc_key_generic.c \
	 pbc_key_local.txt \
	 pbc_key_local.c
TESTSRC=dtest.c \
        pbc_create.c \
        what_is_my_ip.c \
        pbc_verify.c \
        candv.c
ALLSRC=${GENERALSRC} ${TESTSRC} ${LOGINSRC} ${MODULESRC}

GENERALMISC=README \
            CREDITS \
            LICENSE
MODULEMISC=CHANGES.mod_pubcookie \
           Makefile.tmpl \
           Makefile.apxs 
LOGINMISC=CHANGES.login \
          Makefile \
          Makefile.index.cgi \
          contrib\* \
	  INSTALL.login
TESTMISC=Makefile
ALLMISC=${GENERALMISC} ${TESTMISC} ${LOGINMISC} ${MODULEMISC}

MAKEFILE=Makefile
TAR=tar
RM=rm
GZIP=gzip

default:	all

test_apps:	candv dtest speed_test pbc_create pbc_verify check_crypted_blob

all:	candv dtest pbc_key_generic pbc_key_local make_crypted_blob candv dtest pbc_create pbc_verify check_crypted_blob


speed_test:	speed_test.o libpubcookie.o base64.o
	$(CC) ${CFLAGS} -o $@ speed_test.o libpubcookie.o base64.o $(LDFLGS)

candv:		candv.o libpubcookie.o base64.o
	$(CC) ${CFLAGS} -o $@ candv.o libpubcookie.o base64.o $(LDFLAGS)

dtest:		dtest.o libpubcookie.o 
	$(CC) ${CFLAGS} -o $@ dtest.o libpubcookie.o base64.o $(LDFLAGS)

check_crypted_blob:	check_crypted_blob.o libpubcookie.o 
	$(CC) ${CFLAGS} -o $@ check_crypted_blob.o libpubcookie.o base64.o $(LDFLAGS)

pbc_create:	pbc_create.o libpubcookie.o base64.o
	$(CC) ${CFLAGS} -o $@ pbc_create.o libpubcookie.o base64.o $(LDFLAGS)

pbc_verify:	pbc_verify.o libpubcookie.o base64.o
	$(CC) ${CFLAGS} -o $@ pbc_verify.o libpubcookie.o base64.o $(LDFLAGS)

t:		t.o libpubcookie.o 
	$(CC) ${CFLAGS} -o $@ t.o libpubcookie.o base64.o $(LDFLAGS)

pbc_key_generic:	pbc_key_generic.o libpubcookie.o 
	$(CC) ${CFLAGS} -o $@ pbc_key_generic.o libpubcookie.o base64.o $(LDFLAGS)

pbc_key_local:		pbc_key_local.o libpubcookie.o 
	$(CC) ${CFLAGS} -o $@ pbc_key_local.o libpubcookie.o base64.o $(LDFLAGS)

make_crypted_blob:	make_crypted_blob.o libpubcookie.o 
	$(CC) ${CFLAGS} -o $@ make_crypted_blob.o libpubcookie.o base64.o $(LDFLAGS)

what_is_my_ip:		what_is_my_ip.o libpubcookie.o base64.o
	$(CC) ${CFLAGS} -o $@ what_is_my_ip.o libpubcookie.o base64.o $(LDFLAGS)

uwnetid_stub:		uwnetid_stub.o libpubcookie.o index.cgi_krb.o base64.o
	$(CC) ${CFLAGS} -o $@ uwnetid_stub.o libpubcookie.o base64.o index.cgi_krb.o $(LDFLAGS) -lkrb5

k5auth_test:		k5auth.o k5auth_test.o
	$(CC) ${CFLAGS} -o $@ k5auth.o k5auth_test.o $(LDFLAGS) -lkrb5

securid_stub:	securid_stub.o  securid.o libpubcookie.o base64.o
	$(CC) ${CFLAGS} -o $@ securid_stub.o libpubcookie.o base64.o securid.o $(LDFLAGS) -lmgoapi -lkrb5

moduletar:
	VERSION=`awk '/PBC_PUBID/{print $$3}' pbc_version.h | sed 's/"//g'`; \
	BASENAME=mod_pubcookie; \
	DIR_NAME=$$BASENAME-$$VERSION; \
	TARFILE=$$BASENAME-$${VERSION}.tar; \
	rm -rf $$DIR_NAME $$TARFILE; \
	ln -s . $$DIR_NAME; \
	for i in ${GENERALSRC} $(MODULESRC) $(GENERALHEAD) ${MODULEHEAD} ${MODULEMISC} $(GENERALMISC) ;\
	do \
	        $(TAR) rvf $$TARFILE $$DIR_NAME/$$i; \
	done; \
	$(GZIP) -f $$TARFILE; \
	$(RM) -rf $$DIR_NAME; \
	echo Created $$TARFILE.gz ; \
	ls -l $$TARFILE.gz


logintar:
	LVERSION=`awk '/PBC_LOGIN_VERSION/{print $$3}' pbc_version.h | sed 's/"//g'`; \
	BASENAME=pubcookie_login; \
	DIR_NAME=$$BASENAME-$$LVERSION; \
	TARFILE=$$BASENAME-$${LVERSION}.tar; \
	rm -rf $$DIR_NAME $$TARFILE; \
	ln -s . $$DIR_NAME; \
	for i in ${GENERALSRC} ${LOGINSRC} ${TESTSRC} ${GENERALHEAD} ${LOGINHEAD} ${TESTHEAD} ${LOGINMISC} ${GENERALMISC} ${TESTMISC} ;\
	do \
	        $(TAR) rvf $$TARFILE $$DIR_NAME/$$i; \
	done; \
	$(GZIP) -f $$TARFILE; \
	$(RM) -rf $$DIR_NAME; \
	echo Created $$TARFILE.gz; \
	ls -l $$TARFILE.gz

base64.o: base64.c ${GENERALHEAD} ${MAKEFILE}
candv.o: candv.c ${GENERALHEAD} ${MAKEFILE}
dtest.o: dtest.c ${GENERALHEAD} ${MAKEFILE}
libpubcookie.o: libpubcookie.c libpubcookie.h ${GENERALHEAD} ${MAKEFILE}
make_crypted_blob.o: make_crypted_blob.c libpubcookie.h ${GENERALHEAD} ${MAKEFILE}
pbc_key_generic.o: pbc_key_generic.c ${GENERALHEAD} ${MAKEFILE}
pbc_key_local.o: pbc_key_local.c ${GENERALHEAD} ${MAKEFILE}
mod_pubcookie.o: mod_pubcookie.c libpubcookie.o ${MAKEFILE}
pbc_create.o: pbc_create.c ${GENERALHEAD} ${MAKEFILE}
pbc_verify.o: pbc_verify.c ${GENERALHEAD} ${MAKEFILE}
t.o: t.c ${GENERALHEAD} ${MAKEFILE}
check_crypted_blob.o: check_crypted_blob.c ${GENERALHEAD} ${MAKEFILE}
what_is_my_ip.o: what_is_my_ip.c ${GENERALHEAD} ${MAKEFILE}
uwnetid_stub.o: uwnetid_stub.c ${GENERALHEAD} ${MAKEFILE}
index.cgi_krb.o: index.cgi_krb.c ${GENERALHEAD} ${MAKEFILE}
securid.o: securid.c securid.h ${GEN_HEAD} ${MAKEFILE}
k5auth.o: k5auth.c k5auth.h ${GEN_HEAD} ${MAKEFILE}

clean: 
	$(RM) -f *.o *~ core test candv dtest out check_crypted_blob mod_pubcookie.so what_is_my_ip pbc_create pbc_verify t make_crypted_blob what_is_my_ip pbc_key_generic pbc_key_local uwnetid_stub securid_stub

# to purify candv {then run a.out)
#purify gcc ./candv.o libpubcookie.o base64.o -L./ssleay -lRSAglue -lcrypto ./rsaref/build/rsaref.a

