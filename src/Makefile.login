# -*- makefile -*-
# 
# Makefile.login, Makefile for the login server
# 
# Copyright (C) 2002 Jonathan J. Miner <miner@doit.wisc.edu>
# 
# $Id: Makefile.login,v 1.6 2002-06-12 20:09:58 jjminer Exp $

include Makefile.settings

DEFINES += -DDEBUG

CGIC_DIR=/usr/user/cgic1.07-pubcookie1.01
CGIC_LIB=$(CGIC_DIR)/libcgic.a

# you have your choice of "basic" and "basic"
FLAVOR=basic

DEFINES += -DFLAVOR=$(FLAVOR)

EXTRA_CFLAGS += -g -I$(CGIC_DIR)
EXTRA_LIBS += -ldl
# Socket Libraries
# EXTRA_LIBS += -lnsl -lsocket

## HAVE_KRB4 - you want the kerberos 4 verifier
# DEFINES += -DHAVE_KRB4

## HAVE_KRB5 - you want the kerberos 5 verifier
DEFINES += -DHAVE_KRB5
EXTRA_LIBS += -ldes -lkrb5

## HAVE_LDAP - you want the ldap verifier
# DEFINES += -DHAVE_LDAP
# EXTRA_LIBS += -lldapssl30
# EXTRA_CFLAGS += -I/data/netscape/sdk3/include
# EXTRA_LDFLAGS += -L/data/netscape/sdk3/include

## MAKE_MIRROR - mirrors everything sent to the browser
# DEFINES += -DMAKE_MIRROR

# There be dragons here...

PBC_PATH=-DPBC_PATH=\"$(PUBCOOKIE_DIR)/\"

TEST_SRC=pbc_create.c pbc_verify.c candv.c dtest.c make_crypted_blob.c \
		 check_crypted_blob.c

TEST_OBJ=pbc_create.o pbc_verify.o candv.o dtest.o make_crypted_blob.o \
		 check_crypted_blob.o

TEST_FILES=pbc_create pbc_verify candv dtest make_crypted_blob check_crypted_blob

UTIL_SRC=pbc_key_local.c pbc_key_generic.c keyserver.c keyclient.c

UTIL_OBJ=pbc_key_local.o pbc_key_generic.o keyserver.o keyclient.o

UTIL_FILES=keyserver keyclient

VERIFIERS=verify_alwaystrue.o \
	verify_kerberos4.o \
	verify_kerberos5.o \
	verify_shadow.o \
	verify_ldap.o

VERIFY_SRC=verify_alwaystrue.c \
	verify_kerberos4.c \
	verify_kerberos5.c \
	verify_shadow.c \
	verify_ldap.c

FLAVOR_SRC=flavor_basic.c

INDEX_OBJ=index.cgi.o verify.o \
		  flavor_$(FLAVOR).o \
		  $(VERIFIERS)

INDEX_FILES=index.cgi

INDEX_SRC=index.cgi.c verify.c \
		  $(VERIFY_SRC) \
		  $(FLAVOR_SRC)

KEYMGT_FILES=keyclient keyserver

KEYMGT_SRC=keyclient.c keyserver.c

INDEX_HEAD=index.cgi.h \
		   flavor.h \
		   verify.h

LOGIN_TEMPLATES=login_templates.generic/login_part1 \
			    login_templates.generic/login_part2 \
			    login_templates.generic/nonpost_redirect \
			    login_templates.generic/notok_part1 \
			    login_templates.generic/notok_part2

DOCS=$(GENERAL_DOCS) \
	 ../doc/NEW_SITE.txt \
	 ../doc/INSTALL.login.txt \
	 ../doc/CHANGES.login.txt

ALL_HEAD=$(INDEX_HEAD) $(LIB_HEAD)

ALL_SRC=$(INDEX_SRC) $(UTIL_SRC) $(TEST_SRC) $(LIB_SRC)

MAKEFILES += Makefile.login

VERSION := `$(AWK) '/PBC_LOGIN_VERSION/{print $$3}' pbc_version.h | $(SED) 's/"//g'`
BASENAME := pubcookie_login-$(VERSION)

.PHONY: all clean tests utils install ver

all: ver $(INDEX_FILES) $(UTIL_FILES)

ver:
	@echo Making $(BASENAME);

include Makefile.libpubcookie

%.o: %.c ${LIB_HEAD} ${MAKEFILES}

candv:	candv.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ candv.o $(LIB_OBJ) $(LDFLAGS)

dtest:	dtest.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ dtest.o $(LIB_OBJ) $(LDFLAGS)

vtest: $(VERIFIERS)
	$(CC) ${CFLAGS} -DTEST_VERIFY -o $@ verify.c $(VERIFIERS) $(LIB_OBJ) $(LDFLAGS)

check_crypted_blob:	check_crypted_blob.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ check_crypted_blob.o $(LIB_OBJ) $(LDFLAGS)

pbc_create:	pbc_create.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ pbc_create.o $(LIB_OBJ) $(LDFLAGS)

pbc_verify:	pbc_verify.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ pbc_verify.o $(LIB_OBJ) $(LDFLAGS)

pbc_key_generic: pbc_key_generic.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ pbc_key_generic.o $(LIB_OBJ) $(LDFLAGS)

pbc_key_local: pbc_key_local.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ pbc_key_local.o $(LIB_OBJ) $(LDFLAGS)

make_crypted_blob: make_crypted_blob.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ make_crypted_blob.o $(LIB_OBJ) $(LDFLAGS)

what_is_my_ip: what_is_my_ip.o $(LIB_OBJ)
	$(CC) ${CFLAGS} -o $@ what_is_my_ip.o $(LIB_OBJ) $(LDFLAGS)

index.cgi: $(INDEX_OBJ) $(LIB_OBJ) $(CGIC_LIB) 
		$(CC) ${CFLAGS} -o $@ $(INDEX_OBJ) $(LIB_OBJ) $(CGIC_LIB) $(LDFLAGS)

index.cgi.o $(VERIFIERS) flavor_$(FLAVOR).o: $(MAKEFILES) $(LIB_HEAD) $(INDEX_HEAD)

keyserver: keyserver.o $(LIB_OBJ)
		$(CC) ${CFLAGS} -o $@ keyserver.o $(LIB_OBJ) $(CGIC_LIB) $(LDFLAGS)

keyclient: keyclient.o $(LIB_OBJ)
		$(CC) ${CFLAGS} -o $@ keyclient.o $(LIB_OBJ) $(LDFLAGS)

clean::
	$(FORCE_RM) $(INDEX_FILES) $(INDEX_OBJ) $(TEST_OBJ) $(UTIL_OBJ) \
			 	$(UTIL_FILES) $(TEST_FILES)

tests: $(TEST_FILES)

utils: $(UTIL_FILES)

$(PUBCOOKIE_DIR):
	$(INSTALL_DIR) $(PUBCOOKIE_DIR)

$(LOGIN_DIR): $(PUBCOOKIE_DIR)
	$(INSTALL_DIR) $(LOGIN_DIR)

$(TEMPLATE_DIR): $(PUBCOOKIE_DIR)
	$(INSTALL_DIR) $(TEMPLATE_DIR)

install:: $(PUBCOOKIE_DIR) $(LOGIN_DIR) $(TEMPLATE_DIR) $(UTIL_FILES) $(INDEX_FILES) $(LOGIN_TEMPLATES)
	$(INSTALL_BIN) $(UTIL_FILES) $(PUBCOOKIE_DIR)
	$(INSTALL_BIN) $(INDEX_FILES) $(LOGIN_DIR)
	$(INSTALL_OTHER) $(LOGIN_TEMPLATES) $(TEMPLATE_DIR)

dist: ver
	$(MKDIR) $(BASENAME)
	$(CP) $(ALL_SRC) $(ALL_HEAD) \
	      Makefile.settings Makefile.libpubcookie \
		  $(BASENAME)/
	$(SED) -e 's/^MAKEFILES += Makefile.login$$/MAKEFILES += Makefile/g' \
		   Makefile.login > $(BASENAME)/Makefile
	$(RECURSIVE_CP) contrib $(BASENAME)
	$(MKDIR) $(BASENAME)/login_templates
	$(CP) $(LOGIN_TEMPLATES) $(BASENAME)/login_templates
	$(CP) $(DOCS) $(BASENAME)/
	$(TAR) cf $(BASENAME).tar $(BASENAME)/
	$(GZIP) $(BASENAME).tar
	$(RECURSIVE_FORCE_RM) ./$(BASENAME)/

# vim: set noet:
