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
#   $Id: Makefile.index.cgi,v 1.12 2001-11-15 01:58:58 willey Exp $
#

# your compiler here
CC=gcc

# your OpenSSl base directory.  
SSL_BASE=/usr/local/ssl
# if your OpenSSL header files are not in $(SSL_BASE)/include/
SSL_OTHER_INCL=
# if your OpenSSL library files are not in $(SSL_BASE)/lib/
SSL_OTHER_LIB_DIR=

# your cgic library
CGIC=/usr/local/lib/libcgic.a

# extra library dirs (for authentication modules and such)
EXTRA_LIB_DIRS=-L/opt/nfast/gcc/lib
# extra libraries (for authentication modules and suc)
EXTRA_LIBS=-lkrb5 -lmgoapi -lnfstub 

# choose your compile flags.
# some options are: DEBUG - voluminious debug info
#                   MAKE_MIRROR - mirrors everything sent to the browser
#                   NO_HOST_BASED_KEY_FILENAMES - the login server will form
#                             key filenames from components including the 
#                             hostname unless this is set
#                   FORM_NOT_IN_TMPL - if your login form isn't in the template
#                                      hopefully obsolete soon, only UWash need
CFLAGS=-O3 -Wall -I. -I$(SSL_BASE)/include -I$(SSL_BASE)/include/openssl -I/usr/local/include -DFORM_NOT_IN_TMPL


# a blast from the past:
#LDFLAGS=-L$(SSL_BASE)/lib/ $(RSAREF_LIB_DIR) -lssl -lcrypto -lRSAglue -lrsaref $(EXTRA_LIB_DIRS) $(EXTRA_LIBS) -ldl

LDFLAGS=-L$(SSL_BASE)/lib/ -lssl -lcrypto $(EXTRA_LIB_DIRS) $(EXTRA_LIBS) -ldl

# hopefully you don't have to change anything below here
################################################################################

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
ALLHEAD=${GEN_HEAD}
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c base64.c dtest.c candv.c

MAKEFILE=Makefile.index.cgi
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c securid.c index.cgi_securid.c index.cgi_krb.c 
ALLHEAD=${GEN_HEAD}

RM=rm

default:	index.cgi

all:	index.cgi

# most basic compile rules with no authentication modules
#index.cgi:	index.cgi.o  libpubcookie.o base64.o 
#		$(CC) ${CFLAGS} -o $@ index.cgi.o libpubcookie.o base64.o $(CGIC) $(LDFLAGS)

# version used at UWash with two auth modules
index.cgi:	index.cgi.o  securid.o libpubcookie.o base64.o index.cgi_securid.o index.cgi_krb.o 
		$(CC) ${CFLAGS} -o $@ index.cgi.o index.cgi_securid.o index.cgi_krb.o libpubcookie.o base64.o securid.o $(CGIC) $(LDFLAGS)

base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
make_crypted_bit.o: make_crypted_bit.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
mod_pubcookie.o: mod_pubcookie.c libpubcookie.o ${MAKEFILE}
index.cgi.o: index.cgi.c index.cgi.h libpubcookie.o ${MAKEFILE} $(CGIC) 
index.cgi_krb.o: index.cgi_krb.c index.cgi.h libpubcookie.o ${MAKEFILE}
index.cgi_securid.o: index.cgi_securid.c index.cgi.h libpubcookie.o ${MAKEFILE}
securid.o: securid.c securid.h ${GEN_HEAD} ${MAKEFILE}

clean: 
	$(RM) -f index.cgi.o securid.o core index.cgi libpubcookie.o uwnetid_stub securid_stub base64.o  index.cgi_krb.o  index.cgi_securid.o

