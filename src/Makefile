# -*- make -*-
#
# Makefile, overall Makefile for CVS sources.
# 
# Copyright (c) 2002 Jonathan J. Miner <miner@doit.wisc.edu>
#
# $Id: Makefile,v 1.51 2002-06-28 03:30:17 jjminer Exp $

include Makefile.settings

.PHONY: all index.cgi mod_pubcookie.so clean install dist

all: index.cgi mod_pubcookie.so

index.cgi:
	$(MAKE) -f Makefile.login

mod_pubcookie.so:
	$(MAKE) -f Makefile.apxs

clean:
	$(MAKE) -f Makefile.login clean
	$(MAKE) -f Makefile.apxs clean

install: clean
	$(MAKE) -f Makefile.login install
	$(MAKE) -f Makefile.apxs install

dist:
	$(MAKE) -f Makefile.login dist
	$(MAKE) -f Makefile.apxs dist

tests:
	$(MAKE) -f Makefile.login tests

utils:
	$(MAKE) -f Makefile.login utils

test:
	$(MAKE) -f Makefile.login test

# vim: set noet:
