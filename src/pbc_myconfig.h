/*

    Copyright 1999-2002, University of Washington.  All rights reserved.
    see doc/LICENSE.txt for copyright information

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|

    All comments and suggestions to pubcookie@cac.washington.edu
    More information: http://www.pubcookie.org/
    Written by the Pubcookie Team

    this is the interface for the pubcookie config file

 */

/*
    $Id: pbc_myconfig.h,v 1.5 2002-08-20 20:11:45 greenfld Exp $
 */

#ifndef INCLUDED_PBC_MYCONF_H
#define INCLUDED_PBC_MYCONF_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/**
 * initialize the config subsystem
 * @param alt_config the location of an alternate configuration file
 * to read, instead of the default
 * @param ident the identity of the calling program used
 * @return 0 for success, non-zero for failure
 */
extern int libpbc_config_init(const char *alt_config, const char *ident);

/**
 * return a string variable identified by key
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value of the option or def if it isn't found.  the
 * string belongs to the config library---it should not be changed or
 * free().  */
extern const char *libpbc_config_getstring(const char *key, const char *def);

/**
 * return an int variable identified by key
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value of the option or def if it isn't found
 */
extern int libpbc_config_getint(const char *key, int def);

/**
 * return a switch variable (true/false, yes/no, 1/0) identified by key
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value (1 for true, 0 for false) of the option or def if
 * it isn't found 
 */
extern int libpbc_config_getswitch(const char *key, int def);

/**
 * find a space seperated list in the config list
 * @param key the string key
 * @return a NULL terminated array of NUL terminated strings.
 * the array must be free() when the caller is done */
extern char **libpbc_config_getlist(const char *key);

#endif /* INCLUDED_PBC_MYCONF_H */

