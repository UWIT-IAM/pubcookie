/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: pbc_myconfig.h,v 1.10 2003-05-06 23:51:19 willey Exp $
 */

#ifndef INCLUDED_PBC_MYCONF_H
#define INCLUDED_PBC_MYCONF_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/**
 * initialize the config subsystem
 * @param pool Apache memory pool
 * @param alt_config the location of an alternate configuration file
 * to read, instead of the default
 * @param ident the identity of the calling program used
 * @return 0 for success, non-zero for failure
 */
extern int libpbc_myconfig_init(pool *p, const char *alt_config, const char *ident);

/**
 * return a string variable identified by key
 * @param pool Apache memory pool
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value of the option or def if it isn't found.  the
 * string belongs to the config library---it should not be changed or
 * free().  */
extern const char *libpbc_myconfig_getstring(pool *p, const char *key, const char *def);

/**
 * return an int variable identified by key
 * @param pool Apache memory pool
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value of the option or def if it isn't found
 */
extern int libpbc_myconfig_getint(pool *p, const char *key, int def);

/**
 * return a switch variable (true/false, yes/no, 1/0) identified by key
 * @param pool Apache memory pool
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value (1 for true, 0 for false) of the option or def if
 * it isn't found 
 */
extern int libpbc_myconfig_getswitch(pool *p, const char *key, int def);

/**
 * find a space seperated list in the config list
 * @param pool Apache memory pool
 * @param key the string key
 * @return a NULL terminated array of NUL terminated strings.
 * the array must be free() when the caller is done */
extern char **libpbc_myconfig_getlist(pool *p, const char *key);

#ifdef WIN32
  const char *AddSystemRoot(const char *subdir); 
#endif

#endif /* INCLUDED_PBC_MYCONF_H */

