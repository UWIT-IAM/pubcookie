/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
    $Id: pbc_version.h,v 1.60 2004-07-29 23:30:45 dors Exp $
 */

#ifndef PUBCOOKIE_VERSION
#define PUBCOOKIE_VERSION

/* The cookie version - Needs to stick around a while */
#define PBC_VERSION "a5"

/*
 * Someday the cookie version will be the major version or something like that.
 */

#define PBC_VERSION_MAJOR "3"
#define PBC_VERSION_MINOR "1"
#define PBC_VERSION_PATCH "1"

/* beta or final, so the code knows what it is, should it care. */
#define PBC_VERSION_RELEASE "final"

/*
 * Please note that if you change the version string here, you should change it
 * in configure.ac and re-run autoconf and autoheader.
 * This is _exactly_ the same as PACKAGE_VERSION in configure.  At some point
 * configure should probably set this.
 */

#define PBC_VERSION_STRING "3.1.1"

#endif /* !PUBCOOKIE_VERSION */
