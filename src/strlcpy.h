/*
  Copyright (c) 1999-2005 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
  $Id: strlcpy.h,v 1.7 2005-01-03 23:15:06 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy (char *dst, const char *src, size_t len);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat (char *dst, const char *src, size_t len);
#endif
