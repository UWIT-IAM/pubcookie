/*
  Copyright (c) 1999-2003 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
  $Id: strlcpy.h,v 1.4 2003-05-06 23:51:19 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t len);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t len);
#endif
