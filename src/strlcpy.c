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

    strlcat/strlcpy compatibility

 */

/*
    $Id: strlcpy.c,v 2.5 2002-11-14 21:12:12 jjminer Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#ifndef HAVE_STRLCPY
/* strlcpy -- copy string smartly.
 *
 * i believe/hope this is compatible with the BSD strlcpy(). 
 */
size_t strlcpy(char *dst, const char *src, size_t len)
{
    size_t n;

    /* Avoid problems if size_t is unsigned */
    if(len == 0) return strlen(src);
    
    for (n = 0; n < len-1; n++) {
	if ((dst[n] = src[n]) == '\0') break;
    }
    if (src[n] != '\0') {
	/* ran out of space */
	dst[n] = '\0';
	while(src[n]) n++;
    }
    return n;
}
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t len)
{
    size_t i, j, o;
    
    o = strlen(dst);
    if (len < o + 1)
	return o + strlen(src);
    len -= o + 1;
    for (i = 0, j = o; i < len; i++, j++) {
	if ((dst[j] = src[i]) == '\0') break;
    }
    dst[j] = '\0';
    if (src[i] == '\0') {
	return j;
    } else {
	return j + strlen(src + i);
    }
}
#endif
