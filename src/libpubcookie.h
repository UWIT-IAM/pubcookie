/*
    $Id: libpubcookie.h,v 1.1 1998-06-25 03:00:58 willey Exp $
 */

#ifndef PUBCOOKIE_LIB
#define PUBCOOKIE_LIB


char *libpbc_get_cookie(char *, int, int creds, char *, char *, context_plus *);
pbc_cookie_data *libpbc_unbundle_cookie(char *, context_plus *);
int libpbc_init_cookie(pbc_cookie_data *);
int libpbc_abend(const char *,...);
int libpbc_debug(const char *,...);
context_plus *libpbc_sign_init();
context_plus *libpbc_verify_init();

#endif /* !PUBCOOKIE_LIB */
