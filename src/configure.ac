# Process this file with autoconf to produce a configure script.

AC_REVISION($Revision: 2.2 $)
AC_INIT(Pubcookie, 3.0beta, pubcookie-dev@blah)
AC_CONFIG_SRCDIR([libpubcookie.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_AWK

# Set default prefix to /usr/local/pubcookie
AC_PREFIX_DEFAULT(/usr/local/pubcookie)

# Utilities
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(SED, sed, sed)
AC_PATH_PROG(TAR, tar, tar)
AC_PATH_PROG(GZIP, gzip, gzip)
AC_PATH_PROG(MKDIR, mkdir, mkdir)
AC_PATH_PROG(MV, mv, mv)

# Checks for libraries.
AC_CHECK_LIB(socket,socket)
AC_CHECK_LIB(nsl,gethostent)
AC_CHECK_LIB(dl,dlopen)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h shadow.h stdlib.h \
                  string.h strings.h sys/param.h sys/socket.h sys/time.h \
                  syslog.h unistd.h getopt.h ctype.h stdarg.h stdio.h \
                  sys/utsname.h time.h pwd.h sys/types.h assert.h sys/stat.h \
                  sysexits.h mgoapi.h securid.h sys/resource.h])

# OpenSSL Fun

AC_ARG_WITH(ssl-dir,
[  --with-ssl-dir=PATH    Openssl lib/include root],
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(ssl-inc-dir,
[  --with-ssl-inc-dir=PATH    Openssl include path],
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(ssl-lib-dir,
[  --with-ssl-lib-dir=PATH    Openssl lib path],
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

AC_CHECK_LIB(ssl,SSL_library_init)
AC_CHECK_LIB(crypto,ERR_load_ASN1_strings)
AC_CHECK_HEADERS([openssl/ssl.h])

if test "$ac_cv_header_openssl_ssl_h" = "yes"; then
    AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/err.h openssl/rand.h openssl/des.h])
    AC_DEFINE(OPENSSL_IN_DIR, 1, [Define to 1 if openssl is in include/openssl])
else
    AC_CHECK_HEADERS([crypto.h x509.h pem.h ssl.h err.h rand.h des.h])
    AC_DEFINE(OPENSSL_NOT_IN_DIR, 1,
              [Define to 1 if openssl is directly in the include path.])
fi

# Login Server specific stuff.
# This needs to be set up to not change the LIBS variable, it needs to be
# AC_SUBST'd somewhere login server specific.

OLDLIBS=$LIBS
OLDLDFLAGS=$LDFLAGS
OLDCPPFLAGS=$CPPFLAGS
OLDCFLAGS=$CFLAGS

AC_ARG_WITH(cgic-dir,
[  --with-cgic-dir=PATH     CGIC lib/include directory],
[ case "$withval" in
   no)
    ;;
   *)
    CPPFLAGS="$CPPFLAGS -I$withval"
    LDFLAGS="$LDFLAGS -L$withval"
    ;;
  esac ])

AC_CHECK_HEADERS([cgic.h])

if test "$ac_cv_header_cgic_h"; then
    LIBS="$LIBS -lcgic"
fi

AC_ARG_ENABLE(krb5,
[  --enable-krb5    Enable Kerberos 5 Verifier ],
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_KRB5, 1, [Define to 1 to support krb5 verifiers])
    ;;
  esac ])

if test "$enable_krb5" = "yes"; then
    AC_CHECK_HEADERS([com_err.h krb5.h])
    AC_CHECK_LIB(krb5, krb5_init_context)
fi

AC_ARG_ENABLE(ldap,
[  --enable-ldap    Enable LDAP Verifier ],
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_LDAP, 1, [Define to 1 to support LDAP verifiers])
    ;;
  esac ])

# This is OpenLDAP Specific.  If I was cool, I would detect OpenLDAP vs the
# Netscape LDAP SDK, but I'm not that cool.
  
if test "$enable_ldap" = "yes"; then
    AC_CHECK_HEADERS([lber.h])
    AC_CHECK_HEADERS([ldap.h])
    AC_CHECK_LIB(lber, ber_init)
    AC_CHECK_LIB(ldap, ldap_init)
fi

AC_ARG_ENABLE(shadow,
[  --enable-shadow    Enable Shadow Verifier ],
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_SHADOW, 1, [Define to 1 to support shadow verifiers])
    ;;
  esac ])

if test "$enable_shadow" = "yes"; then
    AC_CHECK_HEADERS([shadow.h crypt.h])
fi

LOGINLIBS=$LIBS
LOGINLDFLAGS=$LDFLAGS
LOGINCPPFLAGS=$CPPFLAGS
LOGINCFLAGS=$CFLAGS

LIBS=$OLDLIBS
LDFLAGS=$OLDLDFLAGS
CPPFLAGS=$OLDCPPFLAGS
CFLAGS=$OLDCFLAGS

AC_SUBST(LOGINLIBS, $LOGINLIBS)
AC_SUBST(LOGINCPPFLAGS, $LOGINCPPFLAGS)
AC_SUBST(LOGINCFLAGS, $LOGINCFLAGS)
AC_SUBST(LOGINLDFLAGS, $LOGINLDFLAGS)

# End of Login-server specific stuff, hopefully.

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero dup2 gethostbyname gethostname getspnam gettimeofday \
                memset socket strcasecmp strchr strdup strerror strncasecmp \
                strstr uname strlcpy strlcat])

AC_CONFIG_FILES([Makefile Makefile.settings Makefile.login])
AC_OUTPUT
