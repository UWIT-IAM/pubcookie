# Process this file with autoconf to produce a configure script.

AC_REVISION($Revision: 1.21 $)
AC_INIT(Pubcookie, [3.0.0 pre-beta4], pubcookie-dev@u.washington.edu)
AC_CONFIG_SRCDIR([src/libpubcookie.c])
AC_CONFIG_HEADER([src/config.h])

# Set default prefix to /usr/local/pubcookie
AC_PREFIX_DEFAULT(/usr/local/pubcookie)

AC_MSG_NOTICE([Configuring for $PACKAGE_STRING])

if test "x$enable_apache" = "x"; then
    enable_apache=yes
fi

# Before any tests, check to see if we are doing anything..

AC_MSG_CHECKING([If I should build the apache module..])
AC_ARG_ENABLE(apache,
              AC_HELP_STRING([--enable-apache],
                             [Enable building the apache module (default: on)]),
              [ case "${enableval}" in
                yes)
                   AC_MSG_RESULT(yes)
                   AC_SUBST(apache_module, "apache_module")
                   AC_SUBST(install_apache, "install-apache")
                   ;;
                *)
                   AC_MSG_RESULT(no)
                   enable_apache=no
                   AC_SUBST(MAKE_APACHE, "@echo Skipping ")
                   ;;
               esac ])

if test "x$enable_login" = "x"; then
    enable_login=no
fi

AC_MSG_CHECKING([If I should build the login cgi..])
AC_ARG_ENABLE(login,
              AC_HELP_STRING([--enable-login],
                             [Enable building the login cgi (default: off)]),
              [ case "${enableval}" in
                yes)
                   AC_MSG_RESULT(yes)
                   enable_login=yes
                   AC_SUBST(login_server, "login_server")
                   AC_SUBST(install_login, "install-login")
                   ;;
                *)
                   AC_MSG_RESULT(no)
                   AC_SUBST(MAKE_LOGIN, "@echo Skipping ")
                   ;;
               esac ])

if test "$enable_login" = "no" && test "$enable_apache" = "no"; then
    AC_MSG_ERROR([the login server or apache module must be enabled], 1)
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_AWK

# Utilities
AC_PATH_PROG(AR, ar, ar)
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(SED, sed, sed)
AC_PATH_PROG(TAR, tar, tar)
AC_PATH_PROG(GZIP, gzip, gzip)
AC_PATH_PROG(MKDIR, mkdir, mkdir)
AC_PATH_PROG(MV, mv, mv)


if test "$enable_apache" = "yes"; then

if test "x$with_apxs" = "x"; then
    with_apxs=no
fi

AC_ARG_WITH(apxs,
    AC_HELP_STRING([--with-apxs=PATH],[/path/to/apxs]),
[ case "$withval" in
   no)
      OLDPATH=$PATH
      PATH="/usr/local/apache/bin:/usr/www/bin:/usr/sbin:$PATH"
      AC_PATH_PROG(APXS, apxs)
      PATH=$OLDPATH
      ;;
    *)
      OLDPATH=$PATH
      PATH="$withval:$PATH"
      AC_PATH_PROG(APXS, apxs)
      PATH=$OLDPATH
      ;;
  esac ])

fi # If they disabled apache, don't look for apxs.

# Checks for libraries.
AC_CHECK_LIB(socket,socket)
AC_CHECK_LIB(nsl,gethostent)
AC_CHECK_LIB(dl,dlopen)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h shadow.h stdlib.h \
                  string.h strings.h sys/param.h sys/socket.h sys/time.h \
                  unistd.h getopt.h ctype.h stdarg.h stdio.h varargs.h\
                  sys/utsname.h time.h pwd.h sys/types.h assert.h sys/stat.h \
                  sysexits.h mgoapi.h securid.h sys/resource.h fnmatch.h])

AC_CHECK_HEADER([syslog.h], 
    AC_DEFINE(HAVE_SYSLOG_H, 1,
              [Define to 1 if you have the <syslog.h> header file.])
    AC_MSG_CHECKING([for LOG_AUTHPRIV in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #include <syslog.h>
                ], [ printf( "%d", LOG_AUTHPRIV ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_LOG_AUTHPRIV, 1,
                              [Define to LOG_AUTH if your system doesn't define LOG_AUTHPRIV])])
    AC_MSG_CHECKING([for LOG_MAKEPRI in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #include <syslog.h>
                ], [ printf( "%d", LOG_MAKEPRI(1,2) ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_LOG_MAKEPRI, 1,
                              [Define to 1 if your system doesn't define LOG_MAKEPRI])])
    AC_MSG_CHECKING([for LOG_FAC in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #include <syslog.h>
                ], [ printf( "%d", LOG_FAC(1) ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_LOG_FAC, 1,
                              [Define to 1 if your system doesn't define LOG_FAC])])
    AC_MSG_CHECKING([for facilitynames in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #define SYSLOG_NAMES 1
                 #include <syslog.h>
                ], 
                [ printf( "%p", facilitynames ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_SYSLOG_NAMES, 1,
                              [Define to 1 if your system doesn't have SYSLOG_NAMES])])
    )

AC_MSG_CHECKING([audit log facility])
AC_ARG_WITH(audit-log,
            AC_HELP_STRING([--with-audit-log=facility],
                           [syslog() facility of audit messages
                            (default: LOG_AUTHPRIV)]),
            AC_MSG_RESULT($withval)
            [AC_DEFINE_UNQUOTED(PBC_LOG_AUDIT_FACILITY, $withval,
                       [Define to the AUDIT syslog() facility])],
            AC_MSG_RESULT(LOG_AUTHPRIV)
            [AC_DEFINE(PBC_LOG_AUDIT_FACILITY, LOG_AUTHPRIV,
                       [Define to the AUDIT syslog() facility])],
                       )

AC_MSG_CHECKING([general log facility])
AC_ARG_WITH(general-log,
            AC_HELP_STRING([--with-general-log=facility],
                           [syslog() facility of general messages
                            (default: LOG_AUTHPRIV)]),
            AC_MSG_RESULT($withval)
            [AC_DEFINE_UNQUOTED(PBC_LOG_GENERAL_FACILITY, $withval,
                       [Define to the GENERAL syslog() facility])],
            AC_MSG_RESULT(LOG_AUTHPRIV)
            [AC_DEFINE(PBC_LOG_GENERAL_FACILITY, LOG_AUTHPRIV,
                       [Define to the GENERAL syslog() facility])],
                       )


# OpenSSL Fun

AC_ARG_WITH(ssl-dir,
    AC_HELP_STRING([--with-ssl-dir=PATH], [Openssl lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(ssl-inc-dir,
    AC_HELP_STRING([--with-ssl-inc-dir=PATH], [Openssl include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(ssl-lib-dir,
    AC_HELP_STRING([--with-ssl-lib-dir=PATH], [Openssl lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

AC_CHECK_LIB(crypto,ERR_load_ASN1_strings)
AC_CHECK_LIB(ssl,SSL_library_init)
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

OLDLIBS=$LIBS


if test "$enable_login" = yes; then

    CPPFLAGS="$CPPFLAGS -I$srcdir/cgic/"
    LDFLAGS="$LDFLAGS -L\$(builddir)/cgic/"

AC_CHECK_HEADERS([cgic.h])
    LIBS="$LIBS -lcgic"

AC_ARG_ENABLE(krb5,
    AC_HELP_STRING([--enable-krb5],[Enable Kerberos 5 Verifier]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_KRB5, 1, [Define to 1 to support krb5 verifiers])
    ;;
  esac ])

if test "$enable_krb5" = "yes"; then

# Find the KRB5 Libraries!

# RetHat seems to put KRB5 in /usr/kerberos

if test -d "/usr/kerberos/include"; then
    CPPFLAGS="$CPPFLAGS -I/usr/kerberos/include"
fi

if test -d "/usr/kerberos/lib"; then
    LDFLAGS="$LDFLAGS -L/usr/kerberos/lib"
fi

AC_ARG_WITH(krb5-dir,
    AC_HELP_STRING([--with-krb5-dir=PATH], [KRB5 lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(krb5-inc-dir,
    AC_HELP_STRING([--with-krb5-inc-dir=PATH], [KRB5 include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(krb5-lib-dir,
    AC_HELP_STRING([--with-krb5-lib-dir=PATH], [KRB5 lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

    AC_CHECK_HEADERS([com_err.h krb5.h])
    AC_CHECK_LIB(krb5, krb5_init_context)
fi

AC_ARG_ENABLE(ldap,
    AC_HELP_STRING([--enable-ldap],[Enable LDAP Verifier]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_LDAP, 1, [Define to 1 to support LDAP verifiers])
    ;;
  esac ])

# This is OpenLDAP Specific.  If I was cool, I would detect OpenLDAP vs the
# Netscape LDAP SDK, but I'm not that cool.
  
if test "$enable_ldap" = "yes"; then

# Find the LDAP Libraries!

AC_ARG_WITH(ldap-dir,
    AC_HELP_STRING([--with-ldap-dir=PATH], [LDAP lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(ldap-inc-dir,
    AC_HELP_STRING([--with-ldap-inc-dir=PATH], [LDAP include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(ldap-lib-dir,
    AC_HELP_STRING([--with-ldap-lib-dir=PATH], [LDAP lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

    AC_CHECK_HEADERS([lber.h])
    AC_CHECK_HEADERS([ldap.h])
    AC_CHECK_LIB(lber, ber_init)
    AC_CHECK_LIB(ldap, ldap_init)
fi

AC_ARG_ENABLE(shadow,
    AC_HELP_STRING([--enable-shadow],[Enable Shadow Verifier ]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_SHADOW, 1, [Define to 1 to support shadow verifiers])
    ;;
  esac ])

if test "$enable_shadow" = "yes"; then
    AC_CHECK_HEADERS([shadow.h crypt.h])
    AC_CHECK_LIB(crypt, crypt)
fi

AC_ARG_ENABLE(dmalloc,
    AC_HELP_STRING([--enable-dmalloc],[Enable dmalloc debugging]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_DMALLOC, 1, [Define to 1 to enable dmalloc debugging])
    ;;
  esac ])

if test "$enable_dmalloc" = "yes"; then
    AC_CHECK_HEADERS([dmalloc.h],,,[ ])
    AC_CHECK_LIB(dmalloc, dmalloc_shutdown)

    if test "x$GCC" = "x"; then
        OLDCC=$CC
        CC="$CC -Xc"
        AC_TRY_COMPILE( [], [], [], CC=$OLDCC )
    fi
fi

fi # End of stuff we skip if we're not enabling the login server.

LOGINLIBS=$LIBS

LIBS=$OLDLIBS

AC_SUBST(LOGINLIBS, $LOGINLIBS)

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
                strstr uname strlcpy strlcat snprintf vsnprintf])

AC_CONFIG_FILES([Makefile src/pbc_path.h cgic/Makefile])
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])
AC_OUTPUT
