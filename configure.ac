# Process this file with autoconf to produce a configure script.

AC_REVISION($Revision: 1.52 $)
AC_INIT(Pubcookie, [3.0.1 pre-beta2], pubcookie-dev@u.washington.edu)
AC_CONFIG_SRCDIR([src/libpubcookie.c])
AC_CONFIG_HEADER([src/config.h])
AC_LANG(C)

# Set default prefix to /usr/local/pubcookie
AC_PREFIX_DEFAULT(/usr/local/pubcookie)

AC_MSG_NOTICE([Configuring for $PACKAGE_STRING])

if test "x$enable_apache" = "x"; then
    enable_apache=yes
fi

# Before any tests, check to see if we are doing anything..

AC_MSG_CHECKING([if I should build the apache module])
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

if test "x$enable_apache_static" = "x"; then
    enable_apache_static=no
fi

AC_MSG_CHECKING([if I should build the static apache module])

AC_ARG_ENABLE(apache-static,
              AC_HELP_STRING( [--enable-apache-static],
                              [Enable building the static apache module
                              (default: off)]),
              [ case "${enableval}" in
                yes)
                   AC_MSG_RESULT(yes)
                   ;;
                *)
                   AC_MSG_RESULT(no)
                   enable_apache_static=no
                   ;;
                esac ])

if test "x$enable_login" = "x"; then
    enable_login=no
fi

AC_MSG_CHECKING([if I should build the login cgi])
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

if test "$enable_login" = "no" && \
   test "$enable_apache" = "no" && \
   test "$enable_apache_static" = "no"; then
    AC_MSG_ERROR([the login server or apache module must be enabled], 1)
fi

# Checks for programs.
AC_PROG_CC

AC_AIX

# For whatever reason AIX needs a list of exported symbols.
AC_CANONICAL_HOST
APXS_LDFLAGS=

case $host in
    *aix*)
# Check for IBM xlc compiler.

if test "$GCC" != "yes"; then

AC_MSG_CHECKING([for IBM xlc Compiler])
AC_TRY_RUN( [ 
    #include <stdlib.h>

    #ifndef __xlC__
    # define __xlC__ 0
    #endif

    int main() {
        exit( __xlC__ == 0 );
    }
    ],
    [ AC_MSG_RESULT([yes])
    APXS_LDFLAGS="-Wl,-bE:mod_pubcookie.exp"
    AC_DEFINE( IBM_XLC, 1,
    [Define to 1 if the Compiler is IBM xlc] )
    IBM_XLC=1
    ],
    [ AC_MSG_RESULT([no])
    ]
)

fi

aix_system=yes
    ;;
    *sun*)
# Check to see if this is the Sun Workshop compiler.

if test "$GCC" != "yes"; then

AC_MSG_CHECKING([for Sun Workshop Compiler])
AC_TRY_RUN( [ 
    #include <stdlib.h>

    #ifndef __SUNPRO_C
    # define __SUNPRO_C 0
    #endif

    int main() {
        exit( __SUNPRO_C == 0 );
    }
    ],
    [ AC_MSG_RESULT([yes])
    AC_DEFINE( SUN_WORKSHOP, 1,
    [Define to 1 if the Compiler is Sun Workshop] )
    SUN_WORKSHOP=1
    ],
    [ AC_MSG_RESULT([no])
    ]
)

fi
    ;;
esac

if test "$aix_system" != "yes"; then
    AC_SUBST( IF_AIX, [#] )
fi;

AC_SUBST(APXS_LDFLAGS, "$APXS_LDFLAGS")

# Fix problems where we're using gcc without gnu ld
# (Code by Bradford L. Barrett at University of Florida)
if test "$GCC" = "yes"; then
    GCC_LIB=`gcc -print-libgcc-file-name`
    LIBS="$LIBS -lgcc";
    LDFLAGS="$LDFLAGS -L`dirname $GCC_LIB`"
fi

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
AC_PATH_PROG(CHMOD, chmod, chmod)
AC_PATH_PROG(TEST, test, test)
AC_PATH_PROG(MAKE, make)
AC_PATH_PROG(GMAKE, gmake)

gnu_make=no

if test "x$MAKE" != "x"; then
    AC_MSG_CHECKING( [if $MAKE is GNU make] )
    $MAKE --version > /dev/null 2>&1
    if test "$?" != "0"; then
        AC_MSG_RESULT([no])
        gnu_make=no
    else
        AC_MSG_RESULT([yes])
        gnu_make=yes
    fi
fi

if test "$aix_system" = "yes" && \
   test "x$GMAKE" = "x" && \
   test "$gnu_make" = "no"; then
    AC_SUBST( IF_AIX_MAKE, "" )
else
    AC_SUBST( IF_AIX_MAKE, [#] )
fi

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
      if test -d "$withval"; then
          PATH="$withval:$PATH"
          AC_PATH_PROG(APXS, apxs)
      else 
          PATH=`dirname $withval`":$PATH"
          PROG=`basename $withval`
          AC_PATH_PROG(APXS, $PROG)
      fi
      PATH=$OLDPATH
      ;;
  esac ])

  if test "x$APXS" = "x"; then
      AC_MSG_ERROR( "apxs is required for building mod_pubcookie!" )
  fi
  AC_MSG_CHECKING( [if $APXS works] )
  $APXS -q CFLAGS >/dev/null 2>&1
  if test "$?" != "0"; then
      AC_MSG_RESULT([no])
      AC_MSG_RESULT([Here is the output from $APXS:])
      $APXS -q CFLAGS
      AC_MSG_ERROR([Please correct this error and try again.])
  fi

  AC_MSG_RESULT([yes])

  AC_MSG_CHECKING([Apache version])
  APACHE_VERSION=
  OCFLAGS=$CFLAGS
  APXS_INC=`$APXS -q INCLUDEDIR`
  CFLAGS="$CFLAGS -I$APXS_INC"
  AC_TRY_RUN( [ 
    /* Look for 1.x version */
    #include <stdlib.h>
    #include <httpd.h>

    int main() {
        exit( ( APACHE_RELEASE > 10300000 &&
                APACHE_RELEASE < 10400000 ) != 1 );
    }
    ],
      [APACHE_VERSION="1_3"
       APACHE_MOD_EXT="so"],
    [ 
    ]
  )
  if test "x$APACHE_VERSION" = "x"; then
    AC_TRY_RUN( [ 
      /* Look for 2.x version */
      #include <stdlib.h>
      #include <httpd.h>

      int main() {
          exit( *AP_SERVER_MAJORVERSION!='2');
      }
      ],
        [APACHE_VERSION="2"
         APACHE_MOD_EXT="la"],
      [ 
        AC_MSG_ERROR([Apache version 1.3.x or 2.x is required!])
      ]
    )
  fi
  AC_MSG_RESULT([$APACHE_VERSION])
  AC_SUBST(APACHE_VERSION, $APACHE_VERSION)
  AC_SUBST(APACHE_MOD_EXT, $APACHE_MOD_EXT)

  CFLAGS=$OCFLAGS

  AC_MSG_CHECKING( [if we are upgrading mod_pubcookie] )
  if test -f `$APXS -q LIBEXECDIR`"/mod_pubcookie.so"; then
      AC_MSG_RESULT([yes])
      AC_SUBST( IF_MODULE_UPGRADE, "" )
  else
      AC_MSG_RESULT([no])
      AC_SUBST( IF_MODULE_UPGRADE, [#] )
  fi

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
                  sysexits.h mgoapi.h sys/resource.h fnmatch.h \
                  errno.h ])

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

ssl_include_path=
ssl_lib_path=
ssl_openssl=openssl

AC_ARG_WITH(ssl,
    AC_HELP_STRING([--with-ssl=PATH], [Openssl lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_include_path="-I$withval/include"
     ssl_lib_path="-L$withval/lib"
     ssl_openssl="$withval/bin/openssl"
     ;;
  esac ])

AC_ARG_WITH(ssl-dir,
    AC_HELP_STRING([--with-ssl-dir=PATH], [Openssl lib/include root (deprecated)]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_include_path="-I$withval/include"
     ssl_lib_path="-L$withval/lib"
     ssl_bin_path="$withval/bin/openssl"
     ;;
  esac ])

AC_ARG_WITH(ssl-inc-dir,
    AC_HELP_STRING([--with-ssl-inc-dir=PATH], [Openssl include path]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_include_path="-I$withval"
     ;;
  esac ])

AC_ARG_WITH(ssl-lib-dir,
    AC_HELP_STRING([--with-ssl-lib-dir=PATH], [Openssl lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_lib_path="-L$withval"
     ;;
  esac ])

if test "x$ssl_include_path" = "x" -a -d "/usr/local/ssl/include"; then
    ssl_include_path="-I/usr/local/ssl/include"
fi

if test "x$ssl_include_path" = "x" -a -d "/usr/include/openssl"; then
    ssl_include_path="-I/usr/include/openssl"
fi

if test "x$ssl_lib_path" = "x" -a -d "/usr/local/ssl/lib"; then
    ssl_lib_path="-L/usr/local/ssl/lib"
fi

if test "x$ssl_include_path" != "x"; then
    CPPFLAGS="$CPPFLAGS $ssl_include_path"
fi

if test "x$ssl_lib_path" != "x"; then
    LDFLAGS="$LDFLAGS $ssl_lib_path"
fi

# Look for openssl krb5 includes

AC_MSG_CHECKING([for openssl krb5 includes])
vfi=
vfa=
for vf in `$ssl_openssl version -f`
do
    case $vf in
      -I*) vfi="$vfi $vf"
           ;;
    esac
    vfa="yes"
done
if test "x$vfi" != "x" ; then
    CPPFLAGS="$CPPFLAGS $vfi"
    AC_MSG_RESULT([$vfi])
else
    if test "x$vfa" != "x"; then
       AC_MSG_RESULT([none])
    else
       AC_MSG_WARN([could not run openssl to find includes])
    fi
fi


AC_CHECK_LIB(crypto,ERR_load_ASN1_strings,,
             AC_MSG_ERROR([libcrypto is required.]))
AC_CHECK_LIB(ssl,SSL_library_init,,
             AC_MSG_ERROR([libssl is required.]))
AC_CHECK_HEADERS([openssl/ssl.h])

if test "$ac_cv_header_openssl_ssl_h" = "yes"; then
     AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/err.h openssl/rand.h openssl/des.h], 
	[AC_DEFINE(OPENSSL_IN_DIR, 1, 
		 [Define to 1 if openssl is in include/openssl])],
		[AC_MSG_ERROR([can't find required SSL header files (may need --with-ssl-inc-dir)])])
else
     AC_CHECK_HEADERS([crypto.h x509.h pem.h err.h rand.h des.h], 
	[AC_DEFINE(OPENSSL_NOT_IN_DIR, 1, 
		 [Define to 1 if openssl is directly in include path.])],
		[AC_MSG_ERROR([can't find required SSL header files (may need --with-ssl-inc-dir)])])
fi

# Login Server specific stuff.

OLDLIBS=$LIBS


if test "$enable_login" = yes; then

    CPPFLAGS="$CPPFLAGS -I$srcdir/cgic/"
    LDFLAGS="$LDFLAGS -L\$(builddir)/cgic/"

AC_CHECK_HEADERS([cgic.h], AC_SUBST(CGIC_LIB, "-lcgic"))

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

# check to see if we're using Heimdal Kerberos
# thanks to Leif Johansson <leifj@it.su.se>
# and Love Hörnquist Åstrand <lha@it.su.se>
AC_CHECK_TYPE([krb5_addresses], 
  AC_DEFINE(KRB5_HEIMDAL, 1, [set to 1 if using Heimdal Kerberos]), 
  ,
  [#include <krb5.h>])

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
    AC_CHECK_HEADERS([ldap.h],,,[#include <lber.h>])

    AC_MSG_CHECKING([if LDAP API is OpenLDAP])
    AC_TRY_RUN( [ 
    #include <ldap.h>

    int main() {
        exit( strcmp(LDAP_VENDOR_NAME, "OpenLDAP") );
    }
                ],
                [ AC_MSG_RESULT([yes])
                  AC_DEFINE( LDAP_OPENLDAP, 1,
                             [Define to 1 if the LDAP library is OpenLDAP] )
                  LDAP_OPENLDAP=1
                ],
                [ AC_MSG_RESULT([no])
                  AC_MSG_WARN( "Warning: No OpenLDAP API found." ) 
                  LDAP_OPENLDAP=0
                ],
                AC_MSG_WARN( "Cross-Compiling not supported."  ) )

    if test "$LDAP_OPENLDAP" = "1"; then
        AC_CHECK_LIB(lber, ber_init)
        AC_CHECK_LIB(ldap, ldap_init)
    else

        AC_MSG_CHECKING([if LDAP API is Sun/Netscape/iPlanet])
        AC_TRY_RUN( [ 
        #include <lber.h>
        #include <ldap.h>

        int main() {

        if ( (strcmp(LDAP_VENDOR_NAME, "Sun Microsystems Inc.") == 0)
            && LDAP_VENDOR_VERSION >= 508 )
            exit(0);

            exit(2);
        }
                    ],
                    [ AC_MSG_RESULT([yes])
                    AC_MSG_WARN( "Warning: Non-OpenLDAP API found.  YMMV." ) 
                    AC_DEFINE( LDAP_SUN, 1,
                    [Define to 1 if the LDAP library is Sun/Netscape/iPlanet] )
                    LDAP_SUN=1
                    ],
                    [ AC_MSG_RESULT([no])
                    LDAP_SUN=0
                    ],
                    AC_MSG_WARN( "Cross-Compiling not supported."  ) )


        if test "$LDAP_SUN" = "1"; then
            AC_CHECK_HEADERS([ldap_ssl.h ldappr.h],,,
            [ #include <lber.h>
              #include <ldap.h>
            ])
            AC_CHECK_LIB(ldap50, ldap_init)
            AC_CHECK_LIB(ssl3, SSL_AuthCertificate)
            AC_CHECK_LIB(nss3, CERT_VerifyCert)
            AC_CHECK_LIB(prldap50, prldap_init)
            AC_CHECK_LIB(ssldap50, ldapssl_init)

            if test "x$with_cert_db_path" = "x"; then
                with_cert_db_path=no
            fi

            AC_MSG_CHECKING([for cert7.db and key3.db path])
            AC_ARG_WITH(cert-db-path,
                        AC_HELP_STRING([--with-cert-db-path=PATH],
                        [cert7 and key3 db path (from a Netscape installation)]),
            [ case "$withval" in
            no)
            AC_MSG_ERROR([with-cert-db-path must be specified with Sun SDK.], 1)
            ;;
            *)
            AC_SUBST(CERT_DB_PATH, "$withval")
            AC_MSG_RESULT($withval)
            ;;
        esac ])
    fi
fi

    # For now, Blow up if we aren't using OpenLDAP.

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

AC_ARG_ENABLE(uwsecurid,
    AC_HELP_STRING([--enable-uwsecurid],[Enable U. Wash. SecurID Verifier ]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_UWSECURID, 1, [Define to 1 to support U. Wash. SecurID verifiers])
    ;;
  esac ])

if test "$enable_uwsecurid" = "yes"; then

# Find the mango Libraries!

if test -d "/usr/local/include"; then
    CPPFLAGS="$CPPFLAGS -I/usr/local/include"
fi

if test -d "/usr/local/lib"; then
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

AC_ARG_WITH(mango-inc-dir,
    AC_HELP_STRING([--with-mango-inc-dir=PATH], [U WASH ONLY: Mango include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(mango-lib-dir,
    AC_HELP_STRING([--with-mango-lib-dir=PATH], [U WASH ONLY: Mango lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

    AC_CHECK_HEADERS([mgoapi.h mgostuff.h])
    LIBS="$LIBS -lmgoapi";
    AC_CHECK_LIB(mgoapi)
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


    if test "x$SUN_WORKSHOP" != "x"; then
        # Sun Workshop Compiler is annoying!
        OLDCC=$CC
        CC="$CC -Xc"
        OLDCPPFLAGS=$CPPFLAGS
        CPPFLAGS="$CPPFLAGS -D__EXTENSIONS__"
        AC_TRY_COMPILE( [], [], [], [
            CC=$OLDCC
            CPPFLAGS=$CPPFLAGS
            ]
        )
    fi

fi

AC_ARG_WITH(fcgi,
    AC_HELP_STRING([--with-fcgi=PATH],[Build for fastcgi ]),
[ case "${withval}" in
   no)
    ;;
   *)
    CPPFLAGS="$CPPFLAGS -I$withval/include -DWITH_FCGI"
    LIBS="$LIBS -lfcgi"
    LDFLAGS="$LDFLAGS -L$withval/lib"
    ;;
  esac ])

if test "$enable_shadow" = "yes"; then
    AC_CHECK_HEADERS([shadow.h crypt.h])
    AC_CHECK_LIB(crypt, crypt)
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
# AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero dup2 gethostbyname gethostname getspnam gettimeofday \
                memset socket strcasecmp strchr strdup strerror strncasecmp \
                strstr uname strlcpy strlcat bcopy])

AC_CHECK_FUNCS( [snprintf vsnprintf],, [
SNPRINTF_O="\$(builddir)/src/snprintf.o"
SNPRINTF_C="\$(srcdir)/src/snprintf.c"
] )

AC_SUBST( SNPRINTF_0, $SNPRINTF_O )
AC_SUBST( SNPRINTF_C, $SNPRINTF_C )

AM_MAINTAINER_MODE

AC_CONFIG_FILES([Makefile src/pbc_path.h cgic/Makefile])
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])
AC_OUTPUT

if test "x$GMAKE" = "x" && \
   test "$gnu_make" = "no"; then
   AC_MSG_WARN([
   $MAKE is not GNU make and gmake was not found on your system.
   You may have problems compiling.
   Please let $PACKAGE_BUGREPORT know if you have a fix.
   ])
fi
if test "x$GMAKE" != "x" && \
   test "$gnu_make" = "no"; then
    AC_MSG_WARN([
    I found make and gmake on your system and
    $MAKE doesn't seem to be GNU Make.
    For best results please use $GMAKE.
    ])
fi
