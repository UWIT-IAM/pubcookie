/*

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is a pubcookie include file for macros that define the 
    way the pubcookie module does stuff

    logic for how the pubcookie include files are devided up:
       libpubcookie.h: only stuff used in library
       pubcookie.h: stuff used in the module and library
       pbc_config.h: stuff used in the module and library that 
            people might want to change, as far a local configuration
       pbc_version.h: only version stuff

 */

/*
    $Id: pbc_config.h,v 1.71 2002-11-19 00:48:15 ryanc Exp $
 */

#ifndef PUBCOOKIE_CONFIG
#define PUBCOOKIE_CONFIG

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if defined (APACHE1_3)
#define APACHE
#endif

#include "pbc_myconfig.h" 

#ifdef WIN32
#  define PBC_KEY_DIR (AddSystemRoot("\\inetsrv\\pubcookie\\keys"))
#else
#  include "pbc_path.h"
#endif


#ifdef HAVE_DMALLOC_H
# ifndef APACHE
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/* names of the login servers */
#define PBC_LOGIN_HOST (libpbc_config_getstring("login_host", "weblogin.washington.edu"))
#define PBC_LOGIN_URI (libpbc_config_getstring("login_uri", "https://weblogin.washington.edu/"))
#define PBC_ENTRPRS_DOMAIN (libpbc_config_getstring("enterprise_domain", ".washington.edu"))

#if defined (WIN32)
	#define PBC_PUBLIC_NAME (libpbc_config_getstring("PUBLIC_dir_name", "PUBLIC")) 
	#define PBC_NETID_NAME (libpbc_config_getstring("NETID_dir_name", "UWNETID"))
	#define PBC_SECURID_NAME (libpbc_config_getstring("SECURID_dir_name", "SECURID"))
	#define PBC_DEFAULT_APP_NAME (libpbc_config_getstring("DEFAULT_APP_name", "defaultapp"))
	#define PBC_LEGACY_DIR_NAMES (libpbc_config_getint("LegacyDirNames", 1))
	#define PBC_DEBUG_TRACE (libpbc_config_getint("Debug_Trace", 0))
	#define PBC_IGNORE_POLL (libpbc_config_getint("Ignore_Poll", 0))
	#define PBC_DEBUG_DIR (libpbc_config_getstring("Debug_Dir", "\\LogFiles\\Pubcookie"))
	#define PBC_SYSTEM_ROOT (libpbc_config_getstring("System_Root","")) /*blank for Windows System*/
	#define PBC_AUTHTYPE0 (libpbc_config_getstring("AuthTypeName0", "NONE")) 
	#define PBC_AUTHTYPE1 (libpbc_config_getstring("AuthTypeName1", "UWNETID"))
	#define PBC_AUTHTYPE2 (libpbc_config_getstring("AuthTypeName2", "SECURID"))
	#define PBC_CRYPT_KEYFILE (PBC_PATH "c_key")
	#define PBC_PUBKEY "System\\CurrentControlSet\\Services\\PubcookieFilter"

#endif

#define PBC_REFRESH_TIME 0
#define PBC_MIN_INACT_EXPIRE 	      ( 5 * 60 )
#define PBC_DEFAULT_INACT_EXPIRE     ( 30 * 60 )
#define PBC_UNSET_INACT_EXPIRE                 0
#define PBC_MIN_HARD_EXPIRE 	 ( 1 * 60 * 60 )
#define PBC_MAX_HARD_EXPIRE 	( 12 * 60 * 60 )
#define PBC_DEFAULT_HARD_EXPIRE  ( 8 * 60 * 60 )
#define PBC_UNSET_HARD_EXPIRE                  0
#define PBC_DEFAULT_EXPIRE_LOGIN ( 8 * 60 * 60 )
#define PBC_GRANTING_EXPIRE               ( 60 )
#define PBC_BAD_AUTH 1
#define PBC_BAD_USER 2
#define PBC_FORCE_REAUTH 3

#define PBC_DEFAULT_DIRDEPTH 0

#define PBC_OK   1
#define PBC_FAIL 0
#define PBC_TRUE   1
#define PBC_FALSE  0

/* the cookies; l, g, and s have the same format g request and pre s
   are different internally
 */
/* the formmulti part will probably only hang around until will correctly
   handle form/multipart
 */
#define PBC_L_COOKIENAME "pubcookie_l"
#define PBC_G_COOKIENAME "pubcookie_g"
#define PBC_G_REQ_COOKIENAME "pubcookie_g_req"
#define PBC_S_COOKIENAME "pubcookie_s"
#define PBC_PRE_S_COOKIENAME "pubcookie_pre_s"
#define PBC_FORM_MP_COOKIENAME "pubcookie_formmultipart"
#define PBC_CRED_COOKIENAME "pubcookie_cred"
#define PBC_CRED_TRANSFER_COOKIENAME "pubcookie_transcred"

/* this apache module stuff should go into something like mod_pubcookie.h */
#define PBC_AUTH_FAILED_HANDLER "pubcookie-failed-handler"
#define PBC_BAD_USER_HANDLER "pubcookie-bad-user"
#define PBC_END_SESSION_REDIR_HANDLER "pubcookie-end-session-redir-handler"
#define PBC_STOP_THE_SHOW_HANDLER "pubcookie-stop-the-show-handler"

#define PBC_G_REQ_EXP (10 * 60)    /* shrug?  ten minutes? */
#define PBC_PRE_S_EXP (10 * 60)    /* shrug?  ten minutes? */

/* set in apache config to clear session cookie and redirect to weblogin */
#define PBC_END_SESSION_ARG_REDIR   "redirect"
#define PBC_END_SESSION_ARG_CLEAR_L "clearLogin"
#define PBC_END_SESSION_ARG_ON      "On"
#define PBC_END_SESSION_ARG_OFF     "Off"

#define PBC_END_SESSION_NOPE          0    /* no end session */
#define PBC_END_SESSION_ONLY          1    /* end session only */
#define PBC_END_SESSION_REDIR         2    /* end session, redirect to WLS */
#define PBC_END_SESSION_CLEAR_L       4    /* end session, redirect to WLS, 
                                              clear Login cookie */
#define PBC_END_SESSION_ANY           127  /* any of the above, except NONE */

#define LOGOUT_ACTION_UNSET          -1
#define LOGOUT_ACTION_NOTHING        0
#define LOGOUT_ACTION_CLEAR_L        1
#define LOGOUT_ACTION_CLEAR_L_NO_APP 2

#define PBC_SESSION_REAUTH 1
#define PBC_SUPER_DEBUG 1
#define PBC_CLEAR_COOKIE "clear"
#define PBC_SET "set"

#define EARLIEST_EVER "Fri, 11-Jan-1990 00:00:01 GMT"

/* this is the content of the redirect page's body if there is a POST */

#define PBC_POST_NO_JS_HTML1 "<HTML><HEAD></HEAD>\n \
<BODY BGCOLOR=\"white\" onLoad=\"document.query.submit.click()\">\n \
<CENTER>\n \
<FORM METHOD=\"POST\" ACTION=\""
         /* url of login page */
#define PBC_POST_NO_JS_HTML2 "\" NAME=\"query\">\n \
<INPUT TYPE=\"hidden\" NAME=\"post_stuff\" VALUE=\""
         /* packages POST stuff */
#define PBC_POST_NO_JS_HTML3 "\">\n \
<TABLE CELLPADDING=0 CELLSPACING=0 BORDER=0 WIDTH=520><TR><TD WIDTH=300 VALIGN=\"MIDDLE\"> <IMG SRC=\""
         /* UWnetID logdo url */
#define PBC_POST_NO_JS_HTML4 "\" ALT=\"UW NetID Login\" HEIGHT=\"64\" WIDTH=\"208\"> \n \
<SCRIPT LANGUAGE=\"JavaScript\">\n\
document.write(\"<P>Your browser should move to the next page in a few seconds.  If it doesn't, please click the button to continue.<P>\")\n \
</SCRIPT> <NOSCRIPT> \
<P>You do not have Javascript turned on, please click the button to continue.<P>\n </NOSCRIPT>\n</TABLE>\n \
<INPUT TYPE=\"SUBMIT\" NAME=\"submit\" VALUE=\""
	/* button text (PBC_POST_NO_JS_BUTTON) */
#define PBC_POST_NO_JS_HTML5 "\">\n </FORM>\n"
	/* copyright (PBC_HTML_COPYRIGHT) */
#define PBC_POST_NO_JS_HTML6 "</CENTER>\n </BODY></HTML>\n"

#define PBC_HTML_COPYRIGHT "<P><address>&#169; 1999 University of Washington</address><P>\n" 
#define PBC_POST_NO_JS_BUTTON "Click here to continue"
#define PBC_WEBISO_LOGO "images/login.gif"

/* 
 for the GET line to the login server
 this is used in the login script too
 */
#define PBC_GETVAR_APPSRVID "one"
#define PBC_GETVAR_APPID "two"
#define PBC_GETVAR_CREDS "three"
#define PBC_GETVAR_VERSION "four"
#define PBC_GETVAR_METHOD "five"
#define PBC_GETVAR_HOST "six"    /* host portion of url, could be host:port */
#define PBC_GETVAR_URI "seven"
#define PBC_GETVAR_ARGS "eight"
#define PBC_GETVAR_FR "fr"
/* new in dec 1999 */
#define PBC_GETVAR_REAL_HOST "hostname"  /* machine's hostname         */
#define PBC_GETVAR_APPSRV_ERR "nine"  /* let the login server know why */
#define PBC_GETVAR_FILE_UPLD "file"   /* for form multipart testing    */
#define PBC_GETVAR_FLAG "flag"        /* not currently used            */
#define PBC_GETVAR_REFERER "referer"  /* to knit together the referer  */
#define PBC_GETVAR_POST_STUFF "post_stuff"  /* post args               */
/* new in Aug 2001 */
#define PBC_GETVAR_SESSION_REAUTH "sess_re" /* session delta force reauth */
#define PBC_GETVAR_REPLY "reply"            /* tags a reply from the form */
/* new in oct 2001 */
#define PBC_GETVAR_DURATION "duration" 
/* new in March 2002 to support short term logout */
#define PBC_GETVAR_LOGOUT_ACTION "logout_action"
/* added previously but only now as defines March 2002 */
#define PBC_GETVAR_FIRST_KISS "first_kiss"
#define PBC_GETVAR_NEXT_SECURID "next_securid"
#define PBC_GETVAR_USER "user"
#define PBC_GETVAR_REALM "realm"
#define PBC_GETVAR_PASS "pass"
#define PBC_GETVAR_PASS2 "pass2"
#define PBC_GETVAR_GREQ_CREDS "creds_from_greq"
/* added May 2002 willey*/
#define PBC_GETVAR_PINIT "pinit"
/* added June 2002 leg */
#define PBC_GETVAR_CRED_TARGET "cred_target"
/* added June 2002 willey */
#define PBC_GETVAR_PRE_SESS_TOK "pre_sess_tok"

/* 
 things that are used both places (module and the library)
 */
#define PBC_CREDS_NONE    '0'

#define PBC_COOKIE_TYPE_NONE  '0'
#define PBC_COOKIE_TYPE_G     '1'
#define PBC_COOKIE_TYPE_S     '2'
#define PBC_COOKIE_TYPE_L     '3'
#define PBC_COOKIE_TYPE_PRE_S '4'

#define PBC_BASIC_CRED_ID '1'
#define PBC_GETCRED_CRED_ID '2'

/* macros to support older version of apache */

#ifdef APACHE1_3
#define pbc_malloc(x) ap_palloc(p, x)
#define pbc_free(x) libpbc_void(x)
#define pbc_strdup(x) ap_pstrdup(p, x)
#define pbc_strndup(s, n) ap_pstrdup(p, s, n)
#define pbc_fopen(x, y) ap_pfopen(p, x, y)
#define pbc_fclose(x) ap_pfclose(p, x)
#endif

#ifndef pbc_malloc
#define pbc_malloc(x) malloc(x)
#endif
#ifndef pbc_free
#define pbc_free(x) free(x)
#endif
#ifndef pbc_strdup
#define pbc_strdup(x) strdup(x)
#endif
#ifndef pbc_strndup
#define pbc_strndup(s, n) (char *)strncpy(calloc(n+1, sizeof(char)), s, n)
#endif
#ifndef pbc_fopen
#define pbc_fopen(x, y) fopen(x, y)
#endif
#ifndef pbc_fclose
#define pbc_fclose(x) fclose(x)
#endif

/* 
   macros to support passing extra args when compiling w/ apache
 */

/* p is the memory pool in apache */

#if defined (APACHE1_3)
#define libpbc_gen_granting_req(a,b,c,d,e,f,g,h,i,j,k) \
		libpbc_gen_granting_req_p(p, a,b,c,d,e,f,g,h,i,j,k,l)
#define libpbc_get_cookie(a,b,c,d,e,f,g) \
		libpbc_get_cookie_p(p, a,b,c,d,e,f,g)
#define libpbc_get_cookie_with_expire(a,b,c,d,e,f,g,h) \
		libpbc_get_cookie_with_expire_p(p, a,b,c,d,e,f,g,h)
#define libpbc_unbundle_cookie(a,b)        libpbc_unbundle_cookie_p(p, a,b)
#define libpbc_update_lastts(a,b,c)        libpbc_update_lastts_p(p, a,b,c)
#define libpbc_pubcookie_init() 	   libpbc_pubcookie_init_p(p)
#define libpbc_alloc_init(a) 		   libpbc_alloc_init_p(p, a)
#define libpbc_gethostip() 		   libpbc_gethostip_p(p)
#define libpbc_init_crypt(a) 		   libpbc_init_crypt_p(p, a)
#define libpbc_rand_malloc() 		   libpbc_rand_malloc_p(p)
#define libpbc_get_private_key(a,b) 	   libpbc_get_private_key_p(p, a,b)
#define libpbc_get_public_key(a,b) 	   libpbc_get_public_key_p(p, a,b)
#define libpbc_init_cookie_data() 	   libpbc_init_cookie_data_p(p)
#define libpbc_init_md_context_plus() 	   libpbc_init_md_context_plus_p(p)
#define libpbc_get_crypt_key(a,b) 	   libpbc_get_crypt_key_p(p, a,b)
#define libpbc_sign_cookie(a,b) 	   libpbc_sign_cookie_p(p, a,b)
#define libpbc_sign_bundle_cookie(a,b)   libpbc_sign_bundle_cookie_p(p, a,b)
#define libpbc_stringify_cookie_data(a)    libpbc_stringify_cookie_data_p(p, a)
#define libpbc_free_md_context_plus(a)     libpbc_free_md_context_plus_p(p, a)
#define libpbc_generate_crypt_key(a)       libpbc_generate_crypt_key_p(p, a)
#define libpbc_set_crypt_key(a,b)          libpbc_set_crypt_key_p(p,a,b)

#else

#define libpbc_gen_granting_req(a,b,c,d,e,f,g,h,i,j,k) \
		libpbc_gen_granting_req_np(a,b,c,d,e,f,g,h,i,j,k)
#define libpbc_get_cookie(a,b,c,d,e,f,g) \
		libpbc_get_cookie_np(a,b,c,d,e,f,g)
#define libpbc_get_cookie_with_expire(a,b,c,d,e,f,g,h) \
		libpbc_get_cookie_with_expire_np(a,b,c,d,e,f,g,h)
#define libpbc_unbundle_cookie(a,b)    libpbc_unbundle_cookie_np(a,b)
#define libpbc_update_lastts(a,b)      libpbc_update_lastts_np(a,b)
#define libpbc_pubcookie_init	 	 libpbc_pubcookie_init_np
#define libpbc_alloc_init(a) 		 libpbc_alloc_init_np(a)
#define libpbc_gethostip   		 libpbc_gethostip_np
#define libpbc_init_crypt(a) 		 libpbc_init_crypt_np(a)
#define libpbc_rand_malloc 	   	 libpbc_rand_malloc_np
#define libpbc_get_private_key(a,b) 	 libpbc_get_private_key_np(a,b)
#define libpbc_get_public_key(a,b) 	 libpbc_get_public_key_np(a,b)
#define libpbc_init_cookie_data 	 libpbc_init_cookie_data_np
#define libpbc_init_md_context_plus 	 libpbc_init_md_context_plus_np
#define libpbc_get_crypt_key(a,b) 	 libpbc_get_crypt_key_np(a,b)
#define libpbc_sign_cookie(a,b) 	 libpbc_sign_cookie_np(a,b)
#define libpbc_sign_bundle_cookie(a,b) libpbc_sign_bundle_cookie_np(a,b)
#define libpbc_stringify_cookie_data(a)  libpbc_stringify_cookie_data_np(a)
#define libpbc_free_md_context_plus(a)   libpbc_free_md_context_plus_np(a)
#define libpbc_generate_crypt_key(a)     libpbc_generate_crypt_key_np(a)
#define libpbc_set_crypt_key(a,b)        libpbc_set_crypt_key_np(a,b)

#endif 

#endif /* !PUBCOOKIE_CONFIG */
