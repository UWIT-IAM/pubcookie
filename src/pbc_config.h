/*
    $Id: pbc_config.h,v 1.19 1999-05-26 18:00:54 willey Exp $
 */

#ifndef PUBCOOKIE_CONFIG
#define PUBCOOKIE_CONFIG

#if defined (APACHE1_2) || defined (APACHE1_3)
#define APACHE
#endif

/* 
 things that came from the module
 */

/* the cookies; l, g, and s have the same format g request and pre s
   are different internally
 */
#define PBC_L_COOKIENAME "pubcookie_l"
#define PBC_G_COOKIENAME "pubcookie_g"
#define PBC_G_REQ_COOKIENAME "pubcookie_g_req"
#define PBC_S_COOKIENAME "pubcookie_s"
#define PBC_PRE_S_COOKIENAME "pubcookie_p_res"
#define PBC_TEST_COOKIENAME "pubcookie_test_cookie"
#define PBC_TEST_COOKIECONTENTS "yes"

#define PBC_AUTH_FAILED_HANDLER "pubcookie-failed-handler"
#define PBC_BAD_USER_HANDLER "pubcookie-bad-user"

#define PBC_POST_NO_JS_HTML1 "<TABLE CELLPADDING=0 CELLSPACING=0 BORDER=0 WIDTH=520> <TR> <TD WIDTH=300 VALIGN=\"MIDDLE\"> <IMG SRC=\""
#define PBC_POST_NO_JS_HTML2 "\" ALT=\"UW NetID Login\" HEIGHT=\"64\" WIDTH=\"208\"><P>You do not have Javascript turned on and are penalized by having to press this button<P>\n" 
#define PBC_HTML_COPYRIGHT "<P><address>&#169; 1999 University of Washington</address><P>\n" 
#define PBC_POST_NO_JS_BUTTON "Click here to continue"
#define PBC_UWNETID_LOGO "images/login.gif"

#define PBC_LOGIN_PAGE "https://weblogin.washington.edu/"

#if defined (WIN32)
#define PBC_CRYPT_KEYFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\c_key"
#define PBC_MASTER_CRYPT_KEYFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\m_key"
#else
#define PBC_CRYPT_KEYFILE "/usr/local/pubcookie/c_key"
#define PBC_MASTER_CRYPT_KEYFILE "/usr/local/pubcookie/m_key"
#endif

#define PBC_DEFAULT_INACT_EXPIRE 30 * 60    
#define PBC_DEFAULT_HARD_EXPIRE 8 * 60 * 60
#define PBC_MAX_HARD_EXPIRE 12 * 60 * 60
#define PBC_DEFAULT_EXPIRE_LOGIN 8 * 60 * 60
#define PBC_GRANTING_EXPIRE 20
#define PBC_BAD_AUTH 1
#define PBC_BAD_USER 2
#define PBC_FORCE_REAUTH 3
/* why is it PBC_NUWNETID_AUTHTYPE and not PBC_UWNETID_AUTHTYPE ???  */
#define PBC_NUWNETID_AUTHTYPE "uwnetid"
#define PBC_SECURID_AUTHTYPE "securid"
#define PBC_REFRESH_TIME 0
#define PBC_ENTRPRS_DOMAIN ".washington.edu"

/* 
 for the GET line to the login server
 this is used in the login script too
 */
#define PBC_GETVAR_APPSRVID "one"
#define PBC_GETVAR_APPID "two"
#define PBC_GETVAR_CREDS "three"
#define PBC_GETVAR_VERSION "four"
#define PBC_GETVAR_METHOD "five"
#define PBC_GETVAR_HOST "six"
#define PBC_GETVAR_URI "seven"
#define PBC_GETVAR_ARGS "eight"
#define PBC_GETVAR_FR "fr"

/* 
 things that are used both places
 */
#define PBC_SIG_LEN 128
#define PBC_CREDS_NONE    '0'
#define PBC_CREDS_UWNETID '1'
#define PBC_CREDS_SECURID '2'
#define PBC_CREDS_UWNETID_SECURID '3'

#define PBC_COOKIE_TYPE_NONE '0'
#define PBC_COOKIE_TYPE_G    '1'
#define PBC_COOKIE_TYPE_S    '2'
#define PBC_COOKIE_TYPE_L    '3'

#if defined (WIN32)
#define PBC_L_CERTFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\pubcookie_login.cert"

/* lives only on login server */
#define PBC_L_KEYFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\pubcookie_login.key"

/* lives only on application server */
#define PBC_S_CERTFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\pubcookie_session.cert"

/* lives only on application server */
#define PBC_S_KEYFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\pubcookie_session.key"

/* lives on application servers */
#define PBC_G_CERTFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\pubcookie_granting.cert"

/* lives only on login server */
#define PBC_G_KEYFILE "C:\\WINNT\\System32\\inetsrv\\pubcookie\\pubcookie_granting.key"

#else

/* lives only on login servers */
#define PBC_L_CERTFILE "/usr/local/pubcookie/pubcookie_login.cert"

/* lives only on login server */
#define PBC_L_KEYFILE "/usr/local/pubcookie/pubcookie_login.key"

/* lives only on application server */
#define PBC_S_CERTFILE "/usr/local/pubcookie/pubcookie_session.cert"

/* lives only on application server */
#define PBC_S_KEYFILE "/usr/local/pubcookie/pubcookie_session.key"

/* lives on application servers */
#define PBC_G_CERTFILE "/usr/local/pubcookie/pubcookie_granting.cert"

/* lives only on login server */
#define PBC_G_KEYFILE "/usr/local/pubcookie/pubcookie_granting.key"

#endif

#ifdef APACHE1_2
#define pbc_malloc(x) palloc(p, x)
#define pbc_free(x) libpbc_void(x)
#define pbc_strdup(x) pstrdup(p, x)
#define pbc_strndup(s, n) pstrdup(p, s, n)
#define pbc_fopen(x, y) pfopen(p, x, y)
#define pbc_fclose(x) pfclose(p, x)
#elif APACHE1_3
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

#if defined (APACHE1_2) || defined (APACHE1_3)
#define libpbc_gen_granting_req(a,b,c,d,e,f,g,h,i,j,k) libpbc_gen_granting_req_p(p, a,b,c,d,e,f,g,h,i,j,k,l)
#define libpbc_get_cookie(a,b,c,d,e,f,g,h) libpbc_get_cookie_p(p, a,b,c,d,e,f,g,h)
#define libpbc_unbundle_cookie(a,b,c)  libpbc_unbundle_cookie_p(p, a,b,c)
#define libpbc_update_lastts(a,b,c)      libpbc_update_lastts_p(p, a,b,c)
#define libpbc_sign_init(a) 		   libpbc_sign_init_p(p, a)
#define libpbc_verify_init(a) 	   libpbc_verify_init_p(p, a)
#define libpbc_pubcookie_init() 	   libpbc_pubcookie_init_p(p)
#define libpbc_pubcookie_exit() 	   libpbc_pubcookie_exit_p(p)
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
#define libpbc_sign_bundle_cookie(a,b,c) 	   libpbc_sign_bundle_cookie_p(p, a,b,c)
#define libpbc_stringify_cookie_data(a) 	   libpbc_stringify_cookie_data_p(p, a)
#define libpbc_free_md_context_plus(a)     libpbc_free_md_context_plus_p(p, a)
#define libpbc_free_crypt(a)               libpbc_free_crypt_p(p, a)

#else
#define libpbc_gen_granting_req(a,b,c,d,e,f,g,h,i,j,k) libpbc_gen_granting_req_np(a,b,c,d,e,f,g,h,i,j,k)
#define libpbc_get_cookie(a,b,c,d,e,f,g,h) libpbc_get_cookie_np(a,b,c,d,e,f,g,h)
#define libpbc_unbundle_cookie(a,b,c)    libpbc_unbundle_cookie_np(a,b,c)
#define libpbc_update_lastts(a,b,c)      libpbc_update_lastts_np(a,b,c)
#define libpbc_sign_init(a) 		 libpbc_sign_init_np(a)
#define libpbc_verify_init(a) 	   	 libpbc_verify_init_np(a)
#define libpbc_pubcookie_init	 	 libpbc_pubcookie_init_np
#define libpbc_pubcookie_exit 		 libpbc_pubcookie_exit_np
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
#define libpbc_sign_bundle_cookie(a,b,c) libpbc_sign_bundle_cookie_np(a,b,c)
#define libpbc_stringify_cookie_data(a)  libpbc_stringify_cookie_data_np(a)
#define libpbc_free_md_context_plus(a)   libpbc_free_md_context_plus_np(a)
#define libpbc_free_crypt(a)             libpbc_free_crypt_np(a)

#endif 

#endif /* !PUBCOOKIE_CONFIG */
