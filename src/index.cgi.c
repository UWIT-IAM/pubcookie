/*

    Copyright 1999-2002, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is the pubcookie login cgi, YEAH!

    this uses a modified version of the cgic library
    functions that are cgiSomething are from that library
 */

/*
    $Id: index.cgi.c,v 1.43 2002-05-18 01:05:43 willey Exp $
 */


/* LibC */
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
/* openssl */
#include <pem.h>
/* kerberos  */
#include <com_err.h>
#include <krb5.h>
#ifdef KRB5
#include <krb5-types.h>
#include "k5auth.h"
#endif
#ifdef KRB4
#include "k4auth.h"
#endif
/* securid */
#include "securid.h"
/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
/* cgic */
#include <cgic.h>

/* the mirror file is a mirror of what gets written out of the cgi */
/* of course it is overwritten each time this runs                 */
FILE	*mirror;

/* do we want debugging? */
int debug;

crypt_stuff         *c_stuff = NULL;

/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
/*      general utility thingies                                           */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */

/*
 * return the length of the passed file in bytes or 0 if we cant tell
 * resets the file postion to the start
 */
static long file_size(FILE *afile)
{
  long len;
  if (fseek(afile, 0, SEEK_END) != 0)
      return 0;
  len=ftell(afile);
  if (fseek(afile, 0, SEEK_SET) != 0)
      return 0;
  return len;
}

/*
 * return a template html file
 */
static char *get_file_template(const char *fname)
{
  char *template;
  long len, readlen;
  FILE *tmpl_file;

  tmpl_file = fopen (fname,"r");
  if (tmpl_file == NULL) {
      log_error (5, "abend", 0,"cant open template file '%s'", fname);
      return NULL;
  }

  len=file_size(tmpl_file);
  if (len==0) {
      return NULL;
  }

  template = malloc (len+1);
  if (template == NULL) {
      log_error (5, "abend", 0, 
		 "unable to malloc %d bytes for template file %s", 
		 len+1, fname);
      return NULL;
  }

  *template=0;
  readlen = fread(template, 1, len, tmpl_file);
  if (readlen != len) {
      log_error (5, "abend", 0, 
		 "read %d bytes when expecting %d for template file %s", 
		 readlen, len, fname);
      free(template);
      return NULL;
  }

  template[len]=0;
  return template;
}

/*
 * print to the passed buffer given the name of the file containing the %s info
 */
static void buf_template_vprintf(const char *fname, char *dst, size_t n,
				 va_list ap)
{
  char *template = get_file_template(fname);
  vsnprintf(dst, n, template, ap);
  free(template);
}


void print_out(char *format,...)
{
    va_list args;

    va_start(args, format);
    vprintf(format, args);

    if (debug) {
	vfprintf(stderr, format, args);
    }

    if (mirror) {
	vfprintf(mirror, format, args);
    }

    va_end(args);
}

/*
 * print out using a template
 */
static void tmpl_print_out(const char *fname,...)
{
  char buf[MAX_EXPANDED_TEMPLATE_SIZE];
  va_list args;

  va_start(args, fname);

  /* why is this being read here and not being used? -jeaton */
  /* format=get_file_template(fname); */

  buf_template_vprintf(fname, buf, sizeof(buf), args);
  va_end(args);

  printf("%s", buf);

  if (debug) {
      fprintf(stderr,"%s",buf);
  }

  if (mirror) {
      fprintf(mirror,"%s",buf);
  }
}


/**
 * checks a login_rec contents for expiration 
 * @param *c from login cookie
 * @param t now
 * @returns PBC_FAIL for expired 
 * @returns PBC_OK   for not expired 
 */
int check_l_cookie_expire (login_rec *c, time_t t) 
{
    if ( c == NULL || t > c->expire_ts )
        return(PBC_FAIL);
    else
        return(PBC_OK);

}

/*
 * initialize some things in the record 
 */
void init_login_rec(login_rec *r)
{
    r->alterable_username = PBC_FALSE;
    r->first_kiss = NULL;
    r->appsrv_err = NULL;
    r->appsrv_err_string = NULL;
    r->expire_ts = PBC_FALSE;
    r->pinit = PBC_FALSE;
    r->reply = PBC_FALSE;

}

/*
 * this returns first cookie for a given name
 */
int get_cookie(char *name, char *result, int max)
{
    char *s;
    char *p;
    char *target;
    char *wkspc;

    if (!(target = malloc(PBC_20K)) ) {
        abend("out of memory");
    }

    /* get all the cookies */
    if (!(s = getenv("HTTP_COOKIE")) ){
	free(target);
        return(PBC_FAIL);
    }
    
    /* make us a local copy */
    strncpy(target, s, PBC_20K-1);
    
    if (!(wkspc=strstr(target, name))) {
	free(target);
        return(PBC_FAIL);
    }
    
    /* get rid of the <name>= part from the cookie */
    p = wkspc = wkspc + strlen(name) + 1;
    while(*p) {
        if (*p == ';' ) {
            *p = '\0';
            break;
        }
        p++;
    }

    strncpy(result, wkspc, max);

    if (debug) {
	fprintf(stderr, "get_cookie: returning cookie: %s\n%s\n",
		name, result);
    }

    free(target);
    return(PBC_OK);

}


char *get_string_arg(char *name, cgiFormResultType (*f)())
{
    int			length;
    char		*s;
    cgiFormResultType 	res;

    cgiFormStringSpaceNeeded(name, &length);
    if (!(s = calloc(length+1, sizeof(char)))) {
	log_error (5, "abend", 0, 
		   "unable to calloc %d chars for string_arg %s", 
		   length+1, name);
	return(NULL);
    }

    if ((res=f(name, s, length+1)) != cgiFormSuccess ) {
	free(s);
        return(NULL);
    } 
    else {
        return(s);
    }

}

/**
 * uses cgic calls to get an int from parsed string of encoded stuff
 * @param name argument 
 * @param default
 * @returns int that was found or default
 */
int get_int_arg(char *name, int def) {
    int		i;

    if( cgiFormInteger(name, &i, 0) == cgiFormSuccess )
        return(i);
    else
        return(def);

}

char *clean_username(char *in)
{
    char	*p;
    int		word_start = 0;

    p = in;
    while(*p) {
        /* no email addresses or full principals */
        if(*p == '@')
            *p = '\0';

        /* no spaces at the beginning of the username */
        if(*p == ' ' && !word_start)
            in = p + 1;
        else
            word_start = 1;

        /* no spaces at the end */
        if(*p == ' ' && word_start) {
            *p = '\0';
            break;
        }
	
        p++;
    }
    return(in);
}

/**
 * sets a login cookie that is expired
 *	we no longer clear login cookies to invalidate them
 *	now we expire them, so we can keep the login name
 *	around
 * @param *c from login cookie (mostly)
 * @param *l from login form (mostly)
 * @returns PBC_FAIL on error
 * @returns PBC_OK if everything went ok
 */
int expire_login_cookie(login_rec *l, login_rec *c) {
    char	*l_cookie;
    char	*message = NULL;
    int		l_res;
    char	*user;

    if(debug)
        log_message("expire_login_cookie: hello");

    if ( (message = malloc(PBC_4K)) == NULL ) 
        abend("out of memory");
    
    if ( (l_cookie = malloc(PBC_4K)) == NULL )
        abend("out of memory");

    init_crypt();

    if( c == NULL || c->user == NULL ) {
        if( l == NULL || l->user == NULL )
            user = strdup("unknown");
        else
            user = l->user;
    }
    else {
        user = c->user;
    }

    l_res = create_cookie(url_encode(user),
                       url_encode("expired"),
                       url_encode("expired"),
                       PBC_COOKIE_TYPE_L,
                       PBC_CREDS_NONE,
                       23,                  
		       time(NULL),  
                       l_cookie,
                       login_private_keyfile(),
                       PBC_4K);

    if(debug)
        log_message("expire_login_cookie: l_res: %d", l_res);

    /* if we have a problem then bail with a nice message */
    if ( l_res == PBC_FAIL ) {
          sprintf( message, "%s%s%s%s%s%s",
		PBC_EM1_START,
		TROUBLE_CREATING_COOKIE,
		PBC_EM1_END,
      		PBC_EM2_START,
		PROBLEMS_PERSIST,
         	PBC_EM2_END);
          print_login_page(l, c, message, "cookie create failed",
			   NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
          log_error(1, "system-problem", 0,
		    "Not able to create cookie for user %s at %s-%s",
		    l->user, l->appsrvid, l->appid);
          free(message);
          return(PBC_FAIL);
    }

#ifdef PORT80_TEST
    print_out("Set-Cookie: %s=%s; domain=%s; path=%s\n", 
#else
    print_out("Set-Cookie: %s=%s; domain=%s; path=%s; secure\n", 
#endif
		PBC_L_COOKIENAME,
                l_cookie,
                login_host(),
                LOGIN_DIR);

    return(PBC_OK);

}

/**
 * clears login cookie
 * depreciated we now expire login cookies
 */
int clear_login_cookie() {

    if(debug)
        log_message("clear_login_cookie: hello");

#ifdef PORT80_TEST
    print_out("Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s\n",
#else
    print_out("Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
#endif
            PBC_L_COOKIENAME, 
            PBC_CLEAR_COOKIE,
            login_host(), 
            LOGIN_DIR, 
            EARLIEST_EVER);

    return(PBC_OK);

}

/**
 * sets cleared granting request cookie
 * @returns PBC_OK regardless
 */
int clear_greq_cookie() {

#ifdef PORT80_TEST
    print_out("Set-Cookie: %s=%s; domain=%s; path=/; expires=%s\n",
#else
    print_out("Set-Cookie: %s=%s; domain=%s; path=/; expires=%s; secure\n",
#endif
            PBC_G_REQ_COOKIENAME, 
            PBC_CLEAR_COOKIE,
            enterprise_domain(),
            EARLIEST_EVER);

    return(PBC_OK);

}

login_rec *load_login_rec(login_rec *l) 
{
    if (debug) {
	fprintf(stderr, "load_login_rec: hello\n");
    }

    /* only created by the login cgi */
    l->next_securid   = get_int_arg(PBC_GETVAR_NEXT_SECURID, 0);
    l->first_kiss     = get_string_arg(PBC_GETVAR_FIRST_KISS, NO_NEWLINES_FUNC);

    /* make sure the username is a username */
    if((l->user = get_string_arg(PBC_GETVAR_USER, NO_NEWLINES_FUNC)))
        l->user = clean_username(l->user);

    l->pass 	      = get_string_arg(PBC_GETVAR_PASS, NO_NEWLINES_FUNC);
    l->pass2 	      = get_string_arg(PBC_GETVAR_PASS2, NO_NEWLINES_FUNC);
    l->args           = get_string_arg(PBC_GETVAR_ARGS, YES_NEWLINES_FUNC);
    l->uri            = get_string_arg(PBC_GETVAR_URI, NO_NEWLINES_FUNC);
    l->host           = get_string_arg(PBC_GETVAR_HOST, NO_NEWLINES_FUNC);
    l->method 	      = get_string_arg(PBC_GETVAR_METHOD, NO_NEWLINES_FUNC);
    l->version 	      = get_string_arg(PBC_GETVAR_VERSION, NO_NEWLINES_FUNC);
    l->creds          = get_int_arg(PBC_GETVAR_CREDS, 0) + 48;

    if( (l->creds_from_greq = 
              get_int_arg(PBC_GETVAR_GREQ_CREDS, 0)+48) == PBC_CREDS_NONE ) 
        l->creds_from_greq  = l->creds;

    l->appid 	      = get_string_arg(PBC_GETVAR_APPID, NO_NEWLINES_FUNC);
    l->appsrvid       = get_string_arg(PBC_GETVAR_APPSRVID, NO_NEWLINES_FUNC);
    l->fr 	      = get_string_arg(PBC_GETVAR_FR, NO_NEWLINES_FUNC);

    l->real_hostname  = get_string_arg(PBC_GETVAR_REAL_HOST, NO_NEWLINES_FUNC);
    l->appsrv_err     = get_string_arg(PBC_GETVAR_APPSRV_ERR, NO_NEWLINES_FUNC);
    l->file 	      = get_string_arg(PBC_GETVAR_FILE_UPLD, NO_NEWLINES_FUNC);
    l->flag 	      = get_string_arg(PBC_GETVAR_FLAG, NO_NEWLINES_FUNC);
    l->referer 	      = get_string_arg(PBC_GETVAR_REFERER, NO_NEWLINES_FUNC);
    l->session_reauth = get_int_arg(PBC_GETVAR_SESSION_REAUTH, 0);
    l->reply 	      = get_int_arg(PBC_GETVAR_REPLY, 0);
    l->duration       = get_int_arg(PBC_GETVAR_DURATION, 0);
    l->pinit          = get_int_arg(PBC_GETVAR_PINIT, 0);

    if (debug) {
	fprintf(stderr, "load_login_rec: bye\n");
    }

    return(l);
}

char *url_encode(char *in)
{
    char	*out;
    char	*p;

    if (!(out = malloc(strlen (in) * 3 + 1)) ) {
        abend("unable to allocate memory in url_encode");
    }

    p = out;
    while( *in ) {
        switch(*in) {
        case ' ':
            *p = '+';
            break;
        case '!':
            *p = '%'; *(++p) = '2'; *(++p) = '1';
            break;
        case '"':
            *p = '%'; *(++p) = '2'; *(++p) = '2';
            break;
        case '#':
            *p = '%'; *(++p) = '2'; *(++p) = '3';
            break;
        case '$':
            *p = '%'; *(++p) = '2'; *(++p) = '4';
            break;
        case '%':
            *p = '%'; *(++p) = '2'; *(++p) = '5';
            break;
        case '&':
            *p = '%'; *(++p) = '2'; *(++p) = '6';
            break;
        case '+':
            *p = '%'; *(++p) = '2'; *(++p) = 'B';
            break;
        case ':':
            *p = '%'; *(++p) = '3'; *(++p) = 'A';
            break;
        case ';':
            *p = '%'; *(++p) = '3'; *(++p) = 'B';
            break;
        case '=':
            *p = '%'; *(++p) = '3'; *(++p) = 'D';
            break;
        case '?':
            *p = '%'; *(++p) = '3'; *(++p) = 'F';
            break;
	default:
	    *p = *in;
	    break;
        }
        p++;
        in++;
    }
    *p = '\0';
    return(out);

}

char *string_encode(char *in)
{
    char	*out;
    char	*p;

    if (!(out = malloc(strlen (in) * 5 + 1)) ) {
        abend("out of memory");
    }

    p = out;
    while( *in ) {
        switch(*in) {
	case '&':
	    *p = '&'; *(++p) = 'a'; *(++p) = 'm'; *(++p) = 'p'; *(++p) = ';';
	    break;
	case '<':
	    *p = '&'; *(++p) = 'l'; *(++p) = 't'; *(++p) = ';';
	    break;
	case '>':
	    *p = '&'; *(++p) = 'g'; *(++p) = 't'; *(++p) = ';';
	    break;
	default:
	    *p = *in;
	    break;
        }
        p++;
        in++;
    }
    *p = '\0';
    return(out);

}

/* write a log message via whatever mechanism                                 */
void log_message(const char *format, ...) 
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    bzero(new_format, PBC_4K);
    bzero(message, PBC_4K);

    snprintf(new_format, sizeof(new_format)-1, "%s: %s\n", 
			ANY_LOGINSRV_MESSAGE, format);
    va_start(args, format);
    vsnprintf(message, sizeof(message)-1, new_format, args);

    va_end(args);

    libpbc_debug(message);

}

void clear_error(const char *service, const char *message) 
{

}

/* send a message to pilot                                                   */
void send_pilot_message(int grade, const char *service, int self_clearing,
			char *message) 
{

    /* messages sent to pilot */

}

/* logs the message and forwards it on to pilot                              */
/*                                                                           */
/*   args: grade - same grades in pilot, 1 to 5, (5 is lowest)               */
/*         service - a name to id the weblogin service (see note)            */
/*         message - varg message                                            */
/*         self-clearing - does it clear itself (1) or not (0)               */
/*                                                                           */
/*   the trick to services is that there needs to be a TRIGGER event         */
/*      and then a CLEARING event.                                           */
/*                                                                           */
/* Service trigger/clear pairs (keep a log of messages here)                 */
/*   uwnetid-err         uwnetid timeout / o.k. uwnet auth                   */
/*   securid-err         securid timeout / o.k. securid auth                 */
/*   abend               abend / not self-clearing                           */
/*   system-problem      multiple / not self-clearing                        */
/*   version             wrong major version / not self-cleaing              */
/*   misc                misc is misc        / not self-clearing             */
/*   auth-kdc            auth_kdc code       / not self-clearing             */
/*   auth-securid        auth securid code   / not self-clearing             */
/*   auth-securid        auth securid code   / not self-clearing             */
/*                                                                           */
/*                                                                           */
void log_error(int grade, const char *service, int self_clearing,
	       const char *format,...)
{
    va_list	args;
    char	new_format[PBC_4K];
    char	message[PBC_4K];

    va_start(args, format);
    snprintf(new_format, sizeof(new_format)-1, "%s: %s", 
	     SYSERR_LOGINSRV_MESSAGE, format);
    vsnprintf(message, sizeof(message)-1, new_format, args);
    log_message(message);
    send_pilot_message(grade, service, self_clearing, message);
    va_end(args);

}

/* when things go wrong and you're not sure what else to do                  */
/* a polite bailing out                                                      */
void abend(char *message) 
{

    log_error(1, "abend", 0, message);
    notok(notok_generic);
    exit(0);

}

void init_mirror_file(const char * mirrorfile) 
{
    if (mirrorfile != NULL) {
	mirror = fopen(mirrorfile, "w");
    } else {
	mirror = fopen("/tmp/mirror", "w");
    }
}

void close_mirror_file() 
{
    if (mirror) {
	fclose(mirror);
    }
}

char *get_my_hostname() 
{
    struct utsname	myname;

    if ( uname(&myname) < 0 )
        log_error(2, "system-problem", 0, "problem doing uname lookup");

    return(strdup(myname.nodename));

}

const char *login_host() 
{
    return(libpbc_config_getstring("login_host", PBC_LOGIN_HOST));

}

const char *enterprise_domain() 
{
    return(libpbc_config_getstring("enterprise_domain", PBC_ENTRPRS_DOMAIN));

}

char *keyfile(char *prefix)
{
    char	*file;
    char	*host;

#ifdef NO_HOST_BASED_KEY_FILENAMES
    if (strdup(file, prefix) == NULL )
        abend("out of memory");
#else
    /* plus one for \0 and plus one for the '.' in the format */
    file = calloc(strlen(PBC_KEY_DIR) +
                  strlen(prefix) +
                  strlen(host=get_my_hostname()) + 1 + 1, sizeof(char));
    if (file == NULL ) 
        abend("out of memory");
    sprintf(file, "%s%s.%s", PBC_KEY_DIR, prefix, host);
#endif

    return(file);

}

char *login_private_keyfile()
{
#ifdef NO_HOST_BASED_KEY_FILENAMES
    return(keyfile(PBC_L_KEYFILE));
#else
    return(keyfile(PBC_L_PRIVKEY_FILE_PREFIX));
#endif

}

char *login_public_keyfile()
{
#ifdef NO_HOST_BASED_KEY_FILENAMES
    return(keyfile(PBC_L_CERTFILE));
#else
    return(keyfile(PBC_L_PUBKEY_FILE_PREFIX));
#endif

}

char *granting_private_keyfile()
{
#ifdef NO_HOST_BASED_KEY_FILENAMES
    return(keyfile(PBC_G_KEYFILE));
#else
    return(keyfile(PBC_G_PRIVKEY_FILE_PREFIX));
#endif

}

/* reads the crypt key */
int init_crypt() 
{
    unsigned char	crypt_keyfile[PBC_4K];

    if (c_stuff != NULL )
        return(PBC_OK);

    snprintf(crypt_keyfile, sizeof(crypt_keyfile)-1, "%s%s.%s", 
	     PBC_KEY_DIR, PBC_CRYPT_KEY_PREFIX, get_my_hostname()); 

    if ((c_stuff = libpbc_init_crypt(crypt_keyfile)) == NULL )
	return(PBC_FAIL);
    else 
	return(PBC_OK);

}

int has_login_cookie()
{
    if (getenv("HTTP_COOKIE") && 
	strstr(getenv("HTTP_COOKIE"), PBC_L_COOKIENAME) )
        return(1);
    else
        return(0);

}

/* we've decided not to serialize cookies, but we'll use this field          */
/* for something else in the future                                          */
/* why 23?  consult the stars                                                */
int get_next_serial()
{
    return(23);
}

char *get_granting_request() 
{
    char        *cookie;

    if ((cookie = malloc(PBC_4K)) == NULL ) {
        abend("out of memory");
    }

    if (get_cookie(PBC_G_REQ_COOKIENAME, cookie, PBC_4K-1) == PBC_FAIL ) {
        return(NULL);
    }

    return(cookie);

}

char *decode_granting_request(char *in)
{
    char	*out;

    if (debug) {
	fprintf(stderr, "decode_granting_request: in: %s\n", in);
    }

    out = strdup(in);    
    libpbc_base64_decode(in, out);

    if (debug) {
	fprintf(stderr, "decode_granting_request: out: %s\n", out);
    }

    return(out);
}


    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
    /*                                                                   */
    /*                                                                   */
    /* four cases for the main thingie                                   */
    /*   - reply from login page                                         */
    /*         in: cred data & granting req data                         */
    /*         process: validate creds                                   */
    /*         out: if successful L & G cookies redirect else login page */
    /*                                                                   */
    /*   - securid credentials (always requires reauth)                  */
    /*         in: G_Req with creds==securid                             */
    /*         out: the login page (incld g_req data and L cookie user)  */
    /*                                                                   */
    /*   - sesison expire requires reauth                                */
    /*         in: G_Req with session_reauth flag set                    */
    /*         out: the login page (incld g_req data and L cookie user)  */
    /*                                                                   */
    /*   - no prev login or creds include securid:                       */
    /*         in: no L cookie, bunch of GET data                        */
    /*               OR creds include securid info in g req              */
    /*         out: the login page (includes data from g req)            */
    /*                                                                   */
    /*   - not first time (have L cookie) but L cookie expired or invalid*/
    /*         in: expired or invalid L cookie, g req                    */
    /*         out: the login page (includes data from g req)            */
    /*                                                                   */
    /*   - not first time (have L cookie) L cookie not expired and valid */
    /*         in: valid L cookie, g req                                 */
    /*         out: L & G cookies redirect (username comes from L cookie)*/
    /*                                                                   */
    /*                                                                   */
    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

int vector_request(login_rec *l, login_rec *c)
{
    char	*res;
    char	message[PBC_4K];

    if (debug) {
	fprintf(stderr, "vector_request: hello\n");
	fprintf(stderr, "vector_request: l->creds: %c\n", l->creds);
    }

    if ( l->reply == FORM_REPLY ) {      /* a reply from the login page */
        res = check_login(l, c);
        if (strcmp(res, CHECK_LOGIN_RET_SUCCESS) ) {
            log_message("%s Authentication failed: %s type: %c %s",
			l->first_kiss, l->user, l->creds, res);
            l->alterable_username = PBC_TRUE; /* username might be wrong */
            if (!strcmp(res, CHECK_LOGIN_RET_FAIL) ) {
                snprintf(message, sizeof(message)-1, "%s%s%s<P>%s",
                    PBC_EM1_START,
                    AUTH_FAILED_MESSAGE1,
                    PBC_EM1_END, 
                    AUTH_FAILED_MESSAGE2);
            }
            else {
                snprintf(message, sizeof(message)-1, "%s%s%s<P>",
                    PBC_EM1_START,
                    AUTH_TROUBLE,
                    PBC_EM1_END);
            }
            print_login_page(l, c, message, LOGIN_REASON_AUTH_FAIL, 
			     NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
            return(PBC_FAIL);
        }
        log_message("%s Authentication success: %s type: %c", l->first_kiss,
		    l->user, l->creds);
        /* reset the expire times so new expire will be set */
        l->expire_ts = PBC_FALSE;
        if( c != NULL )
            c->expire_ts = PBC_FALSE;
    }
    else if (l->creds == PBC_CREDS_CRED3 ) {             /* securid */
        print_login_page(l, c, PRINT_LOGIN_PLEASE, LOGIN_REASON_SECURID,
			 NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
        return(PBC_FAIL);
    }
    else if ( !has_login_cookie() ) {          /* no l cookie, must login */
        print_login_page(l, c, PRINT_LOGIN_PLEASE, LOGIN_REASON_NO_L,
			 NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
        return(PBC_FAIL);
    }
    /* session timeout requires reauth */
    else if (l->session_reauth == PBC_SESSION_REAUTH ) { 
      print_login_page(l, c, PRINT_LOGIN_PLEASE, LOGIN_REASON_SESS_REAUTH,
			 NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
        return(PBC_FAIL);
    }
    else if ( (res=check_l_cookie(l, c)) ) {      /* problem w/ the l cookie*/
        log_message("%s Login cookie bad: %s", l->first_kiss, res);
        print_login_page(l, c, PRINT_LOGIN_PLEASE, res, 
			 NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
        return(PBC_FAIL);
    }

    return(PBC_OK);


}


/**
 * returns user agent, hides cgic global
 * @returns pointer to user agent
 */
char *user_agent() 
{
    return(cgiUserAgent);

}

/**
 * gets lifetime of a login cookie for a kiosk
 * @param *l from login session
 * @returns duration
 */
int get_kiosk_duration(login_rec *l)
{
    int         i;
    char	**keys;
    char	**values;

    if(debug)
        log_message("get_kiosk_duration: agent: %s", user_agent());

    keys = libpbc_config_getlist("kiosk_keys");
    values = libpbc_config_getlist("kiosk_values");

    for(i=0; keys[i] != NULL && values[i] != NULL; i++) {
        if( strstr(user_agent(), keys[i]) != NULL ) {
            if(debug)
                log_message("is kiosk: %s duration: %s\n", 
				user_agent(), values[i]);
            return(atoi(values[i]));
        }
    }

    /* not a kiosk */
    return(PBC_FALSE);

}

/**
 * calculates login cookie expiration
 * @param *l from login session
 * @returns time of expiration
 */
time_t compute_l_expire(login_rec *l)
{
    log_message("compute_l_expire: hello");

    if( (l->duration = get_kiosk_duration(l)) == PBC_FALSE )
        l->duration = 
                libpbc_config_getint("default_l_expire",DEFAULT_LOGIN_EXPIRE);

    return(time(NULL) + l->duration);

}

/**
 * forms nice string with time remaining
 * @param *c from login cookie
 * @returns string
 */
const char *time_remaining_text(login_rec *c)
{
    char 	*remaining = NULL;
    int 	secs_left = 0;
    int		len = PBC_1K;
    char 	*h, *m;

    if(debug)
        fprintf(stderr, "time_remaining_text: hello\n");
    
    if (!(remaining = malloc(len)) )
        abend("out of memory");
    if (!(h = malloc(len)) )
        abend("out of memory");
    if (!(m = malloc(len)) )
        abend("out of memory");

    if( c == NULL ) {
        free(remaining), free(h), free(m);
        return(REMAINING_UNKNOWN);
    }

    if( c->expire_ts == 0 ) {
        secs_left = c->create_ts + DEFAULT_LOGIN_EXPIRE - time(NULL); 
    }
    else {
        secs_left = c->expire_ts - time(NULL); 
    }

    if( secs_left <= 0 ) {
        free(remaining), free(h), free(m);
        return(REMAINING_EXPIRED);
    }
    
    snprintf(m, len, "%d minute%c", 
                secs_left % 3600 / 60,
                (secs_left % 3600 / 60 >= 2 ? 's' : ' '));
    snprintf(h, len, "%d hour%c", 
                secs_left/3600,
                (secs_left/3600 >= 2 ? 's' : ' '));
    snprintf(remaining, len, "%s %s %s %d seconds", 
                (secs_left/3600 >= 1 ? h : ""),
                (secs_left % 3600 / 60 >= 1 ? m : ""),
                (secs_left % 3600 / 60 >= 1 ? "and" : ""),
                secs_left % 3600 % 60);

    free(h), free(m);
    return(remaining);

}

int app_logged_out(login_rec *c, const char *appid, const char *appsrvid) 
{
    char	*new, *p, *app_string;
    const char	*s;
    int         len;

    len = strlen(appid) + strlen(appsrvid) + strlen(APP_LOGOUT_STR) + 3;
    app_string=calloc(len, sizeof(char));
    snprintf(app_string, len, "%s%c%s%c%s", 
		APP_LOGOUT_STR, APP_LOGOUT_STR_SEP, 
		appsrvid, APP_LOGOUT_STR_SEP,
		appid);
    
    /* clean non compliant chars from string */
    p = new = app_string;
    while(*p) {
        if (isalnum((int) *p) || *p == '-' || *p == '_' || *p == '.') {
            *new++ = *p;
        }
        p++;
    }
    *new = '\0';

    if( (s=libpbc_config_getstring(app_string, NULL)) == NULL ) {
        tmpl_print_out(TMPL_FNAME "logout_app");
    }
    else {
        print_out("%s\n", s);
    }
 
    free(app_string);
    return(PBC_OK);

}

int logout(login_rec *l, login_rec *c, int logout_action)
{
    char	*appid;
    char	*appsrvid;

    if (debug) {
        fprintf(stderr, "logout: logout_action: %d\n", logout_action);
    }

    appid = get_string_arg(PBC_GETVAR_APPID, NO_NEWLINES_FUNC);
    appsrvid = get_string_arg(PBC_GETVAR_APPSRVID, NO_NEWLINES_FUNC);

    clear_greq_cookie();     /* just in case there in one lingering */

    if( logout_action == LOGOUT_ACTION_NOTHING ) {
        tmpl_print_out(TMPL_FNAME "logout_part1");
        app_logged_out(c, appid, appsrvid);
        if( c == NULL || check_l_cookie_expire(c, time(NULL)) == PBC_FAIL) {
            tmpl_print_out(TMPL_FNAME "logout_already_weblogin");
            tmpl_print_out(TMPL_FNAME "logout_postscript_still_others");
        }
        else {
            tmpl_print_out(TMPL_FNAME "logout_still_weblogin",
                        (c == NULL || c->user == NULL ? "unknown" : c->user));
            tmpl_print_out(TMPL_FNAME "logout_time_remaining", 
			time_remaining_text(c));
            tmpl_print_out(TMPL_FNAME "logout_postscript_still_weblogin");
        }
        tmpl_print_out(TMPL_FNAME "logout_part2");
    }
    else if( logout_action == LOGOUT_ACTION_CLEAR_L ) {
        expire_login_cookie(l, c);
        tmpl_print_out(TMPL_FNAME "logout_part1");
        app_logged_out(c, appid, appsrvid);
        if( c == NULL || check_l_cookie_expire(c, time(NULL)) == PBC_FAIL)
            tmpl_print_out(TMPL_FNAME "logout_already_weblogin");
        else 
            tmpl_print_out(TMPL_FNAME "logout_weblogin");
        tmpl_print_out(TMPL_FNAME "logout_postscript_still_others");
        tmpl_print_out(TMPL_FNAME "logout_part2");
    }
    else if( logout_action == LOGOUT_ACTION_CLEAR_L_NO_APP ) {
        expire_login_cookie(l, c);
        tmpl_print_out(TMPL_FNAME "logout_part1");
        if( c == NULL || check_l_cookie_expire(c, time(NULL)) == PBC_FAIL )
            tmpl_print_out(TMPL_FNAME "logout_already_weblogin");
        else 
            tmpl_print_out(TMPL_FNAME "logout_weblogin");
        tmpl_print_out(TMPL_FNAME "logout_postscript_still_others");
        tmpl_print_out(TMPL_FNAME "logout_part2");
    }

    return(PBC_OK);

}

int check_logout(login_rec *l, login_rec *c) 
{
    int         logout_action;
    char	*logout_prog;
    char	*uri;
    char  	*p;

    if (debug) 
        fprintf(stderr, "check_logout: program name: %s\n", cgiScriptName);

    /* check to see if this is a logout redirect */
    logout_action = get_int_arg(PBC_GETVAR_LOGOUT_ACTION, LOGOUT_ACTION_UNSET);

    if ( logout_action != LOGOUT_ACTION_UNSET ) {
        fprintf(stderr, "check_logout: logout_action : %s\n", cgiScriptName);
        logout(l, c, logout_action);
        exit(0);
    }
 
    logout_prog = (char *)libpbc_config_getstring("logout_prog", NULL);
    uri = strdup(cgiScriptName);

    /* remove multiple slashes */
    p = uri;
    while( *p ) {
        if( p-1 >= uri && *p == '/' &&  *(p-1) == '/' )
            ;
        else
            p++;
    }
    *p = '\0';

    if ( logout_prog != NULL &&
         uri != NULL &&
	 strcasecmp(logout_prog, uri) == 0 ) {
        logout(l, c, LOGOUT_ACTION_CLEAR_L_NO_APP);
        exit(0);
    }

    return(PBC_OK);

}

/**
 * prints first part of login status page
 *   includes undocumented feature
 */
void status_part1()
{
    int		delay = get_int_arg("countdown", 0);
    int		min_delay = libpbc_config_getint("min_countdown", 9999);

    if( delay != 0 && delay >= min_delay )
        tmpl_print_out(TMPL_FNAME "status_part1_with_countdown", delay, delay);
    else
        tmpl_print_out(TMPL_FNAME "status_part1");
        
}

/**
 * prints login status page
 * @param c contents of login cookie
 */
void login_status_page(login_rec *c)
{
    status_part1();
    tmpl_print_out(TMPL_FNAME "logout_still_weblogin",
           (c == NULL || c->user == NULL ? "unknown" : c->user));
    tmpl_print_out(TMPL_FNAME "logout_time_remaining", time_remaining_text(c));
    tmpl_print_out(TMPL_FNAME "logout_postscript_still_weblogin");
    tmpl_print_out(TMPL_FNAME "status_part2");

}

/**
 * handles pinit requests 
 * @param l info for login session
 * @param c contents of login cookie
 */
int pinit(login_rec *l, login_rec *c)
{

    if(debug)
        log_message("pinit: hello");

    if( c == NULL || check_l_cookie_expire(c, time(NULL)) == PBC_FAIL ) {
	l->creds = PBC_CREDS_CRED1;  /* this is hoakie */
	l->pinit = PBC_TRUE;
	l->host = strdup((char *)login_host());
	l->appsrvid = strdup(l->host);
	l->appid = strdup("pinit");
	l->uri = strdup("/");
        if(debug)
            log_message("pinit: ready to print login page");
        print_login_page(l, c, PRINT_LOGIN_PINIT, "pinit", NO_CLEAR_LOGIN, 
		NO_CLEAR_GREQ);
    }
    else {
        login_status_page(c);
    }
    return(PBC_FAIL);

}

/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
/*	main line                                                          */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

int cgiMain() 
{
    login_rec	*l=NULL;   /* culled from various sources */
    login_rec	*c=NULL;   /* only from login cookie */
    const char  *mirrorfile;

    libpbc_config_init(NULL, "logincgi");
    debug = libpbc_config_getswitch("debug", 0);
    mirrorfile = libpbc_config_getstring("mirrorfile", NULL);
    
    if (debug) {
	fprintf(stderr, "cgiMain: hello built on " __DATE__ " " __TIME__ "\n");
    }

    if (mirrorfile) {
	init_mirror_file(mirrorfile);
    }

#ifndef PORT80_TEST
    /* bail if not ssl */
    if (!getenv("HTTPS") || strcmp( getenv("HTTPS"), "on" ) ) { 
        notok(notok_need_ssl);
        exit(0);
    }
#endif

    /* get the arguments to this cgi, whether they are from submitting */
    /* the login page or from from the granting request cookie         */
    /* you call tell the difference since the submitted one will have  */
    /* user and pass filled in                                         */
    /* malloc and populate login_rec                                   */
    l = get_query(); 

    /* unload the login cookie if we hav it */
    c = verify_unload_login_cookie(l);

    /* log the arrival */
    log_message("%s Visit from user: %s client addr: %s app host: %s appid: %s uri: %s because: %s", 
		l->first_kiss, 
		l->user, 
		cgiRemoteAddr, 
		l->host, 
		l->appid,
		l->uri,
		l->appsrv_err_string);

    /* check the user agent */
    if ( !check_user_agent() ) {
        log_message("%s bad agent: %s user: %s client_addr: %s",
		    l->first_kiss, 
		    user_agent(), 
		    l->user, 
		    cgiRemoteAddr);
        notok(notok_bad_agent);
        exit(0);
    }
    
    /* look for various logout conditions */
    check_logout(l, c);

    /* check to see what cookies we have */
    /* pinit detected in here */
    /* pinit responce detected in here */
    if (cookie_test(l, c) == PBC_FAIL)
        exit(0);

    if (debug) {
	log_message("cgiMain: checked user_agent, logout, and pinit.");
    }

    /* allow for older versions that don't have force_reauth */
    if ( !l->fr ) {
        l->fr = strdup("NFR");
    }
    
    /* check early if we get to ride free */
    l->ride_free_creds = ride_free_zone(l, c);
    
    if (vector_request(l, c) == PBC_FAIL ) {
        exit(0);
    }
    
    /* the reward for a hard days work                                      */
    log_message("%s Issuing cookies for user: %s client addr: %s app host: %s appid: %s", 
		l->first_kiss, 
		l->user, 
		cgiRemoteAddr, 
		l->host, 
		l->appid);
    
    /* generate the cookies and print the redirect page                      */
    print_redirect_page(l, c);
    
    if (mirrorfile) {
	close_mirror_file();
    }

    return(0);  
}

/* in:                                                                       */
/*   field	string for prompt                                            */
/*   var	variable name (pass1, pass2, etc.)                           */
/*   echo       echo the typed chars or stars                                */
/*   field_type see FIELD_TYPE_... defines for types                         */
/*   value      if the field is pre-filled                                   */
void print_form_field(char *field, char *var, int echo, int field_type,
		      char *value) {

    print_out("<P>\n");
    print_out("%s\n", field);
    
    if (debug) {
	log_message("print_form_field: field: %s, field_type %d, value %s", 
		    field, field_type, value);
    }

    if (field_type == FIELD_TYPE_EMPTY_ALTERABLE || 
        field_type == FIELD_TYPE_PREFILLED_ALTERABLE ) {
	print_out("<INPUT TYPE=\"%s\"", 
		  echo==FIELD_ECHO_YES ? "text" : "password");
	if (field_type==FIELD_TYPE_PREFILLED_ALTERABLE ) {
	    print_out(" NAME=\"%s\" SIZE=\"20\" VALUE=\"%s\">\n", var, value);
	} else {
	    print_out(" NAME=\"%s\" SIZE=\"20\">\n", var);
	}
    } else if (field_type == FIELD_TYPE_FREE_RIDE ) {
	print_out("%s\n", FREE_RIDE_MESSAGE);
	print_out("<INPUT TYPE=\"hidden\"");
	print_out(" NAME=\"%s\" VALUE=\"%s\">\n", var, value);
    } else if (field_type == FIELD_TYPE_PREFILLED_UNALTERABLE ) {
	print_out("<span style=\"background: #eeeeee; color:black\">");
	print_out("<tt>%s</tt></span>\n", value);
	print_out("<INPUT TYPE=\"hidden\"");
	print_out(" NAME=\"%s\" VALUE=\"%s\">\n", var, value);
    }
}

void print_login_page(login_rec *l, login_rec *c, char *message, 
		      char *reason, int need_clear_login, int need_clear_greq)
{
    char	*log_in_with = NULL;
    char	*field1_prompt = NULL;
    char	*field2_prompt = NULL;
    char	*field3_prompt = NULL;
    char	*focus_field = NULL;
    char	focus[PBC_1K];
    char	message_out[PBC_1K];
    char	*prefilled_user = NULL;
    int		field1_type = FIELD_TYPE_EMPTY_ALTERABLE;
    int		field2_type = FIELD_TYPE_EMPTY_ALTERABLE;
    int		field3_type = FIELD_TYPE_EMPTY_ALTERABLE;

    log_message("%s Printing login page, reason: %s", l->first_kiss, reason);

#ifdef FORM_NOT_IN_TMPL
    switch (l->creds) {
    case PBC_CREDS_CRED1:
        field1_prompt = strdup(PROMPT_UWNETID);
        field2_prompt = strdup(PROMPT_PASSWD);
        if ((c!=NULL && c->user!=NULL) || (l!=NULL && l->user!=NULL) ) {
            log_in_with = strdup("UW NetID password");
            focus_field = strdup("pass");
        }
        else {
            log_in_with = strdup("UW NetID and password");
            focus_field = strdup("user");
        }
        break;
    case PBC_CREDS_CRED3:
        field1_prompt = strdup(PROMPT_UWNETID);
        field2_prompt = strdup(PROMPT_PASSWD);
        field3_prompt = strdup(PROMPT_SECURID);
        if (l->ride_free_creds == PBC_CREDS_CRED1 ) {
            log_in_with = strdup("SecurID");
            focus_field = strdup("pass2");
        } 
        else {
            if ((c!=NULL && c->user!=NULL) || (l!=NULL && l->user!=NULL) ) {
                log_in_with = strdup("password, and SecurID");
                focus_field = strdup("pass");
            }
            else {
                log_in_with = strdup("UW NetID, password, and SecurID");
                focus_field = strdup("user");
            }
        }
        break;
    default:
        field1_prompt = NULL;
        break;
    }
    
    /* wads of weird logic to determine what the form fields look like */
    if(field1_prompt != NULL) {
        if (c != NULL && c->user != NULL ) {
            field1_type = FIELD_TYPE_PREFILLED_UNALTERABLE;
            prefilled_user = strdup(c->user);
        }
        if (l != NULL && l->user != NULL ) {
            field1_type = FIELD_TYPE_PREFILLED_UNALTERABLE;
            prefilled_user = strdup(l->user);
        }
        if (l->ride_free_creds == PBC_CREDS_CRED1 && 
	    l->creds == PBC_CREDS_CRED3) {
            field1_type=FIELD_TYPE_FREE_RIDE;
        }
        if ((field1_type == FIELD_TYPE_PREFILLED_UNALTERABLE && 
	     c != NULL && c->alterable_username == PBC_TRUE) ||
            (field1_type == FIELD_TYPE_PREFILLED_UNALTERABLE && 
	     l->alterable_username == PBC_TRUE) ) {
            field1_type=FIELD_TYPE_PREFILLED_ALTERABLE;
            free(focus_field);
            focus_field = strdup("user");
        }
    }
    if(field2_prompt != NULL) {
        if (l->ride_free_creds == PBC_CREDS_CRED1 && 
	    l->creds == PBC_CREDS_CRED3) {
            field2_type=FIELD_TYPE_FREE_RIDE;
        }
    }

    /* tell the stoopid browser where to put the cursor */
    sprintf(focus, "onLoad=\"document.query.%s.focus()\"", focus_field);
#endif

    /* text before the form fields */
    if (message == NULL || strcmp(message, PRINT_LOGIN_PLEASE) == 0 ) {
        sprintf(message_out, "<P>The resource you requested requires you to log in with your %s.</P>\n", log_in_with);
    }
    else {
        strcpy(message_out, message);
    }

    if (need_clear_login )   /* depreceated, we now expire L cookie */
        ;  /* used to be clear_login_cookie(); */
    if (need_clear_greq )    /* depreceated, we clear the g req later */
        ;  /* noop */

    tmpl_print_out(TMPL_FNAME "login_part1", focus, reason, message_out);

#ifdef FORM_NOT_IN_TMPL

    if(field1_prompt != NULL)
        print_form_field(field1_prompt, 
                         "user", 
                         FIELD_ECHO_YES, 
                         field1_type, 
                         prefilled_user);
    if(field2_prompt != NULL)
        print_form_field(field2_prompt, 
                         "pass", 
                         FIELD_ECHO_STARS, 
                         field2_type, 
                         "");
    if(field3_prompt != NULL) 
        print_form_field(field3_prompt, 
                         "pass2", 
                         FIELD_ECHO_YES, 
                         field3_type, 
                         "");
#endif


    print_login_page_hidden_stuff(l);
    tmpl_print_out(TMPL_FNAME "login_part2", message, reason);

}

char *check_login_uwnetid(login_rec *l)
{

    if (debug) {
	fprintf(stderr, "check_login_uwnetid: hello\n");
    }

    if (l->ride_free_creds == PBC_CREDS_CRED1 && l->creds == PBC_CREDS_CRED3) {
	if (debug) {
	    fprintf(stderr, "check_login_uwnetid: free ride for this cred\n");
	}
        return(CHECK_LOGIN_RET_SUCCESS);
    }

    if (l->user == NULL || l->pass == NULL ) {
	if (debug) {
	    fprintf(stderr, "check_login_uwnetid: user or pass absent\n");
	}
        return(CHECK_LOGIN_RET_FAIL);
    }

    if (auth_kdc(l->user, l->pass) == NULL ) {
	if (debug) {
	    fprintf(stderr, "check_login_uwnetid: auth_kdc say ok\n");
	}
        clear_error("uwnetid-fail", "uwnetid auth ok");
        return(CHECK_LOGIN_RET_SUCCESS);
    }
    else {
	if (debug) {
	    fprintf(stderr, "check_login_uwnetid: auth_kdc say fail\n");
	}
        return(CHECK_LOGIN_RET_FAIL);
    }

}

char *check_login_securid(char *user, char *sid, int next, login_rec *l)
{

    if (debug) {
	fprintf(stderr, "check_login_securid: hello\n");
    }

    if (user == NULL || sid == NULL ) {
	if (debug) {
	    fprintf(stderr, "check_login_securid: user or sid absent\n");
	}
        return(CHECK_LOGIN_RET_FAIL);
    }

    if (auth_securid(user, sid, next, l) == NULL ) {
	if (debug) {
	    fprintf(stderr, "check_login_securid: auth_securid say ok\n");
	}
        clear_error("securid-fail", "securid auth ok");
        return(CHECK_LOGIN_RET_SUCCESS);
    }
    else {
	if (debug) {
	    fprintf(stderr, "check_login_securid: auth_securid say NOPE!\n");
	}
        log_error(2, "securid-err", 1, "problem doing securid auth");
        return(CHECK_LOGIN_RET_FAIL);
    }

}

/* successful auth returns CHECK_LOGIN_RET_SUCCESS                           */
char *check_login(login_rec *l, login_rec *c)
{
    char	*ret;

    if (debug) {
	fprintf(stderr, "check_login: hello\n");
    }

    if (!(ret = malloc(PBC_1K)) ) {
        abend("out of memory");
    }

    strcpy(ret, CHECK_LOGIN_RET_BAD_CREDS);

    if (l->creds == PBC_CREDS_CRED1 ) {
        strcpy(ret, check_login_uwnetid(l));
    }
    else if (l->creds == PBC_CREDS_CRED3 ) {
        strcpy(ret, check_login_securid(l->user, l->pass2, 
					l->next_securid, l));
        if (!strcmp(ret, CHECK_LOGIN_RET_SUCCESS) ) {
            /* now check the uwnetid part */
            strcpy(ret, check_login_uwnetid(l));
        }
        else {
            return ret;
        }
    }

    return(ret);

}

/* for some n seconds after authenticating we don't ask the user to */
/* retype their credentials                                         */
/*    returns credentials ok for ride free                          */
char ride_free_zone(login_rec *l, login_rec *c)
{
    char	*cookie;
    time_t	t;

    if (debug) {
	fprintf(stderr, "ride_free_zone: hello\n");
    }

    if (!(cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }

    if (init_crypt() == PBC_FAIL) {
        return(PBC_CREDS_NONE);
    }

    if (c == NULL )
        c = verify_unload_login_cookie(l);

    if (c == NULL )
        return(PBC_CREDS_NONE);

    if (debug) {
	fprintf(stderr, "in ride_free_zone ready to look at cookie contents user: %s\n", c->user);
    }

    /* look at what we got back from the cookie */
    if (! c->user ) {
        log_error(5, "system-problem", 0, "no user from L cookie? user from g_req: %s", l->user);
        return(PBC_CREDS_NONE);
    }

    if ((c->create_ts + RIDE_FREE_TIME) < (t=time(NULL)) ) {
	if (debug) {
	    log_message("%s No Free Ride login cookie created: %d now: %d user: %s",
			l->first_kiss,
			c->create_ts, 
                        t,
			c->user);
	}
        return(PBC_CREDS_NONE);
    }
    else {

	if (debug) {
	    log_message("%s Yeah! Free Ride!!! login cookie created: %d now: %d user: %s",
			l->first_kiss,
			c->create_ts, 
                        t,
			c->user);
	}

        if (l->user == NULL )
            l->user = c->user;

        return(PBC_CREDS_CRED1);
    }

}


/* returns NULL if the L cookie is valid                                     */
/*   else a description of it's invalid nature                               */
char *check_l_cookie(login_rec *l, login_rec *c)
{
    time_t	t;
    char	*g_version;
    char	*l_version;

    if (debug) {
	fprintf(stderr, "check_l_cookie: hello\n");
    }

    if (init_crypt() == PBC_FAIL) {
        return("couldn't load crypt key");
    }

    if (c == NULL )
        c = verify_unload_login_cookie(l);

    if (c == NULL)
        return("couldn't decode login cookie");

    if (debug) {
	fprintf(stderr, "in check_l_cookie ready to look at cookie contents %s\n", c->user);
    }

    /* look at what we got back from the cookie */
    if ( c->user == NULL ) {
        log_error(5, "system-problem", 0, "no user from L cookie? user from g_req: %s", l->user);
        return "malformed";
    }

    if (check_l_cookie_expire(c, t=time(NULL)) == PBC_FAIL ) {
        log_message("%s expired login cookie; created: %d expire: %d now: %d",
			l->first_kiss,
			c->create_ts, 
			c->expire_ts, 
                        t);
        return "expired";
	c->expire_ts = l->expire_ts = 0;
    }

    if (debug) {
	fprintf(stderr, 
		"check_l_cookie ready for creds, c: %c l: %c\n", 
		c->creds, l->creds);
    }

    /* probably a pinit or logout */
    if (c->creds == PBC_CREDS_NONE || l->creds == PBC_CREDS_NONE ) {
        return("no_creds");
    }

    if (c->creds != l->creds ) {
        if (l->creds == PBC_CREDS_CRED1 ) {
            if (c->creds != PBC_CREDS_CRED3 ) {
                log_message("%s wrong_creds: from login cookie: %s from request: %s", l->first_kiss, c->creds, l->creds);
                return("wrong_creds");
            }
            else {
                /* take the creds from the login cookie if they are higher */
                l->creds = c->creds;
            }
        }
        else {
            log_message("%s wrong_creds: from login cookie: %s from request: %s", l->first_kiss, c->creds, l->creds);
            return("wrong_creds");
        }
    }

    if (debug) 
	fprintf(stderr, "check_l_cookie: done dorking with creds\n");

    l_version = c->version; g_version = l->version;
    if (*l_version != *g_version ) {
        log_error(5, "version", 0, "wrong major version: from L cookie %s, from g_req %s for host %s", l_version, g_version, l->host);
        return("wrong major version");
    }
    if (*(l_version+1) != *(g_version+1) ) {
        log_message("%s warn: wrong minor version: from l cookie %s, from g_req %s for host %s", l->first_kiss, l_version, g_version, l->host);
    }

    if (debug) 
	fprintf(stderr, "check_l_cookie: done looking at version\n");

    l->user = c->user;
    l->creds = c->creds;
    return((char *)NULL);
}


/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
/*	functions                                                          */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

void print_j_test() 
{

    print_out("%s", J_TEST_TEXT1);
    print_out("%s", J_TEST_TEXT2);
    print_out("%s", J_TEST_TEXT3);
    print_out("%s", J_TEST_TEXT4);
    print_out("%s", J_TEST_TEXT5);

}

void notok_no_g_or_l() 
{
    print_j_test();

    print_out("<NOSCRIPT>\n");

    print_out("%s\n", NOTOK_NO_G_OR_L_TEXT1);

    print_out("</NOSCRIPT>\n");

}

void notok_no_g() 
{
    print_out("%s", NOTOK_NO_G_TEXT1);

}

void notok_formmultipart() 
{
    print_out("%s", NOTOK_FORMMULTIPART_TEXT1);

}

void notok_need_ssl() 
{
    print_out("%s", NOTOK_NEEDSSL_TEXT1);
    log_message("host %s came in on a non-ssl port, why?", cgiRemoteAddr);
}

void notok_bad_agent() 
{
    print_out("%s", NOTOK_BAD_AGENT_TEXT1);
    print_out("The browser you are using identifies itself as:<P><TT></TT>",
                 user_agent());
    print_out("%s", NOTOK_BAD_AGENT_TEXT2);

}

void notok_generic() 
{
    print_out("%s", NOTOK_GENERIC_TEXT1);

}

void notok ( void (*notok_f)() )
{
    /* if we got a form multipart cookie, reset it */
    if ( getenv("HTTP_COOKIE") && strstr(getenv("HTTP_COOKIE"), 
					 PBC_FORM_MP_COOKIENAME) ) {
        print_out("Set-Cookie: %s=%s; domain=%s; path=/; expires=%s\n", 
            PBC_FORM_MP_COOKIENAME, 
            PBC_CLEAR_COOKIE,
            enterprise_domain(), 
            EARLIEST_EVER);
    }

    tmpl_print_out(TMPL_FNAME "notok_part1");
    notok_f();
    tmpl_print_out(TMPL_FNAME "notok_part2");

}

int set_pinit_cookie() {

#ifdef PORT80_TEST
    print_out("Set-Cookie: %s=%s; domain=%s; path=/\n", 
#else
    print_out("Set-Cookie: %s=%s; domain=%s; path=/; secure\n", 
#endif
		PBC_PINIT_COOKIENAME,
                PBC_SET,
                login_host());

    return(PBC_OK);
}

int clear_pinit_cookie() {

#ifdef PORT80_TEST
    print_out("Set-Cookie: %s=%s; domain=%s; path=/; expires=%s\n",
#else
    print_out("Set-Cookie: %s=%s; domain=%s; path=/; expires=%s; secure\n",
#endif
            PBC_PINIT_COOKIENAME, 
            PBC_CLEAR_COOKIE,
            login_host(),
            EARLIEST_EVER);

    return(PBC_OK);

}

int pinit_responce(login_rec *l, login_rec *c)
{

    if(debug) {
        log_message("pinit_responce: hello");
    }

    clear_pinit_cookie();

    tmpl_print_out(TMPL_FNAME "pinit_responce1");
    tmpl_print_out(TMPL_FNAME "welcome_back",
               (c == NULL || c->user == NULL ? "unknown" : c->user));
    tmpl_print_out(TMPL_FNAME "logout_time_remaining",
               time_remaining_text(c));
    tmpl_print_out(TMPL_FNAME "pinit_responce2");
    return(PBC_OK);

}

/**
 * looks at what cookies we hav to do an inital vectoring of the request
 *      should somehow be merged into vector request but all of these  
 *	things should happen first.
 * @param *c from login cookie
 * @param *l from login session
 * @returns PBC_FAIL if the program should finish
 * @returns PBC_OK   if the program should continue
 */
int cookie_test(login_rec *l, login_rec *c) 
{
    char        *cookies;
    char        cleared_g_req[PBC_1K];

    if(debug)
        log_message("cookie_test: hello");

    /* if it's a reply from the login server we immediatly leave */
    if ( l->reply == FORM_REPLY && l->appid != NULL) {
        return(PBC_OK);
    }

    /* if no cookies, then must be pinit */
    if ( (cookies = getenv("HTTP_COOKIE")) == NULL ){
        pinit(l, c);
        return(PBC_FAIL);
    }
    
    if(debug)
        log_message("cookie_test: cookies: %s", cookies);

    /* we don't currently handle form-multipart */
    /* the formmultipart cookie is set by the module */
    if ( strstr(cookies, PBC_FORM_MP_COOKIENAME) ) {
        notok(notok_formmultipart);
        return(PBC_FAIL);
    }

    /* after a pinit login we give the user something nice to look at */
    if ( strstr(cookies, PBC_PINIT_COOKIENAME) != NULL ) {
        pinit_responce(l, c);
        return(PBC_FAIL);
    }

    /* a cleared G req is as bad as no g req */
    snprintf(cleared_g_req, PBC_1K, "%s=%s", PBC_G_REQ_COOKIENAME, 
		PBC_CLEAR_COOKIE);

    /* no g_req or cleared g_req then pinit */
    if ( strstr(cookies, PBC_G_REQ_COOKIENAME) == NULL || 
         strstr(cookies, cleared_g_req) != NULL ) {
        pinit(l, c);
        return(PBC_FAIL);
    }
    
    return(PBC_OK);

}

/*	################################### The beginning of the table       */
void print_table_start()
{
    print_out("<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"580\">\n");

}

/*	################################### da copyright, it's ours!         */
void print_copyright()
{
    print_out("<small>Copyright &#169; 2001 University of Washington</small>\n");

}

/*	################################### UWNetID Logo                     */
void print_uwnetid_logo()
{
    print_out("<img src=\"/images/login.gif\" alt=\"\" height=\"64\" width=\"208\" oncontextmenu=\"return false\">\n");

}


/*	################################### header stuff                     */
void print_http_header()
{
        print_out("Pragma: No-Cache\n");
        print_out("Cache-Control: no-store, no-cache, must-revalidate\n");
        print_out("Expires: Sat, 1 Jan 2000 01:01:01 GMT\n");
        print_out("Content-Type: text/html\n\n");

}

/*	################################### hidden stuff                     */
void print_login_page_hidden_stuff(login_rec *l)
{

    print_out("\n");
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n", 
		PBC_GETVAR_APPSRVID, (l->appsrvid ? l->appsrvid : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_APPID, (l->appid ? l->appid : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%c\">\n", 
                "creds_from_greq", l->creds_from_greq);
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%c\">\n", 
                PBC_GETVAR_CREDS, l->creds);
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_VERSION, (l->version ? l->version : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_METHOD, (l->method ? l->method : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_HOST, (l->host ? l->host : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_URI, (l->uri ? l->uri : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_ARGS, (l->args ? l->args : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FR, (l->fr ? l->fr : "") );

    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_REAL_HOST, (l->real_hostname?l->real_hostname:"") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_APPSRV_ERR, (l->appsrv_err ? l->appsrv_err : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FILE_UPLD, (l->file ? l->file : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FLAG, (l->flag ? l->flag : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_REFERER, (l->referer ? l->referer : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_POST_STUFF, (l->post_stuff ? l->post_stuff : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
		PBC_GETVAR_SESSION_REAUTH, l->session_reauth);

    print_out("<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
		PBC_GETVAR_FIRST_KISS, (l->first_kiss ? l->first_kiss : "") );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
		PBC_GETVAR_NEXT_SECURID, 
                (l->next_securid ? l->next_securid : 0) );
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
		PBC_GETVAR_PINIT, l->pinit);

    /* this tags the incoming request as a form reply */
    print_out("<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
		PBC_GETVAR_REPLY, FORM_REPLY);

}

char *to_lower(char *in)
{
    char	*p;

    for(p = in; *p; p++)
        *p = tolower(*p);

    return(in);

}

void clean_ok_browsers_line(char *in)
{
    char	*p;

    for(p = in; *p; p++) {
        *p = tolower(*p);
        if (*p == '\n' ) 
            *p-- = '\0';
    }

}

int check_user_agent()
{
    char        line[PBC_1K];
    char        agent_clean[PBC_1K];
    FILE	*ifp;

    if ( !(ifp = fopen(OK_BROWSERS_FILE, "r")) ) {
        log_error(2, "system-problem", 0,
		  "can't open ok browsers file: %s, continuing", 
		  OK_BROWSERS_FILE);
        return(0);
    }

    /* make the user agent lower case */
    strncpy( agent_clean, user_agent(), sizeof(agent_clean) );
    clean_ok_browsers_line(agent_clean);

    while( fgets(line, sizeof(line), ifp) != NULL ) {
        clean_ok_browsers_line(line);
        if (line[0] == '#' )
            continue;
        if (strstr( agent_clean, line ) ) {
            return(1);
        }
    }

    return(0);

}


void print_redirect_page(login_rec *l, login_rec *c)
{
    int			serial = 0;
    char		*g_cookie;
    char		*l_cookie;
    char		*redirect_uri;
    char		*message;
    char		*args_enc = NULL; 
    char		*redirect_final = NULL;
    char		*redirect_dest = NULL;
    char		g_set_cookie[PBC_1K];
    char		l_set_cookie[PBC_1K];
    char		*post_stuff_lower = NULL;
    char		*p = NULL;
    int			g_res, l_res;
    int			limitations_mentioned = 0;
    char		*submit_value = NULL;
    cgiFormEntry	*cur;
    cgiFormEntry	*next;
    time_t		now;

    if (debug)
	fprintf(stderr, "print_redirect_page: hello\n");

    if (!(redirect_dest = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    if (!(redirect_final = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    if (!(message = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    if (!(g_cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    if (!(l_cookie = malloc(PBC_4K)) ) {
        abend("out of memory");
    }
    serial = get_next_serial();

    if (init_crypt() == PBC_FAIL) {
        sprintf( message, "%s%s%s%s%s%s",
		PBC_EM1_START,
		TROUBLE_CREATING_COOKIE,
		PBC_EM1_END,
      		PBC_EM2_START,
		PROBLEMS_PERSIST,
         	PBC_EM2_END);
        print_login_page(l, c, message, "cookie create failed", 
			 NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
        log_error(1, "system-problem", 0,
		  "Not able to create cookie for user %s at %s-%s", 
		  l->user, l->appsrvid, l->appid);
	free(message);
        return;
    }

    /* cook up them cookies */
    l_res = create_cookie(url_encode(l->user),
        url_encode(l->appsrvid),
        url_encode(l->appid),
        PBC_COOKIE_TYPE_L,
        l->creds,
        serial,
	(c == NULL || c->expire_ts == 0 ? compute_l_expire(l) : c->expire_ts),
        l_cookie,
        login_private_keyfile(),
        PBC_4K);
    g_res = create_cookie(url_encode(l->user),
        url_encode(l->appsrvid),
        url_encode(l->appid),
        PBC_COOKIE_TYPE_G,
        l->creds_from_greq,
        serial,
        0,
        g_cookie,
        granting_private_keyfile(),
        PBC_4K);

    /* if we have a problem then bail with a nice message */
    if ( !l_res || !g_res ) {
          sprintf( message, "%s%s%s%s%s%s",
		PBC_EM1_START,
		TROUBLE_CREATING_COOKIE,
		PBC_EM1_END,
      		PBC_EM2_START,
		PROBLEMS_PERSIST,
         	PBC_EM2_END);
          print_login_page(l, c, message, "cookie create failed",
			   NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
          log_error(1, "system-problem", 0,
		    "Not able to create cookie for user %s at %s-%s",
		    l->user, l->appsrvid, l->appid);
          free(message);
          return;
    }

    /* create the http header line with the cookie */
    snprintf( g_set_cookie, sizeof(g_set_cookie)-1, 
#ifdef PORT80_TEST
		"Set-Cookie: %s=%s; domain=%s; path=/", 
#else
		"Set-Cookie: %s=%s; domain=%s; path=/; secure", 
#endif
		PBC_G_COOKIENAME,
                g_cookie,
                enterprise_domain());
    snprintf( l_set_cookie, sizeof(l_set_cookie)-1, 
#ifdef PORT80_TEST
		"Set-Cookie: %s=%s; domain=%s; path=%s", 
#else
		"Set-Cookie: %s=%s; domain=%s; path=%s; secure", 
#endif
		PBC_L_COOKIENAME,
                l_cookie,
                login_host(),
                LOGIN_DIR);

    /* whip up the url to send the browser back to */
    if (!strcmp(l->fr, "NFR") )
        redirect_uri = l->uri;
    else
        redirect_uri = l->fr;

#ifdef PORT80_TEST
    snprintf(redirect_dest, PBC_4K-1, "http://%s%s%s", 
#else
    snprintf(redirect_dest, PBC_4K-1, "https://%s%s%s", 
#endif
		l->host, (*redirect_uri == '/' ? "" : "/"), redirect_uri);

    if (l->args ) {
        args_enc = calloc (1, strlen (l->args));
	libpbc_base64_decode(l->args, args_enc);
        snprintf( redirect_final, PBC_4K-1, "%s?%s", redirect_dest, args_enc );
    } 
    else {
        strcpy( redirect_final, redirect_dest );
    }

    /* we don't use the fab log_message funct here because the url encoding */
    /* will look like format chars in future *printf's */
    now = time(NULL);
    fprintf(stderr,
	    "%s: PUBCOOKIE_DEBUG: %s: %s Redirect user: %s redirect: %s\n",
	    libpbc_time_string(now),
	    ANY_LOGINSRV_MESSAGE,
	    l->first_kiss,
	    l->user, 
	    redirect_final);

    /* now blat out the redirect page */
    if( l->pinit == PBC_FALSE )   /* don't need a G cookie for a pinit */
        print_out("%s\n", g_set_cookie);
    else
        set_pinit_cookie();
    print_out("%s\n", l_set_cookie);
    clear_greq_cookie();

    /* incase we have a post */
    if ( l->post_stuff ) {
        /* cgiParseFormInput will extract the arguments from the post */
        /* make them available to subsequent cgic calls */
        if (cgiParseFormInput(l->post_stuff, strlen(l->post_stuff))
                   != cgiParseSuccess ) {
            log_error(5, "misc", 0,
		      "couldn't parse the decoded granting request cookie");
            notok(notok_generic);
            exit(0);
        }

        print_http_header();

	print_out("<HTML>");
	/* when the page loads click on the last element */
        /* (which will always be the submit) in the array */
        /* of elements in the first, and only, form. */
	print_out("<BODY BGCOLOR=\"white\" onLoad=\"");

        /* depending on whether-or-not there is a SUBMIT field in the form */
        /* use the correct javascript to autosubmit the POST */
        /* this should probably be upgraded to only look for submits as */
        /* field names, not anywhere else */
        post_stuff_lower = strdup(l->post_stuff);
        for(p=post_stuff_lower; *p != '\0'; p++)
            *p = tolower(*p);
        if (strstr(post_stuff_lower, "submit") != NULL )
            print_out("document.query.submit.click()");
        else
            print_out("document.query.submit");

        print_out("\">\n");

	print_out("<center>");
        print_table_start();
	print_out("<tr><td align=\"LEFT\">\n");

	print_out("<form method=\"POST\" action=\"%s\" ", redirect_final);
        print_out("enctype=\"application/x-www-form-urlencoded\" ");
        print_out("name=\"query\">\n");

        cur = cgiFormEntryFirst;
        while (cur) {
            /* in the perl version we had to make sure we were getting */
            /* rid of this header line                                 */
            /*        cur->attr =~ s%^\s*HTTP/1.1 100 Continue\s*%%mi;   */

            /* if there is a " in the value string we have to put */
            /* in a TEXTAREA object that will be visible          */
            if (strstr(cur->value, "\"") || 
		strstr(cur->value, "\r") || 
		strstr(cur->value, "\n") ) {
                if (! limitations_mentioned ) {
                    print_out("Certain limitations require that this be shown, please ignore it<BR>\n");
                    limitations_mentioned++;
                }
                print_out("<textarea cols=\"0\" rows=\"0\" name=\"%s\">\n", 
			  cur->attr);
                print_out("%s</textarea>", string_encode (cur->value));
                print_out("<P>\n");
            }
            else {
                /* we don't want to cover other people's submits */
                if ( !strcmp(cur->attr, "submit") )  {
                    submit_value = string_encode (cur->value);
                }
                else {
                    print_out("<input type=\"hidden\" ");
		    print_out("name=\"%s\" value=\"%s\">\n",
			      cur->attr, cur->value);
                }
    	    }

            /* move onto the next attr/value pair */
            next = cur->next;
            cur = next;
        } /* while cur */


        print_out("</td></tr>\n");
        print_uwnetid_logo();
        print_out("<P>");
        print_out("%s\n", PBC_POST_NO_JS_TEXT);
        print_out("</td></tr></table>\n");

        /* put submit at the bottom so it looks better and */
        if (submit_value )
            print_out("<input type=\"submit\" name=\"submit\" value=\'%s\'>\n", submit_value);
        else
            print_out("<input type=\"submit\" value=\"%s\">\n",
		      PBC_POST_NO_JS_BUTTON);

        print_out("</form>\n");
        print_copyright();
        print_out("</center>");
        print_out("</BODY></HTML>\n");
    }
    else {
        /* non-post redirect area                 non-post redirect area */

        /* the refresh header should go into the template as soon as it's*/
        /* been tested                                                   */
      /*        print_out("Location: %s\n", redirect_final); */
        tmpl_print_out(TMPL_FNAME "nonpost_redirect", redirect_final,
		       REFRESH, redirect_final, redirect_final);
    } /* end if post_stuff */

    free(g_cookie);
    free(l_cookie);
    free(message);
    free(redirect_final);

}

/* fills in the login_rec from the form submit and granting request */
login_rec *get_query() 
{
    login_rec		*l = malloc(sizeof(login_rec));
    char		*g_req;
    char		*g_req_clear = NULL;
    struct timeval	t;

    if (debug) {
	fprintf(stderr, "get_query: hello\n");
    }

    init_login_rec(l);

    /* even if we hav a granting request post stuff will be in the request */
    l->post_stuff = get_string_arg(PBC_GETVAR_POST_STUFF, YES_NEWLINES_FUNC);

    if (debug) {
	fprintf(stderr, "get_query: looked at post_stuff\n");
    }

    /* take everything out of the environment */
    l = load_login_rec(l);

    /* cgiParseFormInput will extract the arguments from the granting        */
    /* cookie string and make them available to subsequent cgic calls        */

    /* if the reply field isn't set then this is not be a submit from a login*/
    if (l->reply != FORM_REPLY ) {
        /* get greq cookie */
        g_req = get_granting_request();
     
        /* is granting cookie missing or "spent" */
        if( g_req != NULL && 
            strcmp(g_req, PBC_CLEAR_COOKIE) != 0 ) {

            g_req_clear = decode_granting_request(g_req);

	    if (debug) {
	        fprintf(stderr, "get_query: decoded granting request: %s\n", 
		    g_req_clear);
	    }

            if (cgiParseFormInput(g_req_clear, strlen(g_req_clear)) 
                   != cgiParseSuccess ) {
                log_error(5, "misc", 0,
		      "couldn't parse the decoded granting request cookie");
                notok(notok_generic);
                return(NULL);
            }
            l = load_login_rec(l);

            /* capture the cred that the app asked for */
            l->creds_from_greq  = l->creds;
    
        }
        free( g_req );
        free( g_req_clear );
    }

    /* because it's convenient we add some info that will follow the req */
    if (l->first_kiss == NULL ) {
        l->first_kiss = malloc(30);
        gettimeofday(&t, 0);
        sprintf(l->first_kiss, "%ld-%ld", t.tv_sec, t.tv_usec);
    }

    /* reason why user was sent back to the login srver */
    /* appsrv_err is a string message or code */
    if (l->appsrv_err != NULL ) {
        if (strlen(l->appsrv_err) > 3 ) {  /* the whole message */
            l->appsrv_err_string = strdup(l->appsrv_err);
        }
        else {                             /* the newer was, just a code */
	  l->appsrv_err_string = strdup(redirect_reason[atoi(l->appsrv_err)]);
        }
    }

    if (debug) { 
	fprintf(stderr, "get_query: from login user: %s\n", l->user);
	fprintf(stderr, "get_query: from login version: %s\n", l->version);
	fprintf(stderr, "get_query: from login creds: %c\n", l->creds);
	fprintf(stderr, "get_query: from login appid: %s\n", l->appid);
	fprintf(stderr, "get_query: from login host: %s\n", l->host);
	fprintf(stderr, "get_query: from login appsrvid: %s\n", l->appsrvid);
	fprintf(stderr, "get_query: from login next_securid: %d\n", 
		l->next_securid);
	fprintf(stderr, "get_query: from login first_kiss: %d\n",
		(int)l->first_kiss);
	fprintf(stderr, "get_query: from login post_stuff: %s\n", 
		(l->post_stuff==NULL ? "" : l->post_stuff));
    }

    return(l);

} /* get-query */

/* uses libpubcookie calls to check the cookie and load the login rec with  */
/* cookie contents                                                          */
login_rec *verify_unload_login_cookie (login_rec *l)
{
    md_context_plus     *ctx_plus;
    pbc_cookie_data     *cookie_data;
    char		*cookie = NULL;
    login_rec		*new = NULL;
    time_t		t;

    if (debug)
	fprintf(stderr, "verify_unload_login_cookie: hello\n");

    if (!(cookie = malloc(PBC_4K)) )
        abend("out of memory");

    /* get the login cookie */
    if ((get_cookie(PBC_L_COOKIENAME, cookie, PBC_4K-1)) == PBC_FAIL )
        return((login_rec *)NULL);

    new = malloc(sizeof(login_rec));
    init_login_rec(new);

    if ((ctx_plus = libpbc_verify_init(login_public_keyfile())) == NULL )
        abend("Couldn't load public login key");

    if (init_crypt() == PBC_FAIL) 
        return((login_rec *)NULL);

    if ((cookie_data=libpbc_unbundle_cookie(cookie, ctx_plus, c_stuff))	== NULL)
        return((login_rec *)NULL);

    new->user = (*cookie_data).broken.user;
    new->version = (*cookie_data).broken.version;
    new->type = (*cookie_data).broken.type;
    new->creds = (*cookie_data).broken.creds;
    new->serial = (*cookie_data).broken.serial;
    new->appsrvid = (*cookie_data).broken.appsrvid;
    new->appid = (*cookie_data).broken.appid;
    new->create_ts = (*cookie_data).broken.create_ts;
    new->expire_ts = (*cookie_data).broken.last_ts;

    if (check_l_cookie_expire(new, t=time(NULL)) == PBC_FAIL)
        new->alterable_username = PBC_TRUE;

    if (debug) {
	fprintf(stderr, "verify_unload_login_cookie: bye!  user is %s\n", 
		new->user);
    }

    return(new);

}

int create_cookie(char *user_buf,
                  char *appsrvid_buf,
                  char *appid_buf,
                  char type,
                  char creds,
                  int serial,
		  time_t expire,
                  char *cookie,
                  char *priv_key_file,
 	          int max)
{
    /* special data structs for the crypt stuff */
    md_context_plus 	*ctx_plus;
    /* measured quantities */
    unsigned char 	user[PBC_USER_LEN];
    unsigned char 	appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char 	appid[PBC_APP_ID_LEN];
    /* local junk */
    char		*cookie_local;

    if(debug)
        fprintf(stderr, "create_cookie: hello\n"); 
    
    /* right size the args */
    strncpy(user, user_buf, sizeof(user));
    user[sizeof(user)-1] = '\0';
    strncpy(appsrvid, appsrvid_buf, sizeof(appsrvid));
    appsrvid[sizeof(appsrvid)-1] = '\0';
    strncpy(appid, appid_buf, sizeof(appid));
    appid[sizeof(appid)-1] = '\0';

    if ((ctx_plus = libpbc_sign_init(priv_key_file)) == NULL ) {
        abend("Cound not load private key file");
    }
    
    if(debug)
        fprintf(stderr, "create_cookie: ready to go get cookie, with expire_ts: %d\n", (int)expire); 
    
    /* go get the cookie */
    cookie_local = libpbc_get_cookie_with_expire(user, type, creds, serial, 
			             expire, appsrvid, appid, ctx_plus, 
                                     c_stuff);
    
    strncpy (cookie, cookie_local, max);
    return (PBC_OK);

}

