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
 * $Revision: 1.103 $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

/* LibC */
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTIME_H */

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif /* HAVE_STDARG_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif /* HAVE_SYS_UTSNAME_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif /* HAVE_FCNTL_H */

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif /* HAVE_PWD_H */

/* openssl */
#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

/* cgic */
#ifdef HAVE_CGIC_H
# include <cgic.h>
#else
# error "cgic is required for building the login server"
#endif /* HAVE_CGIC_H */

/* An apache "pool" */
typedef void pool;

/* pubcookie things */
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_configure.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "index.cgi.h"
#include "pbc_logging.h"
#include "strlcpy.h"
#include "snprintf.h"

#include "flavor.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/* the mirror file is a mirror of what gets written out of the cgi */
/* of course it is overwritten each time this runs                 */
FILE *mirror;

/* 'htmlout' stores the HTML text the CGI generates until it exits */
FILE *htmlout;
/* 'headerout' stores the HTTP headers the CGI generates */
FILE *headerout;

/* do we want debugging? */
int debug;

/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
/*      general utility thingies                                           */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */

/*
 * return the length of the passed file in bytes or 0 if we cant tell
 * resets the file postion to the start
 */
static long file_size(pool *p, FILE *afile)
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
static char *get_file_template(pool *p, const char *fname)
{
  char *template;
  long len, readlen;
  FILE *tmpl_file;

  tmpl_file = fopen (fname,"r");
  if (tmpl_file == NULL) {
    pbc_log_activity(p, PBC_LOG_ERROR, "unable to open template file %s",
                     fname);
    return NULL;
  }

  len=file_size(p, tmpl_file);
  if (len==0) {
      return NULL;
  }

  template = malloc (len+1);
  if (template == NULL) {
       pbc_log_activity(p, PBC_LOG_ERROR, 
		       "unable to malloc %d bytes for template file %s", 
		       len+1, fname);
      return NULL;
  }

  *template=0;
  readlen = fread(template, 1, len, tmpl_file);
  if (readlen != len) {
      pbc_log_activity(p, PBC_LOG_ERROR,
		 "abend: read %d bytes when expecting %d for template file %s", 
		 readlen, len, fname);
      free(template);
      return NULL;
  }

  template[len]=0;
  fclose(tmpl_file);
  return template;
}

/*
 * print to the passed buffer given the name of the file containing the %s info
 */
static void buf_template_vprintf(pool *p, const char *fname, char *dst, size_t n,
				 va_list ap)
{
    char *template = get_file_template(p, fname);
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "buf_tempalte_vprintf: hello");
    vsnprintf(dst, n, template, ap);
    free(template);
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "buf_tempalte_vprintf: goodbye");
}

/**
 * print_html saves HTML to be printed at exit, after HTTP headers
 * @param format a printf style formatting
 * @param ... printf style
 * @return always succeeds
 */
void print_html(pool *p, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vfprintf(htmlout, format, args);
    pbc_vlog_activity(p, PBC_LOG_DEBUG_OUTPUT, format, args);

    if (mirror) {
	vfprintf(mirror, format, args);
    }

    va_end(args);
}

/**
 * print_header saves HTTP headers to be printed at exit
 * @param format a printf style formatting
 * @param ... printf style
 * @return always succeeds
 */
void print_header(pool *p, const char *format, ...)
{

    va_list args;

    va_start(args, format);

    vfprintf(headerout, format, args);

    pbc_vlog_activity(p, PBC_LOG_DEBUG_OUTPUT, format, args);

    if (mirror) {
	vfprintf(mirror, format, args);
    }

    va_end(args);
}

/*
 * print out using a template
 */
void tmpl_print_html(pool *p, const char *fpath, const char *fname,...) {
    char buf[MAX_EXPANDED_TEMPLATE_SIZE];
    va_list args;
    char *templatefile;
    int len;
    
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "tmpl_print_html: hello");

    if (fpath == NULL) {
        fpath = TMPL_FNAME;
    }

    /* TODO: 
     * '/' should probably not be used here.  We should use an OS-Neutral path
     * seperator.
     */

    len = strlen(fpath) + strlen("/") + strlen(fname) + 1;

    templatefile = malloc( len * sizeof(char) );

    if (templatefile == NULL) {
        abend(p, "Out of memory allocating templatefile");
    }

    if ( snprintf( templatefile, len, "%s%s%s", fpath,
                   fpath[strlen(fpath) - 1 ] == '/' ? "" : "/",
                   fname ) > len )  {

        /* Need to do something, we would have overflowed.  I don't know how
         * that could happen, but it's bad. */
        abend(p, "Template filename overflow!\n");
    }

    va_start(args, fname);

    /* why is this being read here and not being used? -jeaton */
    /* format=get_file_template(p, fname); */

    buf_template_vprintf(p, templatefile, buf, sizeof(buf), args);
    va_end(args);

    fprintf(htmlout, "%s", buf);
    pbc_log_activity(p, PBC_LOG_DEBUG_OUTPUT, buf);

    if (mirror) {
        fprintf(mirror,"%s",buf);
    }

    if (templatefile != NULL)
        free(templatefile);
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "tmpl_print_html: goodbye");
}

/**
 * output the cached headers and html files.
 * should be called before exiting if we want to show anything to the client.
 */
void do_output(pool *p)
{
    /* set the cookies on the client */
    rewind(headerout);
    while (!feof(headerout)) {
	char buf[8192];
	size_t x;

	x = fread(buf, sizeof(char), sizeof(buf), headerout);
	if (x) {
	    fwrite(buf, x, 1, stdout);
	}
    }

    printf("\r\n");
    
    /* send the HTML to the client */
    rewind(htmlout);
    while (!feof(htmlout)) {
	char buf[8192];
	size_t x;

	x = fread(buf, sizeof(char), sizeof(buf), htmlout);
	if (x) {
	    fwrite(buf, x, 1, stdout);
	}
    }
    
    fflush(stdout);
}

/**
 * all of our output always uses the following headers.
 * this should probably be runtime configurable.
 * @return always succeeds
 */
void print_http_header(pool *p)
{
        print_header(p, "Pragma: No-Cache\n");
        print_header(p, "Cache-Control: no-store, no-cache, must-revalidate\n");
        print_header(p, "Expires: Sat, 1 Jan 2000 01:01:01 GMT\n");
        print_header(p, "Content-Type: text/html\n");
}

/**
 * checks a login_rec contents for expiration
 * @param *p memory pool
 * @param *c from login cookie
 * @param t now
 * @returns PBC_FAIL for expired
 * @returns PBC_OK   for not expired
 */
int check_l_cookie_expire (pool *p, login_rec *c, time_t t) 
{
    if ( c == NULL || t > c->expire_ts )
        return(PBC_FAIL);
    else
        return(PBC_OK);

}

/*
 * initialize some things in the record 
 */
void init_login_rec(pool *p, login_rec *r)
{
    r->alterable_username = PBC_FALSE;
    r->first_kiss = NULL;
    r->appsrv_err = NULL;
    r->appsrv_err_string = NULL;
    r->expire_ts = PBC_FALSE;
    r->pinit = PBC_FALSE;
    r->reply = PBC_FALSE;
    r->pre_sess_tok = 0;

    r->flavor_extension = NULL;
}

/*
 * this returns first cookie for a given name
 */
int get_cookie(pool *p, char *name, char *result, int max)
{
    char *s;
    char *ptr;
    char *target;
    char *wkspc;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "get_cookie: hello\n");

    if (!(target = malloc(PBC_20K)) ) {
        abend(p, "out of memory");
    }

    /* get all the cookies */
    if (!(s = getenv("HTTP_COOKIE")) ){
      pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		       "get_cookie: no cookies, bailing.\n");
        free(target);
        return(PBC_FAIL);
    }
    
    /* make us a local copy */
    strlcpy(target, s, PBC_20K-1);

    if (!(wkspc=strstr(target, name))) {
        free(target);
        return(PBC_FAIL);
    }
    
    /* get rid of the <name>= part from the cookie */
    ptr = wkspc = wkspc + strlen(name) + 1;
    while(*ptr) {
        if (*ptr == ';' ) {
            *ptr = '\0';
            break;
        }
        if (*ptr == '=') {
            /* somehow we're getting junk on the end of some base64-ized
               cookies. this works around the problem. xxx */
            break;
        }
        ptr++;
    }
    /* make sure that after we hit an '=', there's no other junk at the end */
    while (*ptr == '=') ptr++;
    *ptr = '\0';

    strncpy(result, wkspc, max);
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		     "get_cookie: returning cookie: %s=%s",
		     name, result);
    free(target);
    return(PBC_OK);

}


char *get_string_arg(pool *p, char *name, cgiFormResultType (*f)())
{
    int			length;
    char		*s;
    cgiFormResultType 	res;

    cgiFormStringSpaceNeeded(name, &length);
    if (!(s = calloc(length+1, sizeof(char)))) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
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
int get_int_arg(pool *p, char *name, int def) {
    int		i;

    if( cgiFormInteger(name, &i, 0) == cgiFormSuccess ) {
        return(i);
}
    else
        return(def);

}

char *clean_username(pool *p, char *in)
{
    char	*ptr;
    int		word_start = 0;

    ptr = in;
    while(*ptr) {
        /* no email addresses or full principals */
        if(*ptr == '@')
            *ptr = '\0';

        /* no spaces at the beginning of the username */
        if(*ptr == ' ' && !word_start)
            in = ptr + 1;
        else
            word_start = 1;

        /* no spaces at the end */
        if(*ptr == ' ' && word_start) {
            *ptr = '\0';
            break;
        }
	
        ptr++;
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
int expire_login_cookie(pool *p, login_rec *l, login_rec *c) {
    char	*l_cookie;
    char	*message = NULL;
    int		l_res;
    char	*user;

    char *urluser;
    char *urlappsrvid;
    char *urlappid;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "expire_login_cookie: hello");
    if ( (message = malloc(PBC_4K)) == NULL ) 
        abend(p, "out of memory");
    
    if ( (l_cookie = malloc(PBC_4K)) == NULL )
        abend(p, "out of memory");

    if( c == NULL || c->user == NULL ) {
        if( l == NULL || l->user == NULL )
            user = strdup("unknown");
        else
            user = l->user;
    }
    else {
        user = c->user;
    }

    l_res = create_cookie( p, urluser =url_encode(p, user),
                           urlappsrvid = url_encode(p, "expired"),
                           urlappid = url_encode(p, "expired"),
                           PBC_COOKIE_TYPE_L,
                           PBC_CREDS_NONE,
                           23,                  
                           time(NULL),  
                           l_cookie,
                           NULL, /* sending it to myself */
                           PBC_4K);

    if (urluser != NULL)
        free(urluser);
    if (urlappsrvid != NULL)
        free(urlappsrvid);
    if (urlappid != NULL)
        free(urlappid);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW,
		       "expire_login_cookie: l_res: %d", l_res);

    /* if we have a problem then bail with a nice message */
    if ( l_res == PBC_FAIL ) {
        sprintf( message, "%s%s%s%s%s%s",
		PBC_EM1_START,
		TROUBLE_CREATING_COOKIE,
		PBC_EM1_END,
      		PBC_EM2_START,
		PROBLEMS_PERSIST,
         	PBC_EM2_END);
        /* XXX print_login_page(l, c, "cookie create failed"); */
	pbc_log_activity(p, PBC_LOG_ERROR,
		    "Not able to create cookie for user %s at %s-%s",
		    l->user, l->appsrvid, l->appid);
        if (message != NULL)
            pbc_free(p, message);
        return(PBC_FAIL);
    }

    print_header(p, "Set-Cookie: %s=%s; domain=%s; path=%s%s\n",
                 PBC_L_COOKIENAME,
                 l_cookie,
                 login_host(p),
                 LOGIN_DIR,
#ifdef PORT80_TEST
                 ""
#else
        "; secure"
#endif
        );

    if (l_cookie != NULL)
        free(l_cookie);
    if (message != NULL)
        free(message);

    return(PBC_OK);

}

/**
 * clears login cookie
 * depreciated we now expire login cookies
 */
int clear_login_cookie(pool *p) {

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,"clear_login_cookie: hello");

    print_header(p, "Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s%s\n",
            PBC_L_COOKIENAME, 
            PBC_CLEAR_COOKIE,
            login_host(p), 
            LOGIN_DIR, 
            EARLIEST_EVER,
#ifdef PORT80_TEST
                 ""
#else
                     "; secure"
#endif
                     );

                 return(PBC_OK);

}

/**
 * sets cleared granting request cookie
 * @returns PBC_OK regardless
 */
int clear_greq_cookie(pool *p) {

    print_header(p, "Set-Cookie: %s=%s; domain=%s; path=/; expires=%s%s\n",
            PBC_G_REQ_COOKIENAME, 
            PBC_CLEAR_COOKIE,
            enterprise_domain(p),
            EARLIEST_EVER,
#ifdef PORT80_TEST
                 ""
#else
        "; secure"
#endif
        );

    return(PBC_OK);

}

login_rec *load_login_rec(pool *p, login_rec *l) 
{
    char * tmp;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "load_login_rec: hello\n");

    /* only created by the login cgi */
    l->next_securid   = get_int_arg(p, PBC_GETVAR_NEXT_SECURID, 0);
    l->first_kiss     = get_string_arg(p, PBC_GETVAR_FIRST_KISS, NO_NEWLINES_FUNC);

    /* make sure the username is a username */
    if((l->user = get_string_arg(p, PBC_GETVAR_USER, NO_NEWLINES_FUNC)))
        l->user = clean_username(p, l->user);

    l->realm = get_string_arg(p, PBC_GETVAR_REALM, NO_NEWLINES_FUNC);
    
    /* set a default realm if not passed in */
    if (l->realm == NULL) {
       tmp = (char *) libpbc_config_getstring(p, "default_realm", NULL);
       if (tmp) {
          l->realm = strdup(tmp);
       }
    }

    l->pass 	      = get_string_arg(p, PBC_GETVAR_PASS, NO_NEWLINES_FUNC);
    l->pass2 	      = get_string_arg(p, PBC_GETVAR_PASS2, NO_NEWLINES_FUNC);
    l->args           = get_string_arg(p, PBC_GETVAR_ARGS, YES_NEWLINES_FUNC);
    l->uri            = get_string_arg(p, PBC_GETVAR_URI, NO_NEWLINES_FUNC);
    l->host           = get_string_arg(p, PBC_GETVAR_HOST, NO_NEWLINES_FUNC);
    l->method 	      = get_string_arg(p, PBC_GETVAR_METHOD, NO_NEWLINES_FUNC);
    l->version 	      = get_string_arg(p, PBC_GETVAR_VERSION, NO_NEWLINES_FUNC);
    l->creds          = get_int_arg(p, PBC_GETVAR_CREDS, 0) + 48;

    if( (l->creds_from_greq = 
              get_int_arg(p, PBC_GETVAR_GREQ_CREDS, 0)+48) == PBC_CREDS_NONE ) 
        l->creds_from_greq  = l->creds;

    l->appid 	      = get_string_arg(p, PBC_GETVAR_APPID, NO_NEWLINES_FUNC);
    l->appsrvid       = get_string_arg(p, PBC_GETVAR_APPSRVID, NO_NEWLINES_FUNC);
    l->fr 	      = get_string_arg(p, PBC_GETVAR_FR, NO_NEWLINES_FUNC);

    l->real_hostname  = get_string_arg(p, PBC_GETVAR_REAL_HOST, NO_NEWLINES_FUNC);
    l->appsrv_err     = get_string_arg(p, PBC_GETVAR_APPSRV_ERR, NO_NEWLINES_FUNC);
    l->file 	      = get_string_arg(p, PBC_GETVAR_FILE_UPLD, NO_NEWLINES_FUNC);
    l->flag 	      = get_string_arg(p, PBC_GETVAR_FLAG, NO_NEWLINES_FUNC);
    l->referer 	      = get_string_arg(p, PBC_GETVAR_REFERER, NO_NEWLINES_FUNC);
    l->session_reauth = get_int_arg(p, PBC_GETVAR_SESSION_REAUTH, 0);
    l->reply 	      = get_int_arg(p, PBC_GETVAR_REPLY, 0);
    l->duration       = get_int_arg(p, PBC_GETVAR_DURATION, 0);
    l->pinit          = get_int_arg(p, PBC_GETVAR_PINIT, 0);
    l->pre_sess_tok   = get_int_arg(p, PBC_GETVAR_PRE_SESS_TOK, 0);

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "load_login_rec: bye\n");

    return(l);
}

char *url_encode(pool *p, char *in)
{
    char	*out;
    char	*ptr;

    if (in == NULL) {
        return NULL;
    }

    if (!(out = malloc(strlen (in) * 3 + 1)) ) {
        abend(p, "unable to allocate memory in url_encode");
    }

    ptr = out;
    while( *in ) {
        switch(*in) {
            case ' ':
                *ptr = '+';
                break;
            case '!':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = '1';
                break;
            case '"':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = '2';
                break;
            case '#':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = '3';
                break;
            case '$':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = '4';
                break;
            case '%':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = '5';
                break;
            case '&':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = '6';
                break;
            case '+':
                *ptr = '%'; *(++ptr) = '2'; *(++ptr) = 'B';
                break;
            case ':':
                *ptr = '%'; *(++ptr) = '3'; *(++ptr) = 'A';
                break;
            case ';':
                *ptr = '%'; *(++ptr) = '3'; *(++ptr) = 'B';
                break;
            case '=':
                *ptr = '%'; *(++ptr) = '3'; *(++ptr) = 'D';
                break;
            case '?':
                *ptr = '%'; *(++ptr) = '3'; *(++ptr) = 'F';
                break;
	    default:
	        *ptr = *in;
	        break;
        }
        ptr++;
        in++;
    }
    *ptr = '\0';
    return(out);

}

char *string_encode(pool *p, char *in)
{
    char	*out;
    char	*ptr;

    if (!(out = malloc(strlen (in) * 5 + 1)) ) {
        abend(p, "out of memory");
    }

    ptr = out;
    while( *in ) {
        switch(*in) {
	    case '&':
	        *ptr = '&'; *(++ptr) = 'a'; *(++ptr) = 'm'; *(++ptr) = 'p'; *(++ptr) = ';';
	        break;
	    case '<':
	        *ptr = '&'; *(++ptr) = 'l'; *(++ptr) = 't'; *(++ptr) = ';';
	        break;
	    case '>':
	        *ptr = '&'; *(++ptr) = 'g'; *(++ptr) = 't'; *(++ptr) = ';';
	        break;
	    default:
	        *ptr = *in;
	        break;
        }
        ptr++;
        in++;
    }
    *ptr = '\0';
    return(out);

}

/* when things go wrong and you're not sure what else to do                  */
/* a polite bailing out                                                      */
void abend(pool *p, char *message) 
{

    pbc_log_activity(p, PBC_LOG_ERROR, "abend", message);
    pbc_log_close(p);

    notok(p, notok_generic);
    do_output(p);
    exit(0);

}

void init_mirror_file(pool *p, const char * mirrorfile) 
{
    if (mirrorfile != NULL) {
        mirror = fopen(mirrorfile, "w");
    } else {
        mirror = fopen("/tmp/mirror", "w");
    }
}

void close_mirror_file(pool *p) 
{
    if (mirror) {
        fclose(mirror);
    }
}

const char *login_host(pool *p) 
{
    return(libpbc_config_getstring(p, "login_host", PBC_LOGIN_HOST));

}

const char *enterprise_domain(pool *p) 
{
    const char  *s;

    s = libpbc_config_getstring(p, "enterprise_domain", PBC_ENTRPRS_DOMAIN);

    if( *s != '.' )
        pbc_log_activity(p, PBC_LOG_ERROR,
			 "WARNING!!!! enterprise_domain must start with a '.'");

    return(s);

}

int has_login_cookie(pool *p)
{
    if (getenv("HTTP_COOKIE") && 
        strstr(getenv("HTTP_COOKIE"), PBC_L_COOKIENAME) )
        return(1);
    else
        return(0);

}

char *get_granting_request(pool *p) 
{
    char        *cookie;

    if ((cookie = malloc(PBC_4K)) == NULL ) {
        abend(p, "out of memory");
    }

    if (get_cookie(p, PBC_G_REQ_COOKIENAME, cookie, PBC_4K-1) == PBC_FAIL ) {
        return(NULL);
    }

    return(cookie);

}

char *decode_granting_request(pool *p, char *in, char **peerp)
{
    char *out = NULL;
    char *peer = NULL;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
			 "decode_granting_request: in: %s\n", in);

    if (peerp) *peerp = NULL;

    /* xxx check to see if 'in' is _<peer>_<base64 bundled> or just <base64> */
    /* (bundling currently relies on signing with the login server key */
    if (0 && in[0] == '_') {
        char *p;
        int len;

        in++;

        /* grab peername */
        for (p = in; *p != '\0' && *p != '_'; p++) {
            len++;
        }
        if (p == '\0' || p - in > 1024) {
            /* xxx error error */
            return NULL;
        }

        *p++ = '\0';
        peer = strdup(in);

#if 0
        libpbc_unbundle_cookie(cookie, ctx_plus, c_stuff);
#endif

        if (peerp) *peerp = peer;
    } else {
        out = strdup(in);    
        libpbc_base64_decode(p, (unsigned char *) in, 
			     (unsigned char *) out, NULL);
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		     "decode_granting_request: out: %s\n", out);

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

int vector_request(pool *p, login_rec *l, login_rec *c)
{
    login_result res;
    const char *errstr = NULL;
    struct login_flavor *fl = NULL;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "vector_request: hello\n");

    /* find flavor of authn requested */
    fl = get_flavor(p, l->creds_from_greq);

    if (!fl) {
        /* the application server's httpd.conf is misconfigured and asking
           for a flavor we don't support? */
        pbc_log_activity(p, PBC_LOG_ERROR, 
                         "vector_request: "
                         "no flavor found matching creds_from_greq=%c", 
                         l->creds_from_greq);
        pbc_log_activity(p, PBC_LOG_ERROR, 
                         "check application server configuration");
        return PBC_FAIL;
    }

    /* init_flavor should probably be called earlier on, but it
       works here for now */
    if (fl->init_flavor() != 0) {
        pbc_log_activity(p, PBC_LOG_ERROR,
                         "init_flavor: %s not available", fl->name);
        return PBC_FAIL;
    }

    /* decode login cookie */
    l->check_error = check_l_cookie(p, l, c);

    /* call authn flavor to determine correct result */
    res = fl->process_request(p, l, c, &errstr);

    switch (res) {
        case LOGIN_OK:
            return PBC_OK;
            break;
    
        case LOGIN_ERR:
	    /* show the user some sort of error */
	    ntmpl_print_html(p, TMPL_FNAME, 
                        libpbc_config_getstring(p, "tmpl_error", "error"), 
                        "flavor", fl->name,
                        "error", errstr ? errstr : 
                        "unknown error in flavor process_request",
                        NULL);
            return PBC_FAIL;
            break;

        case LOGIN_INPROGRESS:
            return PBC_FAIL;
            break;

        default:
            abort();
    }

}


/**
 * returns user agent, hides cgic global
 * @returns pointer to user agent
 */
char *user_agent(pool *p) 
{
    return(cgiUserAgent);

}

/**
 * gets lifetime of a login cookie for a kiosk
 * @param *l from login session
 * @returns duration
 */
int get_kiosk_duration(pool *p, login_rec *l)
{
    int         i;
    char	**keys;
    char	**values;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW,
			 "get_kiosk_duration: agent: %s", user_agent(p));

    keys = libpbc_config_getlist(p, "kiosk_keys");
    values = libpbc_config_getlist(p, "kiosk_values");

    if(keys != NULL) {
       for(i=0; keys[i] != NULL && values[i] != NULL; i++) {
           if( strstr(user_agent(p), keys[i]) != NULL ) {
	     pbc_log_activity(p, PBC_LOG_DEBUG_LOW,"is kiosk: %s duration: %s\n", 
			      user_agent(p), values[i]);
               return(atoi(values[i]));
           }
       }
    }
    /* not a kiosk */
    return(PBC_FALSE); /* xxx false isn't a duration -leg */

}

/**
 * calculates login cookie expiration
 * @param *l from login session
 * @returns time of expiration
 */
time_t compute_l_expire(pool *p, login_rec *l)
{
    time_t t;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,"compute_l_expire: hello");

    if( (l->duration = get_kiosk_duration(p, l)) == PBC_FALSE )
        l->duration = 
        libpbc_config_getint(p, "default_l_expire",DEFAULT_LOGIN_EXPIRE);

    t = time(NULL) + l->duration;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,"compute_l_expire: bye %d", t);

    return t;
}

/**
 * forms nice string with time remaining
 * @param *c from login cookie
 * @returns string
 */
const char *time_remaining_text(pool *p, login_rec *c)
{
    char 	*remaining = NULL;
    int 	secs_left = 0;
    int		len = PBC_1K;
    char 	*h, *m;


    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "time_remaining_text: hello\n");

    if (!(remaining = malloc(len)) )
        abend(p, "out of memory");
    if (!(h = malloc(len)) )
        abend(p, "out of memory");
    if (!(m = malloc(len)) )
        abend(p, "out of memory");

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
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "returning: %s\n", remaining);
    return(remaining);

}

int app_logged_out(pool *p, login_rec *c, const char *appid, const char *appsrvid) 
{
    char	*new, *ptr, *app_string;
    const char	*s;
    int         len;

    len = strlen(appid) + strlen(appsrvid) + strlen(APP_LOGOUT_STR) + 3;
    app_string=calloc(len, sizeof(char));
    snprintf(app_string, len, "%s%c%s%c%s", 
             APP_LOGOUT_STR, APP_LOGOUT_STR_SEP, 
             appsrvid, APP_LOGOUT_STR_SEP,
             appid);

    /* clean non compliant chars from string */
    ptr = new = app_string;
    while(*ptr) {
        if (isalnum((int) *ptr) || *ptr == '-' || *ptr == '_' || *ptr == '.') {
            *new++ = *ptr;
        }
        ptr++;
    }
    *new = '\0';

    if( (s=libpbc_config_getstring(p, app_string, NULL)) == NULL ) {
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_app", "logout_app"),
                        NULL);
    }
    else {
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_app_custom",
                                                "logout_app_custom"),
                        "text", s,
                        NULL);
    }

    free(app_string);
    return(PBC_OK);

}

int logout(pool *p, login_rec *l, login_rec *c, int logout_action)
{
    char	*appid;
    char	*appsrvid;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"logout: logout_action: %d\n", logout_action);

    /* get appid and appsrvid from env */
    if( (appid=get_string_arg(p, PBC_GETVAR_APPID,NO_NEWLINES_FUNC)) == NULL )
        appid = strdup("");
    if( (appsrvid=get_string_arg(p, PBC_GETVAR_APPSRVID,NO_NEWLINES_FUNC)) == NULL)
        appsrvid = strdup("");

    clear_greq_cookie(p);     /* just in case there in one lingering */

    if( logout_action == LOGOUT_ACTION_NOTHING ) {
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_part1",
                                                "logout_part1"),
                        NULL);

        app_logged_out(p, c, appid, appsrvid);
        if( c == NULL || check_l_cookie_expire(p, c, time(NULL)) == PBC_FAIL) {
            ntmpl_print_html(p, TMPL_FNAME,
			libpbc_config_getstring(p, "tmpl_logout_already_weblogin",
				"logout_already_weblogin"),
                        NULL);
            ntmpl_print_html(p, TMPL_FNAME,
			libpbc_config_getstring(p, "tmpl_logout_postscript_still_others",
				"logout_postscript_still_others"),
                        NULL);
        }
        else {
            ntmpl_print_html(p, TMPL_FNAME,
			libpbc_config_getstring(p, "tmpl_logout_still_weblogin",
				"logout_still_weblogin"),
                        "user",
                        (c == NULL || c->user == NULL ? "unknown" : c->user),
                        NULL);
            ntmpl_print_html(p, TMPL_FNAME,
			libpbc_config_getstring(p, "tmpl_logout_time_remaining",
				"logout_time_remaining"), 
                                "remaining",
			        time_remaining_text(p, c),
                        NULL);
            ntmpl_print_html(p, TMPL_FNAME,
			libpbc_config_getstring(p, "tmpl_logout_postscript_still_weblogin",
				"logout_postscript_still_weblogin"),
                        NULL);
        }
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_part2",
                                                "logout_part2"),
                        NULL);
    }
    else if( logout_action == LOGOUT_ACTION_CLEAR_L ) {
        expire_login_cookie(p, l, c);
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_part1",
                                                "logout_part1"),
                        NULL);
        app_logged_out(p, c, appid, appsrvid);
        if( c == NULL || check_l_cookie_expire(p, c, time(NULL)) == PBC_FAIL)
            ntmpl_print_html(p, TMPL_FNAME,
                            libpbc_config_getstring(p, "tmpl_logout_already_weblogin",
                                                    "logout_already_weblogin"),
                            NULL);
        else 
            ntmpl_print_html(p, TMPL_FNAME,
                            libpbc_config_getstring(p, "tmpl_logout_weblogin",
                                                    "logout_weblogin"),
                            NULL);
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_postscript_still_others",
                                                "logout_postscript_still_others"),
                            NULL);
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_part2",
                                                "logout_part2"),
                            NULL);
    }
    else if( logout_action == LOGOUT_ACTION_CLEAR_L_NO_APP ) {
        expire_login_cookie(p, l, c);
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_part1",
                                                "logout_part1"),
                            NULL);
        if( c == NULL || check_l_cookie_expire(p, c, time(NULL)) == PBC_FAIL )
            ntmpl_print_html(p, TMPL_FNAME,
                            libpbc_config_getstring(p, "tmpl_logout_already_weblogin",
                                                    "logout_already_weblogin"),
                            NULL);
        else 
            ntmpl_print_html(p, TMPL_FNAME,
                            libpbc_config_getstring(p, "tmpl_logout_weblogin",
                                                    "logout_weblogin"),
                            NULL);
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_postscript_still_others",
                                                "logout_postscript_still_others"),
                            NULL);
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_logout_part2",
                                                "logout_part2"),
                            NULL);
    }

    return(PBC_OK);
}

/**
 * check_logout checks to see if this is a logout action, and
 * calls the logout function if so
 *
 * @param l login_rec from submission
 * @param c login_rec from cookies
 *
 * @returns PBC_OK if not a logout, or never returns if a logout
 */
int check_logout(pool *p, login_rec *l, login_rec *c) 
{
    int logout_action;
    char *logout_prog;
    char *uri;
    char *ptr;
    char *ptr2;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
			 "check_logout: program name: %s\n", cgiScriptName);

    /* check to see if this is a logout redirect */
    logout_action = get_int_arg(p, PBC_GETVAR_LOGOUT_ACTION, LOGOUT_ACTION_UNSET);

    if ( logout_action != LOGOUT_ACTION_UNSET ) {
	pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
			 "check_logout: logout_action : %s\n", cgiScriptName);
        logout(p, l, c, logout_action);
        do_output(p);
        exit(0);
    }
 
    ptr = ptr2 = uri = strdup(cgiScriptName);
    /* remove multiple slashes from uri */
    while( *ptr2 ) {
        if( ptr2 != uri && *ptr2 == '/' &&  *(ptr2-1) == '/' )
            ptr2++;
         else 
            *ptr++ = *ptr2++;
    }
    *ptr = '\0';

    ptr = ptr2 = logout_prog = 
		(char *)libpbc_config_getstring(p, "logout_prog", NULL);
    /* remove multiple slashes from config file entry */
    while( *ptr2 ) {
        if( ptr2 != logout_prog && *ptr2 == '/' &&  *(ptr2-1) == '/' )
            ptr2++;
         else 
            *ptr++ = *ptr2++;
    }
    *ptr = '\0';

    if(logout_prog != NULL && uri != NULL &&
       strcasecmp(logout_prog, uri) == 0 ) {
        logout(p, l, c, LOGOUT_ACTION_CLEAR_L_NO_APP);
        do_output(p);
        if (uri != NULL)
            free(uri);
        exit(0);
    }

    if (uri != NULL)
        free(uri);

    return(PBC_OK);

}

/**
 * prints login status page
 * @param c contents of login cookie
 */
void login_status_page(pool *p, login_rec *c)
{
    char *refresh_line = NULL;
    int refresh_needed_len = STATUS_INIT_SIZE;
    int refresh_len = 0;
    int delay = get_int_arg(p, "countdown", 0);
    int min_delay = libpbc_config_getint(p, "min_countdown", 9999);

    while ( delay != 0 && delay >= min_delay &&
            refresh_needed_len > refresh_len ) {
        if (refresh_line == NULL) {
            refresh_line = malloc( refresh_needed_len * sizeof(char) );
        } else {
            refresh_line = realloc( refresh_line, refresh_needed_len * sizeof(char) );
        }

        if (refresh_line == NULL) {
            /* Out of memory */
            libpbc_abend(p,  "Out of memory for refresh string." );
        }

        refresh_len = refresh_needed_len;

        refresh_needed_len = snprintf( refresh_line, refresh_len,
                                       STATUS_HTML_REFRESH, delay, delay );
    }
    
    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_status", "status"),
                    "refresh", refresh_line != NULL ? refresh_line : "",
                    "user", (c == NULL || c->user == NULL ? "unknown" : c->user),
                    "remaining", time_remaining_text(p, c),
                    NULL
                   );
    if (refresh_line != NULL)
        free(refresh_line);
}

/**
 * handles pinit requests 
 * @param l info for login session
 * @param c contents of login cookie
 */
int pinit(pool *p, login_rec *l, login_rec *c)
{

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,"pinit: hello");

    if( c == NULL || check_l_cookie_expire(p, c, time(NULL)) == PBC_FAIL ) {
	/* what credentials should we default to if a user has
	   come directly to us? */
	const char *credname = 
	    libpbc_config_getstring(p, "pinit_default_authtype",
				       "webiso-vanilla");
	struct login_flavor *fl = NULL;
	const char *errstr;
	login_result res;
	
	/* find what the credential id is for that authtype */
	l->creds_from_greq = l->creds = libpbc_get_credential_id(p, credname);
	if (l->creds == PBC_CREDS_NONE) {
	    /* what are we suppose to do here? i guess just losing is
             reasonable and safe */
	    pbc_log_activity(p, PBC_LOG_ERROR,
			     "pinit: pinit_default_authtype not recognized");
	    abort();
	}
	l->pinit = PBC_TRUE;
	l->host = strdup((char *)login_host(p));
	l->appsrvid = strdup(l->host);
	l->appid = strdup("pinit");
	l->uri = strdup(cgiScriptName);
	pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
			     "pinit: ready to print login page");
	
	/* find flavor of authn requested */
	fl = get_flavor(p, l->creds_from_greq);

	/* decode login cookie */
	l->check_error = check_l_cookie(p, l, c);

	fl->init_flavor();
	res = fl->process_request(p, l, c, &errstr);
	if (res != LOGIN_INPROGRESS) {
	    pbc_log_activity(p, PBC_LOG_ERROR,
			     "unexpected response from fl->process_request: "
			"%d %s", res, errstr ? errstr : "(no errstring)");

	    /* xxx maybe this happens because the default flavor can
	       verify authentication without any interactions with the user
	       actually submitting a form? */

	    /* xxx shouldn't we be using vector_request() instead of
	       calling the flavor ourselves? */
	}
    }
    else {
        login_status_page(p, c);
    }
    return(PBC_FAIL);

}

/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
/*	main line                                                          */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

/**
 * cgiMain: the main routine, called by libcgic
 */
int cgiMain() 
{
    login_rec *l = NULL;   /* culled from various sources */
    login_rec *c = NULL;   /* only from login cookie */
    const char *mirrorfile;
    void *p; /* we pass a pointer around that is an Apache memory pool if we're
                using apache, here we just pass a void pointer */

    libpbc_config_init(p, NULL, "logincgi");
    debug = libpbc_config_getint(p, "debug", 0);
    pbc_log_init(p, "pubcookie login server", NULL, NULL, NULL);

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "cgiMain() hello...\n");

    /* the html and headers are written to tmpfiles then 
     * transmitted to the browser when complete
     */
    htmlout = tmpfile();
    headerout = tmpfile();

    mirrorfile = libpbc_config_getstring(p, "mirrorfile", NULL);

    libpbc_pubcookie_init(p);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "cgiMain() done initializing...\n");

    sleep(libpbc_config_getint(p, "sleepfor", 0));

    /* always print out the standard headers */
    print_http_header(p);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		     "cgiMain: hello built on " __DATE__ " " __TIME__ "\n");

    if (mirrorfile) {
        init_mirror_file(p, mirrorfile);
    }

#ifndef PORT80_TEST
    /* bail if not ssl */
    if (!getenv("HTTPS") || strcmp( getenv("HTTPS"), "on" ) ) { 
        /* instead of just bailing, why not just redirect to an SSL port */
        /* notok(p, notok_need_ssl); */

        char * redirect_final;

        if (!(redirect_final = malloc(PBC_4K)) ) {
           abend(p, "out of memory");
        }

        snprintf(redirect_final, PBC_4K-1, "https://%s%s",
                 cgiServerName, cgiScriptName);

        /* this won't work quite right if somehow a form gets
         * submitted to us on port 80 
         */
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_nonpost_redirect",
                                                "nonpost_redirect"),
                        "url", redirect_final,
                        "delay", REFRESH,
                        NULL);

        goto done;
    }
#endif

    /* get the arguments to this cgi, whether they are from submitting */
    /* the login page or from from the granting request cookie         */
    /* you call tell the difference since the submitted one will have  */
    /* user and pass filled in                                         */
    /* malloc and populate login_rec                                   */
    l = get_query(p); 

    /* unload the login cookie if we have it */
    c = verify_unload_login_cookie(p, l);

    /* log the arrival */
    pbc_log_activity(p, PBC_LOG_AUDIT,
		"%s Visit from user: %s client addr: %s app host: %s appid: %s uri: %s because: %s", 
                l->first_kiss, 
                l->user == NULL ? "(null)" : l->user, 
                cgiRemoteAddr, 
                l->host == NULL ? "(null)" : l->host, 
                l->appid == NULL ? "(null)" : l->appid,
                l->uri == NULL ? "(null)" : l->uri,
                l->appsrv_err_string == NULL ? "(null)" : l->appsrv_err_string);

    /* check the user agent */
    if (!check_user_agent(p)) {
        pbc_log_activity(p, PBC_LOG_AUDIT,
			 "%s bad agent: %s user: %s client_addr: %s",
			 l->first_kiss, 
			 user_agent(p), 
			 l->user == NULL ? "(null)" : l->user, 
			 cgiRemoteAddr);
        notok(p, notok_bad_agent);
	goto done;
    }
    
    /* look for various logout conditions */
    check_logout(p, l, c);

    /* check to see what cookies we have */
    /* pinit detected in here */
    /* pinit response detected in here */
    if (cookie_test(p, l, c) == PBC_FAIL) {
        goto done;
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW,
		    "cgiMain: checked user_agent, logout, and pinit.");

    /* allow for older versions that don't have force_reauth */
    if (!l->fr) {
        l->fr = strdup("NFR");
    }
    
    if (vector_request(p, l, c) == PBC_OK ) {
        /* the reward for a hard days work */
        pbc_log_activity(p, PBC_LOG_AUDIT,
    "%s Issuing cookies for user: %s client addr: %s app host: %s appid: %s", 
			 l->first_kiss, 
			 l->user == NULL ? "(null)" : l->user, 
			 cgiRemoteAddr, 
			 l->host, 
			 l->appid);
    
        /* generate the cookies and print the redirect page */
        print_redirect_page(p, l, c);
    }

done:
    if (mirrorfile) {
	close_mirror_file(p);
    }

    do_output(p);

    if (l != NULL)
        pbc_free(p, l);

    return(0);  

}

/* returns NULL if the L cookie is valid                                     */
/*   else a description of it's invalid nature                               */
/* xxx most of this work should probably be done inside of the flavor */
char *check_l_cookie(pool *p, login_rec *l, login_rec *c)
{
    time_t	t;
    char	*g_version;
    char	*l_version;

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "check_l_cookie: hello\n");

    if (c == NULL )
        c = verify_unload_login_cookie(p, l);

    if (c == NULL)
        return("couldn't decode login cookie");

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, 
		     "in check_l_cookie ready to look at cookie contents %s\n", c->user);

    /* look at what we got back from the cookie */
    if ( c->user == NULL ) {
	pbc_log_activity(p, PBC_LOG_ERROR, 
			 "no user from L cookie? user from g_req: %s", l->user);
        return "malformed";
    }

    if (check_l_cookie_expire(p, c, t=time(NULL)) == PBC_FAIL ) {
      pbc_log_activity(p, PBC_LOG_AUDIT,
		    "%s expired login cookie; created: %d expire: %d now: %d",
			l->first_kiss,
			c->create_ts, 
			c->expire_ts, 
                        t);
        return "expired";
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		"check_l_cookie ready for creds, c: %c l: %c\n", 
		c->creds, l->creds);

    /* probably a pinit or logout */
    if (c->creds == PBC_CREDS_NONE || l->creds == PBC_CREDS_NONE ) {
        return("no_creds");
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, 
		     "check_l_cookie: done dorking with creds\n");

    l_version = c->version; g_version = l->version;
    if (*l_version != *g_version ) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
			 "wrong major version: from L cookie %s, from g_req %s for host %s", l_version, g_version, l->host);
        return("wrong major version");
    }
    if (*(l_version+1) != *(g_version+1) ) {
        pbc_log_activity(p, PBC_LOG_DEBUG_LOW,
			 "%s warn: wrong minor version: from l cookie %s, from g_req %s for host %s", l->first_kiss, l_version, g_version, l->host);
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		     "check_l_cookie: done looking at version\n");

    l->user = c->user;

    return((char *)NULL);
}


/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
/*	functions                                                          */
/* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 

void print_j_test(pool *p) 
{
    print_html(p, "%s", J_TEST_TEXT1);
    print_html(p, "%s", J_TEST_TEXT2);
    print_html(p, "%s", J_TEST_TEXT3);
    print_html(p, "%s", J_TEST_TEXT4);
    print_html(p, "%s", J_TEST_TEXT5);
}

void notok_no_g_or_l(pool *p) 
{
    print_j_test(p);

    print_html(p, "<NOSCRIPT>\n");

    print_html(p, "%s\n", NOTOK_NO_G_OR_L_TEXT1);

    print_html(p, "</NOSCRIPT>\n");

}

void notok_no_g(pool *p) 
{
    print_html(p, "%s", NOTOK_NO_G_TEXT1);

}

void notok_formmultipart(pool *p) 
{
    print_html(p, "%s", NOTOK_FORMMULTIPART_TEXT1);

}

void notok_need_ssl(pool *p) 
{
    print_html(p, "%s", NOTOK_NEEDSSL_TEXT1);
    pbc_log_activity(p, PBC_LOG_AUDIT,
		     "host %s came in on a non-ssl port, why?", cgiRemoteAddr);
}

void notok_bad_agent(pool *p) 
{
    print_html(p, "%s", NOTOK_BAD_AGENT_TEXT1);
    print_html(p, "The browser you are using identifies itself as:<P><TT></TT>",
                 cgiUserAgent);
    print_html(p, "%s", NOTOK_BAD_AGENT_TEXT2);
}

void notok_generic(pool *p) 
{
    print_html(p, "%s", NOTOK_GENERIC_TEXT1);

}

void notok (pool *p,  void (*notok_f)() )
{
    /* if we got a form multipart cookie, reset it */
    if ( getenv("HTTP_COOKIE") && strstr(getenv("HTTP_COOKIE"), 
					 PBC_FORM_MP_COOKIENAME) ) {
        print_header(p, "Set-Cookie: %s=%s; domain=%s; path=/; expires=%s\n", 
		     PBC_FORM_MP_COOKIENAME, 
		     PBC_CLEAR_COOKIE,
		     PBC_ENTRPRS_DOMAIN, 
                     enterprise_domain(p), 
		     EARLIEST_EVER);
    }

    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_notok_part1",
                                            "notok_part1"),
                    NULL);
    notok_f();
    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_notok_part2",
                                            "notok_part2"),
                    NULL);

}

int set_pinit_cookie(pool *p) 
{
    print_header(p, "Set-Cookie: %s=%s; domain=%s; path=/%s\n", 
                 PBC_PINIT_COOKIENAME,
                 PBC_SET,
                 login_host(p),
#ifdef PORT80_TEST
                 ""
#else
        "; secure"
#endif
        );

    return(PBC_OK);
}

int clear_pinit_cookie(pool *p) {

    print_header(p, "Set-Cookie: %s=%s; domain=%s; path=/; expires=%s%s\n",
                 PBC_PINIT_COOKIENAME, 
                 PBC_CLEAR_COOKIE,
                 login_host(p),
                 EARLIEST_EVER,
#ifdef PORT80_TEST
                 ""
#else
        "; secure"
#endif
        );

    return(PBC_OK);

}

int pinit_response(pool *p, login_rec *l, login_rec *c)
{
  
    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "pinit_response: hello");

    clear_pinit_cookie(p);

    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_pinit_response1",
                                            "pinit_response1"),
                    NULL);
    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_welcome_back",
                                            "welcome_back"),
                    "user", (c == NULL || c->user == NULL ? "unknown" : c->user),
                    NULL);
    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_logout_time_remaining",
                                            "logout_time_remaining"),
                    "remaining",
                    time_remaining_text(p, c),
                    NULL);
    ntmpl_print_html(p, TMPL_FNAME,
                    libpbc_config_getstring(p, "tmpl_pinit_response2",
                                            "pinit_response2"),
                    NULL);
    return(PBC_OK);

}

/**
 * cookie_test: looks at what cookies we have to do an inital vectoring
 * of the request; should somehow be merged into vector request but all
 * of these things should happen first.
 *
 * @param *l from login session
 * @param *c from login cookie
 *
 * @returns PBC_FAIL if the program should finish
 * @returns PBC_OK   if the program should continue
 */
int cookie_test(pool *p, login_rec *l, login_rec *c) 
{
    char        *cookies;
    char        cleared_g_req[PBC_1K];

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "cookie_test: hello");

    /* if it's a reply from the login server we immediatly leave */
    if ( l->reply == FORM_REPLY && l->appid != NULL) {
        return(PBC_OK);
    }

    /* if no cookies, then must be pinit */
    if ((cookies = getenv("HTTP_COOKIE")) == NULL) {
        pinit(p, l, c);
        return(PBC_FAIL);
    }
    
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, 
		     "cookie_test: cookies: %s", cookies);

    /* we don't currently handle form-multipart */
    /* the formmultipart cookie is set by the module */
    if ( strstr(cookies, PBC_FORM_MP_COOKIENAME) ) {
        notok(p, notok_formmultipart);
        return(PBC_FAIL);
    }

    /* after a pinit login we give the user something nice to look at */
    if ( strstr(cookies, PBC_PINIT_COOKIENAME) != NULL ) {
        pinit_response(p, l, c);
        return(PBC_FAIL);
    }

    /* a cleared G req is as bad as no g req */
    snprintf(cleared_g_req, PBC_1K, "%s=%s", PBC_G_REQ_COOKIENAME, 
             PBC_CLEAR_COOKIE);

    /* no g_req or cleared g_req then pinit */
    if ( strstr(cookies, PBC_G_REQ_COOKIENAME) == NULL || 
         strstr(cookies, cleared_g_req) != NULL ) {
        pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE,
			"cookie_test: no g_req or empty g_req");
        pinit(p, l, c);
        return(PBC_FAIL);
    }

    return(PBC_OK);
}

/*	################################### The beginning of the table       */
void print_table_start(pool *p)
{
    print_html(p, "<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"580\">\n");

}

/*	################################### da copyright, it's ours!         */
void print_copyright(pool *p)
{
    print_html(p, "<small>Copyright &#169; 2002 University of Washington</small>\n");

}

/*	################################### UWNetID Logo                     */
void print_uwnetid_logo(pool *p)
{
    print_html(p, "<img src=\"/images/login/weblogin.gif\" alt=\"UW NetID Weblogin\" height=\"57\" width=\"198\" oncontextmenu=\"return false\">\n");

}


char *to_lower(pool *p, char *in)
{
    char	*ptr;

    for(ptr = in; *ptr; ptr++)
        *ptr = tolower(*ptr);

    return(in);

}

/**
 *  clean_ok_browsers_line lowercases a string, and truncates it at
 *  the first \n
 *
 *  @param in pointer to a string, which is modified
 *  @return nothing
 */
void clean_ok_browsers_line(pool *p, char *in)
{
    char *ptr;

    for(ptr = in; *ptr; ptr++) {
        *ptr = tolower(*ptr);
        if (*ptr == '\n' ) 
            *ptr-- = '\0';
    }
}


/**
 *  check_user_agent: checks the user_agent string from the browser
 *  to see if it contains any of the lines of OK_BROWSERS_FILE as
 *  a substring
 *
 *  @param none
 *  @return 0 on error
 *  @return 1 if a valid substring matches
 *  @return 0 if no match is found (the browser is bad)
 */
int check_user_agent(pool *p)
{
    char line[PBC_1K];
    char agent_clean[PBC_1K];
    FILE *ifp;

    ifp = fopen(OK_BROWSERS_FILE, "r");
    if (ifp == NULL) {
        pbc_log_activity(p, PBC_LOG_ERROR,
		  "can't open ok browsers file: %s, continuing", 
		  OK_BROWSERS_FILE);
        return(1);
    }

    /* make the user agent lower case */
    strncpy(agent_clean, user_agent(p), sizeof(agent_clean));
    clean_ok_browsers_line(p, agent_clean);

    while(fgets(line, sizeof(line), ifp) != NULL) {
        clean_ok_browsers_line(p, line);
        if (line[0] == '#' ) {
            continue;
        } 
        if (strstr(agent_clean, line)) {
            return(1);
        }
    }

    return(0);
}


void print_redirect_page(pool *p, login_rec *l, login_rec *c)
{
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
    char		*ptr = NULL;
    int			g_res, l_res;
    int			limitations_mentioned = 0;
    char		*submit_value = NULL;
    cgiFormEntry	*cur;
    cgiFormEntry	*next;
    time_t		now;

    char *user;
    char *appsrvid;
    char *appid;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
			 "print_redirect_page: hello (pinit=%d)\n", l->pinit);
    if (!(redirect_dest = malloc(PBC_4K)) ) {
        abend(p, "out of memory");
    }
    if (!(redirect_final = malloc(PBC_4K)) ) {
        abend(p, "out of memory");
    }
    if (!(message = malloc(PBC_4K)) ) {
        abend(p, "out of memory");
    }
    if (!(g_cookie = malloc(PBC_4K)) ) {
        abend(p, "out of memory");
    }
    if (!(l_cookie = malloc(PBC_4K)) ) {
        abend(p, "out of memory");
    }

    pbc_log_activity(p, PBC_LOG_AUDIT, "l->user=%s l->appsrvid=%s l->appid=%s",
		    l->user, l->appsrvid, l->appid);

    /* the login cookie is encoded as having passed 'creds', which is what
       the flavor verified. */

    l_res = create_cookie( p, 
                           user = url_encode(p, l->user),
                           appsrvid = url_encode(p, l->appsrvid),
                           appid = url_encode(p, l->appid),
                           PBC_COOKIE_TYPE_L,
                           l->creds,
                           0,
                           (c == NULL || c->expire_ts < time(NULL) 
                                ? compute_l_expire(p, l) 
                                : c->expire_ts),
                           l_cookie,
                           NULL, /* sending it to myself */
                           PBC_4K);

    if (user != NULL)
        pbc_free(p, user);
    if (appsrvid != NULL)
        pbc_free(p, appsrvid);
    if (appid != NULL)
        pbc_free(p, appid);

    /* since the flavor responsible for 'creds_from_greq' returned
       LOGIN_OK, we tell the application that it's desire for 'creds_from_greq'
       was successful. */

    g_res = create_cookie(p, user = url_encode(p, l->user),
                          appsrvid =url_encode(p, l->appsrvid),
                          appid = url_encode(p, l->appid),
                          PBC_COOKIE_TYPE_G,
                          l->creds_from_greq,
                          l->pre_sess_tok,
                          0,
                          g_cookie,
                          l->host,
                          PBC_4K);

    if (user != NULL)
        free(user);
    if (appsrvid != NULL)
        free(appsrvid);
    if (appid != NULL)
        free(appid);

    /* if we have a problem then bail with a nice message */
    if ( !l_res || !g_res ) {
        sprintf( message, "%s%s%s%s%s%s",
                 PBC_EM1_START,
                 TROUBLE_CREATING_COOKIE,
                 PBC_EM1_END,
                 PBC_EM2_START,
                 PROBLEMS_PERSIST,
                 PBC_EM2_END);
        /* xxx it's kinda hard to jump to print_login_page, because
           what flavor should we be printing here? */
#if 0
    print_login_page(l, c, message, "cookie create failed",
		NO_CLEAR_LOGIN, NO_CLEAR_GREQ);
#endif

        pbc_log_activity(p, PBC_LOG_ERROR,
                         "Not able to create cookie for user %s at %s-%s",
                         l->user, l->appsrvid, l->appid);
        pbc_free(p, message);
        return;
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "created cookies l_res g_res\n");


    /* create the http header line with the cookie */
    snprintf( g_set_cookie, sizeof(g_set_cookie)-1, 
#ifdef PORT80_TEST
		"Set-Cookie: %s=%s; domain=%s; path=/", 
#else
		"Set-Cookie: %s=%s; domain=%s; path=/; secure", 
#endif
		PBC_G_COOKIENAME,
		g_cookie,
		enterprise_domain(p));

    snprintf( l_set_cookie, sizeof(l_set_cookie)-1, 
#ifdef PORT80_TEST
		"Set-Cookie: %s=%s; domain=%s; path=%s", 
#else
		"Set-Cookie: %s=%s; domain=%s; path=%s; secure", 
#endif
		PBC_L_COOKIENAME,
		l_cookie,
		login_host(p),
		LOGIN_DIR);

    /* whip up the url to send the browser back to */
    if (!strcmp(l->fr, "NFR") )
        redirect_uri = l->uri;
    else
        redirect_uri = l->fr;

    snprintf(redirect_dest, PBC_4K-1, 
#ifdef PORT80_TEST
		"http://%s%s%s", 
#else
		"https://%s%s%s", 
#endif
		l->host, (*redirect_uri == '/' ? "" : "/"), redirect_uri);

    if (l->args ) {
        args_enc = calloc (1, strlen (l->args));
        libpbc_base64_decode(p, (unsigned char *) l->args,  
                              (unsigned char *) args_enc, NULL);
        snprintf( redirect_final, PBC_4K-1, "%s?%s", redirect_dest, args_enc );
    } else {
        strcpy( redirect_final, redirect_dest );
    }

    if (redirect_dest != NULL)
        free(redirect_dest);

    /* we don't use the fab log_message funct here because the url encoding */
    /* will look like format chars in future *printf's */
    now = time(NULL);
    fprintf(stderr,
            "%s: PUBCOOKIE_DEBUG: %s: %s Redirect user: %s redirect: %s\n",
            libpbc_time_string(p, now),
            ANY_LOGINSRV_MESSAGE,
            l->first_kiss,
            l->user, 
            redirect_final);

    /* now blat out the redirect page */
    if( l->pinit == PBC_FALSE )   /* don't need a G cookie for a pinit */
        print_header(p, "%s\n", g_set_cookie);
    else
        set_pinit_cookie(p);
    print_header(p, "%s\n", l_set_cookie);
    clear_greq_cookie(p);

    /* incase we have a post */
    if ( l->post_stuff ) {
        /* cgiParseFormInput will extract the arguments from the post */
        /* make them available to subsequent cgic calls */
        if (cgiParseFormInput(l->post_stuff, strlen(l->post_stuff))
                   != cgiParseSuccess ) {
	    pbc_log_activity(p, PBC_LOG_ERROR,
		      "couldn't parse the decoded granting request cookie");
            notok(p, notok_generic);
	    do_output(p);
            exit(0);
        }

	print_html(p, "<HTML>");
	/* when the page loads click on the last element */
        /* (which will always be the submit) in the array */
        /* of elements in the first, and only, form. */
	print_html(p, "<BODY BGCOLOR=\"white\" onLoad=\"");

        /* depending on whether-or-not there is a SUBMIT field in the form */
        /* use the correct javascript to autosubmit the POST */
        /* this should probably be upgraded to only look for submits as */
        /* field names, not anywhere else */
        post_stuff_lower = strdup(l->post_stuff);
        for(ptr=post_stuff_lower; *ptr != '\0'; ptr++)
            *ptr = tolower(*ptr);
        if (strstr(post_stuff_lower, "submit") != NULL )
            print_html(p, "document.query.submit.click()");
        else
            print_html(p, "document.query.submit");

        print_html(p, "\">\n");

	print_html(p, "<center>");
        print_table_start(p);
	print_html(p, "<tr><td align=\"LEFT\">\n");

	print_html(p, "<form method=\"POST\" action=\"%s\" ", redirect_final);
        print_html(p, "enctype=\"application/x-www-form-urlencoded\" ");
        print_html(p, "name=\"query\">\n");

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
                    print_html(p, "Certain limitations require that this be shown, please ignore it<BR>\n");
                    limitations_mentioned++;
                }
                print_html(p, "<textarea cols=\"0\" rows=\"0\" name=\"%s\">\n", 
			  cur->attr);
                print_html(p, "%s</textarea>", string_encode(p, cur->value));
                print_html(p, "<P>\n");
            }
            else {
                /* we don't want to cover other people's submits */
                if ( !strcmp(cur->attr, "submit") )  {
                    submit_value = string_encode(p, cur->value);
                }
                else {
                    print_html(p, "<input type=\"hidden\" ");
		    print_html(p, "name=\"%s\" value=\"%s\">\n",
			      cur->attr, cur->value);
                }
    	    }

            /* move onto the next attr/value pair */
            next = cur->next;
            cur = next;
        } /* while cur */


        print_html(p, "</td></tr>\n");
        print_uwnetid_logo(p);
        print_html(p, "<P>");
        print_html(p, "%s\n", PBC_POST_NO_JS_TEXT);
        print_html(p, "</td></tr></table>\n");

        /* put submit at the bottom so it looks better and */
        if (submit_value )
            print_html(p, "<input type=\"submit\" name=\"submit\" value=\'%s\'>\n", submit_value);
        else
            print_html(p, "<input type=\"submit\" value=\"%s\">\n",
		      PBC_POST_NO_JS_BUTTON);

        print_html(p, "</form>\n");
        print_copyright(p);
        print_html(p, "</center>");
        print_html(p, "</BODY></HTML>\n");
    }
    else {
        /* non-post redirect area                 non-post redirect area */

        /* the refresh header should go into the template as soon as it's*/
        /* been tested                                                   */
        ntmpl_print_html(p, TMPL_FNAME,
                        libpbc_config_getstring(p, "tmpl_nonpost_redirect",
                                                "nonpost_redirect"),
                        "url", redirect_final,
                        "delay",  REFRESH,
                        NULL);
    } /* end if post_stuff */

    if( g_cookie != NULL ) 
        pbc_free(p, g_cookie);
    if( l_cookie != NULL ) 
        pbc_free(p, l_cookie);
    if( message != NULL ) 
        pbc_free(p, message);
    if( redirect_final != NULL ) 
        pbc_free(p, redirect_final);

}

/* fills in the login_rec from the form submit and granting request */
login_rec *get_query(pool *p) 
{
    login_rec		*l = malloc(sizeof(login_rec));
    char		*g_req;
    char		*g_req_clear = NULL;
    struct timeval	t;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "get_query: hello\n");

    init_login_rec(p, l);

    /* even if we hav a granting request post stuff will be in the request */
    l->post_stuff = get_string_arg(p, PBC_GETVAR_POST_STUFF, YES_NEWLINES_FUNC);

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
			 "get_query: looked at post_stuff\n");

    /* take everything out of the environment */
    l = load_login_rec(p, l);

    /* cgiParseFormInput will extract the arguments from the granting        */
    /* cookie string and make them available to subsequent cgic calls        */
    /* if the reply field isn't set then this is not be a submit from a login*/
    if (l->reply != FORM_REPLY ) {
        /* get greq cookie */
        g_req = get_granting_request(p);

        /* is granting cookie missing or "spent" */
        if( g_req != NULL && 
            strcmp(g_req, PBC_CLEAR_COOKIE) != 0 ) {

            g_req_clear = decode_granting_request(p, g_req, NULL);

	    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		 "get_query: decoded granting request: %s\n", g_req_clear);

            if (cgiParseFormInput(g_req_clear, strlen(g_req_clear)) 
                   != cgiParseSuccess ) {
		pbc_log_activity(p, PBC_LOG_ERROR,
		      "couldn't parse the decoded granting request cookie");
                notok(p, notok_generic);
                if ( g_req != NULL )
                    pbc_free(p, g_req );
                return(NULL);
            }
            l = load_login_rec(p, l);

            /* capture the cred that the app asked for */
            l->creds_from_greq  = l->creds;

        }
        if ( g_req != NULL )
            free( g_req );
        if ( g_req_clear != NULL )
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

    pbc_log_activity(p, PBC_LOG_AUDIT, "get_query: from login user: %s\n",
			l->user == NULL ? "(null)" : l->user
			);
    pbc_log_activity(p, PBC_LOG_AUDIT, "get_query: from login version: %s\n",
			l->version == NULL ? "(null)" : l->version
			);
    pbc_log_activity(p, PBC_LOG_AUDIT, 
			"get_query: from login creds: %c\n", l->creds);
    pbc_log_activity(p, PBC_LOG_AUDIT, "get_query: from login appid: %s\n",
			l->appid == NULL ? "(null)" : l->appid
			);
    pbc_log_activity(p, PBC_LOG_AUDIT, "get_query: from login host: %s\n",
			l->host == NULL ? "(null)" : l->host
			);
    pbc_log_activity(p, PBC_LOG_AUDIT, "get_query: from login appsrvid: %s\n",
			l->appsrvid == NULL ? "(null)" : l->appsrvid
			);
    pbc_log_activity(p, PBC_LOG_AUDIT, 
			"get_query: from login next_securid: %d\n", 
			l->next_securid);
    pbc_log_activity(p, PBC_LOG_AUDIT, "get_query: from login first_kiss: %d\n",
			(int)l->first_kiss);
    pbc_log_activity(p, PBC_LOG_AUDIT, 
			"get_query: from login post_stuff: %s\n", 
			(l->post_stuff==NULL ? "" : l->post_stuff));

    return(l);

} /* get-query */

/* uses libpubcookie calls to check the cookie and load the login rec with  */
/* cookie contents                                                          */
login_rec *verify_unload_login_cookie (pool *p, login_rec *l)
{
    pbc_cookie_data     *cookie_data;
    char		*cookie = NULL;
    login_rec		*new = NULL;
    time_t		t;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, 
		       "verify_unload_login_cookie: hello\n");

    if (!(cookie = malloc(PBC_4K)) )
        abend(p, "out of memory");

    /* get the login cookie */
    if ((get_cookie(p, PBC_L_COOKIENAME, cookie, PBC_4K-1)) == PBC_FAIL ) {
        if (cookie != NULL) 
            free(cookie);
        return( (login_rec *) NULL );
    }

    new = malloc(sizeof(login_rec));
    init_login_rec(p, new);

    cookie_data = libpbc_unbundle_cookie(p, cookie, NULL);

    /* Done with cookie */
    if (cookie != NULL)
        free(cookie);

    if (!cookie_data) {
        return((login_rec *)NULL);
    }

    new->user =  (char *) (*cookie_data).broken.user;
    new->version = (char *) (*cookie_data).broken.version;
    new->type = (*cookie_data).broken.type;
    new->creds = (*cookie_data).broken.creds;
    new->pre_sess_token = (*cookie_data).broken.pre_sess_token;
    new->appsrvid = (char *) (*cookie_data).broken.appsrvid;
    new->appid = (char *) (*cookie_data).broken.appid;
    new->create_ts = (*cookie_data).broken.create_ts;
    new->expire_ts = (*cookie_data).broken.last_ts;
    /* xxx login cookie extension data */

    if (check_l_cookie_expire(p, new, t=time(NULL)) == PBC_FAIL)
        new->alterable_username = PBC_TRUE;

    pbc_log_activity(p, PBC_LOG_AUDIT,
                     "verify_unload_login_cookie: bye!  user is %s\n", 
                     new->user  == NULL ? "(null)" : new->user 
                    );

    return(new);

}

int create_cookie(pool *p, char *user_buf,
                  char *appsrvid_buf,
                  char *appid_buf,
                  char type,
                  char creds,
                  int pre_sess_tok,
                  time_t expire,
                  char *cookie,
                  const char *host,
                  int max)
{
    /* measured quantities */
    unsigned char 	user[PBC_USER_LEN];
    unsigned char 	appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char 	appid[PBC_APP_ID_LEN];
    /* local junk */
    char		*cookie_local = NULL;
    char *peer = NULL;
    char *ptr = NULL;

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "create_cookie: hello\n"); 

    /* right size the args */
    strncpy( (char *) user, user_buf, sizeof(user));
    user[sizeof(user)-1] = '\0';
    strncpy( (char *) appsrvid, appsrvid_buf, sizeof(appsrvid));
    appsrvid[sizeof(appsrvid)-1] = '\0';
    strncpy( (char *) appid, appid_buf, sizeof(appid));
    appid[sizeof(appid)-1] = '\0';

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, 
                     "create_cookie: ready to go get cookie, with expire_ts: %d\n", 
                     (int)expire);

    /* go get the cookie */

    /* we need to chop the port number off of 'host', since we just key on
       hostname and not hostname:port but they're passed together in
       the greq */

    if (host != NULL) {

        peer = strdup(host);

        ptr = strchr(peer, ':');
        if (ptr) {
            *ptr = '\0';
        }
    }

    cookie_local = (char *) 
        libpbc_get_cookie_with_expire(p, user, type, creds, pre_sess_tok,
                                      expire, appsrvid, appid, peer);

    if (peer != NULL)
        free(peer);

    /* copy the output to 'cookie' */
    *cookie = '\0';
    if (cookie_local) {
        strncpy (cookie, cookie_local, max);
        /* dynamically allocated by libpbc_get_cookie_with_expire(p) */
        free(cookie_local);
    }

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "create_cookie: goodbye\n" ); 

    return (PBC_OK);
}

