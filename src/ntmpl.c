/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/** @file ntmpl.c
 * Template library
 *
 * $Id: ntmpl.c,v 1.15 2004-08-18 00:53:10 willey Exp $
 */

#ifdef WITH_FCGI
#include "fcgi_stdio.h"
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include "pbc_logging.h"
#include "pbc_config.h"
#include "pubcookie.h"

/* hmm, bad place for this prototype. */
extern FILE *htmlout;
extern FILE *mirror;

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
static char *get_file_template(pool *p, const char * fpath, const char *fname)
{
    char *templatefile;
    char *template = NULL;
    long len, readlen;
    FILE *tmpl_file;

    /* +2 for the "/" between and the trailing null */
    len = strlen(fpath) + strlen(fname) + 2;
    templatefile = (char *) malloc(len * sizeof(char));
    if (templatefile == NULL) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
                         "unable to malloc %d bytes for template filename %s", 
                         len, fname);
        goto done;
    }
    if ( snprintf(templatefile, len, "%s%s%s", fpath,
                  fpath[strlen(fpath) - 1 ] == '/' ? "" : "/",
                  fname) > len)  {
       pbc_log_activity(p, PBC_LOG_ERROR, 
		       "template filename overflow");
       goto done;
    }


    tmpl_file = (FILE *) pbc_fopen(p, templatefile, "r");
    if (tmpl_file == NULL) {
        pbc_log_activity(p, PBC_LOG_ERROR, "cant open template file %s",
                     templatefile);
        template = NULL;
        goto done;
        return NULL;
    }

    len=file_size(p, tmpl_file);
    if (len==0) {
        goto done;
    }

    template = (char *) malloc((len+1) * sizeof (char));
    if (template == NULL) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
		       "unable to malloc %d bytes for template file %s", 
		       len+1, fname);
        goto done;
    }

    *template=0;
    readlen = fread(template, 1, len, tmpl_file);
    if (readlen != len) {
        pbc_log_activity(p, PBC_LOG_ERROR,
		 "read %d bytes when expecting %d for template file %s", 
		 readlen, len, fname);
        pbc_free(p, template);
        template = NULL;
        goto done;
    }

    template[len]=0;

    pbc_fclose(p, tmpl_file);

done:

    if(templatefile != NULL)
        pbc_free(p, templatefile);

    return template;

}

/**
 * ntmpl_print_html() takes a template and a list of items to fill in 
 * and prints to the HTML buffer the result of substitutions.
 * @param fname the name of the template to substitute for
 * @param ... a sequence of attr, substitution parameters for the
 * substitutions.  the attributes are searched for in the template
 * with "%<attr>%"; the entire string is then replaced with the next
 * parameter.  the caller must pass a NULL after all attributes
 */
void ntmpl_print_html(pool *p, const char *fpath, const char *fname, ...)
{
    const char *attr;
    const char *subst;
    va_list ap;
    char *template = get_file_template(p, fpath, fname);
    char *t;
    char *percent;
    char candidate[256];
    int i;

    memset(candidate, 0, 256);

    t = template;
    /* look for the next possible substitution */
    while ((percent = strchr(t, '%')) != NULL) {
        fwrite(t, percent - t, 1, htmlout);
        if( mirror != NULL)
            fwrite(t, percent - t, 1,  mirror);

        /* look to see if this is a legitimate candidate for substitution */
        for (i = 1; percent[i] && (i < sizeof(candidate) - 1); i++) {
            if (percent[i] == '%') break;
            candidate[i-1] = percent[i];
        }
        /* terminate candidate */
        candidate[i-1] = '\0';

        attr = NULL;
        subst = NULL;
        if (percent[i] == '%') {
            /* ok, found a trailing %, so 'candidate' contains a possible
               substitution. look for it in the params */
            va_start(ap, fname);
            while ((attr = va_arg(ap, const char *)) != NULL) {
                subst = va_arg(ap, const char *);
                
                if (!strcmp(attr, candidate)) {
                    /* bingo, matched! */
                    break;
                }
            }
        }

        if (attr != NULL && subst != NULL) {
            /* we found a match; print that out instead */
            fputs(subst, htmlout);
            if( mirror != NULL)
                fputs(subst,  mirror);
            /* move to the trailing % */
            percent = strchr(percent + 1, '%');
        } else {
            /* false alarm, not a substitution */
            fputc('%', htmlout);
            if( mirror != NULL)
                fputc('%', mirror);
        }
        /* skip after the % */
        t = percent + 1;
    }
    
    /* print out everything from the last % on */
    fputs(t, htmlout);
    if( mirror != NULL)
        fputs(t, mirror);

    pbc_free(p, template);
}

/* in the absense of a better template library create html from sub-templates
   this is code that that defected from flavour_basic.c                       */
/* returns NULL if it can't return the correct string */
char *ntmpl_sub_template(pool *p, const char *fpath, const char *fname, ...)
{
    char *field_html = NULL;   /* net result */
    char *fieldfile;
    int filelen;
    int field_len;
    FILE *field_file;
    char buf[PBC_1K];
    int len = PBC_1K;
    int current_len;
    va_list ap;
    char *t;
    char *percent;
    int i;
    char candidate[PBC_1K];
    const char *attr;
    const char *subst;
    char func[] = "ntmpl_sub_template";

    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s: hello", func);

    filelen = strlen(fpath) + strlen("/") + strlen(fname) + 1;

    fieldfile = malloc( filelen *sizeof(char) );

    if ( snprintf( fieldfile, filelen, "%s%s%s",
                   fpath,
                   fpath[strlen(fpath) - 1 ] == '/' ? "" : "/",
                   fname ) > filelen )  {
        /* Need to do something, we would have overflowed. */
        abend(p, "field filename overflow!\n");
    }

    field_file = pbc_fopen(p, fieldfile, "r" );

    if (field_file == NULL) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
                         "%s: Cannot open sub-template file %s", 
			 func, fieldfile);
        return(NULL);
    }

    field_len = file_size(p, field_file);

    if (field_len == 0)
        return NULL;

    if ( field_len >= sizeof(buf) ) {
        pbc_log_activity(p, PBC_LOG_ERROR, 
                         "%s: Need bigger buffer for reading sub-template file, %D not big enough", func, sizeof(buf));
        return(NULL);
    }

    field_html = malloc( (field_len + 1) * sizeof( char ) + len );

    if ( field_html == NULL ) {
        /* Out of memory! */
        libpbc_abend(p,  "Out of memory allocating to field file" );
    }

    current_len = fread( buf, 1, field_len, field_file );

    if (current_len != field_len) {
        libpbc_abend(p,  "read %d when expecting %d on field file read.",
                      current_len, field_len );
    }

    pbc_fclose(p, field_file);
    if (fieldfile != NULL)
        free(fieldfile);

    buf[field_len] = '\0';
    current_len = len;
    strcpy(field_html, buf);

    t = field_html;
    /* look for the next possible substitution */
    while ((percent = strchr(t, '%')) != NULL) {

        /* look to see if this is a legitimate candidate for substitution */
        for (i = 1; percent[i] && (i < sizeof(candidate) - 1); i++) {
            if (percent[i] == '%') break;
            candidate[i-1] = percent[i];
        }
        /* terminate candidate */
        candidate[i-1] = '\0';

        attr = NULL;
        subst = NULL;
        if (percent[i] == '%') {
            /* ok, found a trailing %, so 'candidate' contains a possible
               substitution. look for it in the params */
            va_start(ap, fname);
            while ((attr = va_arg(ap, const char *)) != NULL) {
                subst = va_arg(ap, const char *);
                
                if (!strcmp(attr, candidate)) {
                    /* bingo, matched! */
                    break;
                }
            }
        }

        if (attr != NULL && subst != NULL) {
            
            if ( current_len - strlen(subst) < 0 ) {
                pbc_log_activity(p, PBC_LOG_ERROR, 
                         "%s: not enough room in buffer for substitutions", 
                         func);
                goto done;
            }
            
            /* save what comes after */
            strcpy(buf, percent+i+1);

            /* piece them back together */
            strcpy(percent, subst);
            strcpy(percent+(int)strlen(subst), buf);
    
            /* move to the trailing % */
            percent = percent+(int)strlen(subst);

            current_len -= strlen(subst);
            
        }
        /* skip after the % */
        t = percent + 1;
    }

done: 
    pbc_log_activity(p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %s",
                func, field_html);

    return field_html;

}

#ifdef TEST_NTMPL

#include <stdio.h>

/* the test will substitute 
 *   '%name%' with 'Harry Bovik'
 *   '%userid%' with 'bovik'
 *   '%none%' with NULL
 */
/* pairs of tests/results */
char *test[] = 
{
    "hello", "hello", 
    "hello % hello", "hello % hello",
    "hello %foo% hello", "hello %foo% hello",
    "hello %name% how are you?", "hello Harry Bovik how are you?",
    "hello %name% you are %userid%?", "hello Harry Bovik you are bovik?",
    "%name% aaa", "Harry Bovik aaa",
    "aaa %name%", "aaa Harry Bovik",
    "hello %name hello", "hello %name hello",
    "hello name% hello", "hello name% hello",
    "%foo%name%foo%", "%fooHarry Bovikfoo%",
    "a %none% c", "a %none% c",
    "%name%name%", "Harry Bovikname%",
    "%%name%name%", "%Harry Bovikname%",
    "%none%name%name%", "%noneHarry Bovikname%",
    NULL, NULL,
};

/* needed so we can look at the output */
FILE *htmlout;

int main(int argc, char *argv[])
{
    int i;
    char *x, *y;
    char outbuf[1024];
    FILE *f;
    int err = 0;
    int verbose;
    void *p;

    if (argc > 1 && !strcmp(argv[1], "-v")) {
        verbose++;
    }

    for (i = 0; test[i] != NULL; i += 2) {
        x = test[i]; y = test[i + 1];

        /* initialize htmlout */
        htmlout = tmpfile();

        /* write x to a file */
        f = fopen("/tmp/tmpl_test", "w");
        if (f == NULL) {
            perror("fopen");
            exit(1);
        }
        fputs(x, f);
        fclose(f);

        /* do the substitution */
        ntmpl_print_html(p, "/tmp", "tmpl_test",
                         "name", "Harry Bovik",
                         "none", NULL,
                         "userid", "bovik",
                         NULL);

        /* read from htmlout */
        rewind(htmlout);
        fgets(outbuf, sizeof(outbuf), htmlout);

        /* compare to y */
        if (strcmp(outbuf, y)) {
            printf("ERROR\n"
                   "   template '%s'\n"
                   "   wanted   '%s'\n"
                   "   got      '%s'\n", x, y, outbuf);
            err++;
        } else if (verbose) {
            printf("PASSED '%s'\n", x);
        }

        /* discard htmlout */
        fclose(htmlout);
    }

    if (err || verbose) {
        printf("%d error%s\n", err, err != 1 ? "s" : "");
    }

    exit(err);
}

#endif


