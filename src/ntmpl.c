#include <stdlib.h>
#include <string.h>

#include "index.cgi.h"

#include "pbc_logging.h"

/* hmm, bad place for this prototype. */
extern FILE *htmlout;

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
    pbc_log_activity(PBC_LOG_ERROR, "abend - cant open template file", fname);
    return NULL;
  }

  len=file_size(tmpl_file);
  if (len==0) {
      return NULL;
  }

  template = malloc (len+1);
  if (template == NULL) {
       pbc_log_activity(PBC_LOG_ERROR, 
		       "unable to mallow %d bytes for template file %s", 
		       len+1, fname);
      return NULL;
  }

  *template=0;
  readlen = fread(template, 1, len, tmpl_file);
  if (readlen != len) {
      pbc_log_activity(PBC_LOG_ERROR,
		 "abend: read %d bytes when expecting %d for template file %s", 
		 readlen, len, fname);
      free(template);
      return NULL;
  }

  template[len]=0;
  fclose(tmpl_file);
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
void ntmpl_print_html(const char *fname, ...)
{
    const char *attr;
    const char *subst;
    va_list ap;
    char *template = get_file_template(fname);
    char *t;
    char *percent;
    char candidate[256];
    int i;

    t = template;
    /* look for the next possible substitution */
    while ((percent = strchr(t, '%')) != 0) {
        fwrite(t, percent - t, 1, htmlout);

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
            /* move to the trailing % */
            percent = strchr(percent + 1, '%');
        } else {
            /* false alarm, not a substitution */
            fputc('%', htmlout);
        }
        /* skip after the % */
        t = percent + 1;
    }
    
    /* print out everything from the last % on */
    fputs(t, htmlout);

    free(template);
}

#ifdef TEST_NTMPL

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
        ntmpl_print_html("/tmp/tmpl_test",
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