/*--------------------------------------------------------------------
      tokchk.c -- Verify a token
  --------------------------------------------------------------------*/
 
#include "tasapi.h"

static void PROC usage (void)
{
      fprintf (stdout, "usage: tokchk -u user -t token [-h host] [-p port] [-x config]\n");
      exit (1);
}

int PROC main (int argc, char **argv)
{
      MdsHandle *mds;
      CrnList crn;
      char *prnlist[1], serv[255], *host, *tasf, *tokn, *user;
      int  errs, mode, port, rets;

      MDSzero (&crn, sizeof (CrnList));
      mds = NULL; host = tasf = tokn = user = NULL; mode = errs = 1; port = 0;

      for (--argc, ++argv; argc > 0; argc--, argv++) {
         if (argv[0][0] == '-') {
            switch (argv[0][1]) {
               case 'h':
                  if (--argc == 0) usage ();
                  host = (++argv)[0];
                  break;
               case 'p':
                  if (--argc == 0) usage ();
                  port = atoi ((++argv)[0]);
                  break;
               case 't':
                  if (--argc == 0) usage ();
                  tokn = (++argv)[0];
                  break;
               case 'u':
                  if (--argc == 0) usage ();
                  user = (++argv)[0];
                  break;
               case 'x':
                  if (--argc == 0) usage ();
                  tasf = (++argv)[0];
                  break;
               default:
                 usage ();
            }
         }
      }

      if (user != NULL && tokn != NULL) {
            if (host == NULL) host = TAS_HOST;
            if (port ==    0) port = TAS_PORT;
            TASinitialize (&mds, tasf);
            MDSsetoption (mds, MDS_OPT_HOST, (void *)  host);
            MDSsetoption (mds, MDS_OPT_PORT, (void *) &port);
            strcpy (crn.user, user);
            strcpy (crn.prn , tokn);
            if ((rets = TASchktoken (mds, &crn)) == MDS_SUCCESS) {
               fprintf (stdout, "PASS\n");
               errs = 0;
            } else {
               fprintf (stdout, "FAIL\n");
            }
      } else {
         usage ();
      }

      exit (errs);
}
