/* -------------------------------------------------------------------- */
/* $Id: securid.h,v 1.1 2000-09-08 19:23:58 willey Exp $         */
/* -------------------------------------------------------------------- */

#define SECURID_DO_SID    1
#define SECURID_ONLY_CRN  0
#define SECURID_TYPE_NORM 0
#define SECURID_TYPE_NEXT 2

#define SECURID_OK        0
#define SECURID_FAIL      1
#define SECURID_WANTNEXT  2
#define SECURID_PROB      3
#define SECURID_BAILOUT   4

int securid (char *, char *, char *, char *, int, int, int);
