/*
  Copyright (c) 1999-2004 University of Washington.  All rights reserved.
  For terms of use see doc/LICENSE.txt in this distribution.
 */

/*
  $Id: securid.h,v 1.6 2004-02-10 00:42:15 willey Exp $
 */

#ifdef HAVE_MGOAPI_H
# include <mgoapi.h>
#endif /* HAVE_MGOAPI_H */

#define SECURID_DO_SID    1
#define SECURID_ONLY_CRN  0
#define SECURID_TYPE_NORM 0
#define SECURID_TYPE_NEXT 2

#define SECURID_OK        0
#define SECURID_FAIL      1
#define SECURID_WANTNEXT  2
#define SECURID_PROB      3
#define SECURID_BAILOUT   4

#define BIGS 1024

int securid (char *, char *, char *, char *, int, int, int);
