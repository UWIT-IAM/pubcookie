/*--------------------------------------------------------------------
      messages.h -- SecurID API message definitions
  --------------------------------------------------------------------*/

#ifndef _SIDMSGS_H_
#define _SIDMSGS_H_

#define ERR_MSGS_MAX  8       /* Number of messages */

static char *_err_msgs[] = 
{
  "Success",
  "Network communications error"
  "No more tokens in string",
  "Invalid or missing argument",
  "Invalid or missing option",
  "No servers are available",
  "Invalid CRN or PRN value",
  "Next PRN value is required",
};

#endif /* _SIDMSGS_H_ */
