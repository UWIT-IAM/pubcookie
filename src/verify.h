#ifndef INCLUDED_VERIFY_H
#define INCLUDED_VERIFY_H

/* returns 0 on success; non-zero on failure */
typedef int plaintext_verifier(const char *userid,
			       const char *passwd,
			       const char *service,
			       const char *user_realm,
			       const char **errstr);

/* given a string, find the corresponding verifier */
plaintext_verifier *get_verifier(const char *name);

#endif
