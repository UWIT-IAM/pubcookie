#ifndef INCLUDED_SECURITY_H
#define INCLUDED_SECURITY_H

/**
 * initializes the security subsystem.
 * the configuration & logging subsystems are required prerequisites
 * @returns non-zero on error
 */
int security_init(void);

/**
 * libpbc_mk_priv takes 'buf', 'len', and returns 'outbuf', 'outlen',
 * an encrypted string that can only be read by 'peer'.
 * @param peer the name of the peer this is destined for.  if NULL,
 * the message will be signed with private material that is only known
 * to this host. 
 * @param buf a pointer to the cleartext string
 * @param len the length of the data pointed to by buf
 * @param outbuf will be filled in with a malloc()ed buffer.  it must
 * later be free()ed.
 * @param outlen the length of outbuf.
 * @returns 0 on success, non-zero on failure.
 */
int libpbc_mk_priv(const char *peer, const char *buf, const int len,
		   char **outbuf, int *outlen);

/**
 * libpbc_rd_priv decodes an encrypted string sent by 'peer'.  if
 * 'peer' is NULL, we assume that this host previously called libpbc_mk_priv
 * @param peer the peer this message came from; if NULL, this message came
 * from this host.
 * @param buf a pointer to the encrypted message
 * @param len the length of the encrypted message
 * @param outbuf a malloc()ed pointer to the plaintext message
 * @param outlen the length of the plaintext message
 * @returns 0 on success, non-0 on failure (including if the message could 
 * not be decrypted or did not pass integrity checks)
 */
int libpbc_rd_priv(const char *peer, const char *buf, const int len,
		   char **outbuf, int *outlen);

/**
 * libpbc_mk_safe allocates a signature and returns it to the
 * application. 'outbuf' does not contain the plaintext message; both
 * 'buf' and 'outbuf' must be sent to the other side.
 * @param peer the peer this message is being sent to; if NULL, this message
 * is destined to myself.
 * @param buf a pointer to the message to be sent
 * @param len  the length of the message
 * @param outbuf a malloc()ed pointer to the signature
 * @param outlen the length of the signature
 * @returns 0 success, non-0 on failure
 */
int libpbc_mk_safe(const char *peer, const char *buf, const int len,
		   char **outbuf, int *outlen);

/**
 * verifies a message signed with libpbc_mk_safe()
 * @param peer the peer this message was sent from; NULL if this is me
 * @param buf the plaintext message
 * @param len the length of the plaintext message
 * @param sigbuf the signature returned from libpbc_mk_safe()
 * @param siglen the length of the received signature
 * @returns 0 on success, non-0 on any failure
 */
int libpbc_rd_safe(const char *peer, const char *buf, const int len,
		   const char *sigbuf, const int siglen);

#endif
