int kerberos4_verifier(const char *userid,
			const char *passwd,
			const char *service,
			const char *user_realm,
			const char **errstr)
{
    *errstr = "kerberos4 not implemented";
    return -1;
}
