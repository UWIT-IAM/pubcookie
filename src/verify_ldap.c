int ldap_verifier(const char *userid,
			const char *passwd,
			const char *service,
			const char *user_realm,
			const char **errstr)
{
    *errstr = "ldap not implemented";
    return -1;
}
