#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <krb.h>
#include <kafs.h>

#include "k4auth.h"

const char *kerberos4_verify_password(const char *user,
				      const char *passwd,
				      const char *principal,
				      char *path_to_srvtab)
{
  int ret;
#define MAXKPATHLEN (1024)
  char tkt[MAXKPATHLEN];
  char lrealm[REALM_SZ];
  ret=krb_get_lrealm(lrealm,1);
  if(ret!=KSUCCESS)
    return "cant get local realm";
  snprintf(tkt, sizeof(tkt), "%s_pubcookie.%u", TKT_ROOT, (unsigned)getpid());
  krb_set_tkt_string (tkt);
  ret = krb_verify_user((char*)user,"",lrealm,(char*)passwd,
			  KRB_VERIFY_NOT_SECURE, NULL);
  dest_tkt();
  if(ret==KSUCCESS)
    return 0;
  return "bad k4 password";
}

