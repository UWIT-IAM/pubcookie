#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <krb5.h>

#include "k5auth.h"

/*
 * returns 0 success or error text on failure
 */
static const char *k5support_verify_tgt(krb5_context context, 
					krb5_ccache ccache,
					const char *principal,
					char *path_to_srvtab)
 
{
  krb5_principal server;
  krb5_data packet;
  krb5_keyblock *keyblock = NULL;
  krb5_auth_context auth_context = NULL;
  krb5_error_code k5_retcode;
  krb5_keytab id;
  char thishost[BUFSIZ];
  const char *result="can't get ticket";
  char foodat[2];
  memset(foodat,23,sizeof(foodat));

  /* this duplicates work done in krb5_sname_to_principal
   * oh well.
   */
  if (gethostname(thishost,BUFSIZ) < 0)
    return  "gethostname failed";
  thishost[BUFSIZ-1] = '\0';

  k5_retcode=krb5_make_principal(context,&server,NULL,
			 principal,thishost,NULL);
  if (k5_retcode)
    return "krb5_make_principal";

  k5_retcode=krb5_kt_read_service_key(context,path_to_srvtab,server, 0, 0, &keyblock);
  if (k5_retcode) {
    result="krb5_kt_read_service_key failed";
    goto fini;
  }

  if (keyblock)
    free(keyblock);

  krb5_data_zero(&packet);
  packet.length=sizeof(foodat);
  packet.data=foodat;

  k5_retcode = krb5_mk_req(context, &auth_context, 0,principal, 
			   thishost,NULL, ccache, &packet);
  if (auth_context) {
    krb5_auth_con_free(context, auth_context);
    auth_context = NULL;
  }

  if (k5_retcode) {
    result="krb5_mk_req faild";
    goto fini;
  }

  k5_retcode=krb5_kt_resolve(context,path_to_srvtab,&id);
  if (k5_retcode) {
    result="krb5_kt_resolve failed";
    goto fini;
  }

  k5_retcode=krb5_rd_req(context, &auth_context, &packet, 
			 server,id, NULL, NULL);
  if (k5_retcode) {
    result="krb5_rd_req failed";
    goto fini;
  }

  
  /* all is good now */
  result=0;

 fini:
  krb5_free_principal(context, server);

  return result;
}

const char *kerberos5_verify_password(const char *user,
				      const char *passwd,
				      const char *principal,
				      char *path_to_srvtab)
{
  krb5_context context;
  krb5_ccache ccache = NULL;
  krb5_principal auth_user;
  krb5_creds creds;
  krb5_get_init_creds_opt opts;

  char tfname[40];
  const char* result=0;
  
  if(user==0)
    return "k5:no username";

  if(passwd==0)
    return "k5:no password";

  if (krb5_init_context(&context))
    return "k5:init context failed";
    
  if (krb5_parse_name (context, user, &auth_user)) {
    krb5_free_context(context);
    return "k5:parse_name failed";
  }

  /* create a new CCACHE so we don't stomp on anything */
  snprintf(tfname,sizeof(tfname), "/tmp/k5cc_%d", getpid());
  if (krb5_cc_resolve(context, tfname, &ccache)) {
    krb5_free_principal(context, auth_user);
    krb5_free_context(context);
    return "k5:krb5_cc_resolve failed";
  }

  if (krb5_cc_initialize (context, ccache, auth_user)) {
    krb5_free_principal(context, auth_user);
    krb5_free_context(context);
    return "k5:krb5_cc_intilize failed";
  }

  krb5_get_init_creds_opt_init(&opts);

  /* 15 min should be more than enough */
  krb5_get_init_creds_opt_set_tkt_life(&opts, 900); 
  if (krb5_get_init_creds_password(context, &creds, 
				   auth_user, passwd, NULL, NULL, 
				   0, NULL, &opts)) {
    krb5_cc_destroy(context, ccache);
    krb5_free_principal(context, auth_user);
    krb5_free_context(context);
    return "k5:krb5_init_creds_password failed";
  }

  /* at this point we should have a TGT. Let's make sure it is valid */
  if (krb5_cc_store_cred(context, ccache, &creds)) {
    krb5_free_principal(context, auth_user);
    krb5_cc_destroy(context, ccache);
    krb5_free_context(context);
    return "k5:krb5_cc_store_cred";
  }

  if(result==0)
    result=k5support_verify_tgt(context,ccache,principal,path_to_srvtab);

/* destroy any tickets we had */
  krb5_free_cred_contents(context, &creds);
  krb5_free_principal(context, auth_user);
  krb5_cc_destroy(context, ccache);
  krb5_free_context(context);
  return result;
}
