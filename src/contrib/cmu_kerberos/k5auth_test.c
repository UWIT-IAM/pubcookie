#include <stdio.h>
#include "k5auth.h"

int main(int argc, char **argv)
{
  const char *result;
  if(argc!=3)
    exit(2);
  /* /usr/www/www_krb5.keytab */
  result=kerberos5_verify_password(argv[1],argv[2],"pubcookie","FILE:/usr/www/private/www_krb5.keytab");
  if(result==0) {
    printf("ok\n");
    return 0;
  }
  printf("failed:'%s'\n",result);
  return 1;
}
