#include <stdio.h>
#include "k4auth.h"

int main(int argc, char **argv)
{
  const char *result;
  if(argc!=3)
    exit(2);
  result=kerberos4_verify_password(argv[1],argv[2],"pubcookie","/usr/www/private/srvtab");
  if(result==0) {
    printf("ok\n");
    return 0;
  }
  printf("failed:'%s'\n",result);
  return 1;
}
