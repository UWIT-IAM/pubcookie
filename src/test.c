#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <pem.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#define LEN 5

void *main() {


    char	bongo[LEN];
    char	*bart;
 //   union ts {
//	time_t	ta_t;
//	char	ta_s[4];
 //   };
//    union ts	ta;
    //char	*out;
    pbc_cookie_data	*cookie_data;
    unsigned char	*cookie;
    md_context_plus	*sign_context_plus;
    md_context_plus	*verify_context_plus;
//    unsigned char 	*sig;
    unsigned char 	user[PBC_USER_LEN];
    unsigned char type;
    unsigned char creds;
    unsigned char appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char app_id[PBC_APP_ID_LEN];
//    char		cookie_string[4096];
    int			res;

    sign_context_plus = libpbc_sign_init();
    verify_context_plus = libpbc_verify_init();

    strcpy(user, "willey");
    type='1';
    creds='9';
    strcpy(appsrv_id, "appserver id is blah");
    strcpy(app_id, "application id is googoo");

    cookie = libpbc_get_cookie(user, type, creds, appsrv_id, app_id, sign_context_plus);
    if ( cookie )
        printf("%s\n", cookie);
    cookie_data = libpbc_unbundle_cookie(cookie, verify_context_plus);

//    (*cookie_data).string[PBC_USER_LEN-1] = '\0';
    if ( cookie_data ) 
	printf("user is %s\n", (*cookie_data).broken.user);
    else
	printf("this sucks\n");

    exit(1);

//    strcpy(cookie_string, "asdfasdkfjaiefjqwekfjkldfj");
//    sig = libpbc_sign_cookie(cookie_string, sign_context_plus);
//   res = libpbc_verify_sig(sig, cookie_string, verify_context_plus);
    exit(res);

    strcpy((*cookie_data).broken.user,"willey");

//    ta.ta_t = time(NULL);
//    printf("t %d s %s\n", ta.ta_t, ta.ta_s);

    strcpy(bongo, "blah");
//    t = (char *)calloc(  5 -1 +1, sizeof(char));
//    bart = (char *)strncpy(t,  bongo ,   5 -1 ) ;

    bart = pbc_strndup(bongo, LEN-1);
    printf("char %d\n", sizeof(char));
    printf("unsigned char %d\n", sizeof(unsigned char));
    printf("int %d\n", sizeof(int));
    printf("unsigned int %d\n", sizeof(unsigned int));
    printf("short %d\n", sizeof(short));
    printf("unsigned short %d\n", sizeof(unsigned short));
    printf("time_t %d\n", sizeof(time_t));
    printf("bongo %s  bongo %s\n", bongo, bart);

    exit (0);

}
