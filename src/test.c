#include "pbc_config.h"
#include <time.h>
#define LEN 5

main() {

    char	bongo[LEN];
    char	*bart;
    char	a;
    time_t	t;
    union ts {
	time_t	ta_t;
	char	ta_s[4];
    };
    union ts	ta;
    //char	*out;



    ta.ta_t = time(NULL);
    printf("t %d s %s\n", ta.ta_t, ta.ta_s);

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

}
