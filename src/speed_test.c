/*
    $Id: speed_test.c,v 1.2 2000-04-07 17:37:29 willey Exp $
 */

/* Copyright 1999, University of Washington.  All rights reserved. */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/times.h>
#include <string.h>
#include <pem.h>
#include <unistd.h>
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

typedef struct {
    clock_t	begin_uclock;
    clock_t	save_uclock;
    clock_t	begin_sclock;
    clock_t	save_sclock;
    time_t	begin_time;
    time_t	save_time;
} time_keeper;
static time_keeper	tk;

void start_time() {
    tk.begin_uclock = tk.save_uclock = clock();
    tk.begin_time = tk.save_time = time(NULL);
}

void prn_time(int n) {
    char	s1[PBC_1K];
    char	s2[PBC_1K];
    int		wid, len1, len2;
    double	clocks_per_sec = (double)CLOCKS_PER_SEC;
    double	user_clocks, user_time;
    double	real_time;
    double	c;

    c = clock();
    user_clocks = c - tk.save_uclock;
    user_time = user_clocks / clocks_per_sec;

    real_time = difftime(time(NULL), tk.save_time);

    tk.save_uclock = c;
    tk.save_time = time(NULL);

    printf("\t%d interations:\n", n);

    len1 = sprintf(s1, "%.1f", user_time);
    len2 = sprintf(s2, "%.1f", real_time);
    wid = (len1>len2) ? len1 : len2;
    printf("User time: %*.4f seconds, %*.4f clocks\nReal time: %*.1f seconds\n",
        wid, user_time, wid, user_clocks, wid, real_time);
    printf("\t%f per second\n", n / real_time);
    
}

void tot_time(int n) {
    char	s1[PBC_1K];
    char	s2[PBC_1K];
    int		wid, len1, len2;
    double	clocks_per_sec = (double)CLOCKS_PER_SEC;
    double	user_clocks, user_time;
    double	real_time;
    double	c;

    c = clock();
    user_clocks = c - tk.begin_uclock;
    user_time = user_clocks / clocks_per_sec;

    real_time = difftime(time(NULL), tk.begin_time);

    printf("\t%d interations total:\n", n);

    len1 = sprintf(s1, "%.1f", user_time);
    len2 = sprintf(s2, "%.1f", real_time);
    wid = (len1>len2) ? len1 : len2;
    printf("User time: %*.4f seconds, %*.4f clocks\nReal time: %*.1f seconds\n",
        wid, user_time, wid, user_clocks, wid, real_time);
    printf("\t%f per second\n", n / real_time);
    
}

void usage(const char *progname) {
    printf("%s [-k key_file] [-c cert_file] [-s key_for_cert_file][-h]\n\n", progname);
    printf("\t key_file:\tencyption key, \n\t\t\tdefault is %s\n", PBC_CRYPT_KEYFILE);
    printf("\t cert_file:\tcetificate file, \n\t\t\tdefault is %s\n", PBC_G_CERTFILE);
    printf("\t key_for_cert_file:\tkey for cetificate file, \n\t\t\tdefault is %s\n\n", PBC_G_KEYFILE);
    exit (1);
}

int main(int argc, char **argv) {
    unsigned char type;
    unsigned char creds;
    int serial=2147483647;
    char user[PBC_USER_LEN];
    unsigned char appsrv_id[PBC_APPSRV_ID_LEN];
    unsigned char app_id[PBC_APP_ID_LEN];
    unsigned char       *cookie;
    unsigned char       *updated_cookie;
    pbc_cookie_data	*cookie_data;
    pbc_cookie_data	*cookie_data2;
    char		*key_file = NULL;
    char		*g_cert_file = NULL;
    char		*g_key_file = NULL;
    int 		c, barfarg = 0;

    int			i, iterations = 500;
    int			iter_chunk = 100;

    md_context_plus 	*s_ctx_plus;
    md_context_plus	*v_ctx_plus;
    crypt_stuff         *c_stuff;

    optarg = NULL;
    while (!barfarg && ((c = getopt(argc, argv, "hk:c:s:i:")) != -1)) {
	switch (c) {
	case 'h' :
	    usage(argv[0]);
	    break;
	case 'i' :
	    iterations = atoi(optarg);
	    break;
	case 'k' :
	    key_file = strdup(optarg);
	    break;
	case 'c' :
	    g_cert_file = strdup(optarg);
	    break;
	case 's' :
	    g_key_file = strdup(optarg);
	    break;
	default :
	    barfarg++;
	    usage(argv[0]);
	}
    }

    type='1';
    creds='9';
    strncpy(appsrv_id, "appserver id is blah", PBC_APPSRV_ID_LEN);
    strncpy(app_id, "app id is googoo", PBC_APP_ID_LEN);
    strncpy(user, "bongo", PBC_USER_LEN);

    if ( key_file )
        c_stuff = libpbc_init_crypt(key_file);
    else
        c_stuff = libpbc_init_crypt(PBC_CRYPT_KEYFILE);

    if ( g_key_file )
        s_ctx_plus = libpbc_sign_init(g_key_file);
    else
        s_ctx_plus = libpbc_sign_init(PBC_G_KEYFILE);

    if ( g_cert_file )
        v_ctx_plus = libpbc_verify_init(g_cert_file);
    else
        v_ctx_plus = libpbc_verify_init(PBC_G_CERTFILE);

    start_time();

    for( i = 1; i <= iterations; i++ ) {
        cookie = libpbc_get_cookie(user, type, creds, serial, appsrv_id, app_id, s_ctx_plus, c_stuff);

        if ( ! (cookie_data=libpbc_unbundle_cookie(cookie, v_ctx_plus, c_stuff)) ) {
            printf("test failed: cookie couldn't be unbundled\n");
	    exit (1);
        }
        updated_cookie = libpbc_update_lastts(cookie_data, s_ctx_plus, c_stuff);
    
        cookie_data2 = libpbc_unbundle_cookie(updated_cookie, v_ctx_plus, c_stuff);
        if( cookie_data2 ) {
//	    printf("!");
        } 
        else {
	    printf("this sucks\n");
        } 

        if( i % iter_chunk == 0 ) {
            printf("\n\t%d iterations:\n", iter_chunk);
            prn_time(iter_chunk);
        }
        else
            fflush(stdout);
    }
 
    printf("\n");

    tot_time(iterations);
    exit(0);
}
    
