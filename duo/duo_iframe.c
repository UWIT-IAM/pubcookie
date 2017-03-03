/* duo code for iframe implementation.
   Univ Wash copyright, Fox
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "duo.h"
#include "duo_iframe.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

static char *AUTH_PREFIX = "AUTH";
static char *DUO_PREFIX = "TX";
static char *APP_PREFIX = "APP";
static int DUO_EXPIRE = 300;
static int APP_EXPIRE = 3600;

// convert some data to base64
static int _data_to_base64(char **d64, int *d64l, void *data, int dl)
{
   BIO *b64, *bmem;
   BUF_MEM *bmem_mem;

   b64 = BIO_new(BIO_f_base64());
   BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
   bmem = BIO_new(BIO_s_mem());
   BIO_push(b64, bmem);

   BIO_write(b64, data, dl);
   BIO_flush(b64);
   BIO_get_mem_ptr(bmem, &bmem_mem);
   *d64 = strdup(bmem_mem->data);
   if (d64l) *d64l = bmem_mem->length;
   BIO_free_all(bmem);
   return (1);
}

// convert some base64 to data
static int _base64_to_data(char **data, int *dl, char *d64, int d64l)
{
   BIO *b64, *bmem;

   b64 = BIO_new(BIO_f_base64());
   bmem = BIO_new(BIO_s_mem());
   BIO_push(b64, bmem);
   BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);

   char *buf = (char*) malloc(d64l+4);
   BIO_write(bmem, d64, d64l);
   BIO_flush(bmem);
   int nb = BIO_read(b64, buf, d64l);
   *data = buf;
   if (dl) *dl = nb;
   BIO_free_all(bmem);
   return (1);
}

// compute an HMAC
static char* _hmac(char *skey, char *txt) {
   char *ret = (char*) malloc(SHA_DIGEST_LENGTH*4);
   HMAC_CTX hmac;
   unsigned char MD[SHA_DIGEST_LENGTH];
   HMAC_CTX_init(&hmac);
   HMAC_Init(&hmac, skey, strlen(skey), EVP_sha1());
   HMAC_Update(&hmac, (u_char *)txt, strlen(txt));
   HMAC_Final(&hmac, MD, NULL);
   HMAC_CTX_cleanup(&hmac);

   int i;
   char *p = ret;
   for (i=0; i<sizeof(MD); i++) {
      sprintf(p, "%02x", MD[i]);
      p += 2;
   }
   *p = '\0';
   // printf ("hmac = %s\n", ret);
   return (ret);
}

// sign some stuff
static char *_sign_vals(char *skey, char *username, char *ikey, char *prefix, int expire) {
   time_t tt = time(NULL);
   int exp = tt + expire;
   char *txt = (char*) malloc(10000);
   sprintf((char*)txt, "%s|%s|%d", username, ikey, exp);
   char *b64;
   int b64l;
   int ret = _data_to_base64(&b64, &b64l, (void*)txt, strlen(txt));
   b64[b64l] = '\0';
   sprintf(txt, "%s|%s", prefix, b64);
   // printf ("tob64 ret = %d: [%s]\n", ret, txt);

   char *hmtxt = _hmac(skey, txt);
   strcat(strcat(txt, "|"), hmtxt);

   return (txt);
}

// verify part of duo auth response
static char *_parse_vals(char *key, char *in_sig, char *prefix, char *ikey) {
   char *u_prefix = in_sig;
   char *u_b64 = strchr(in_sig, '|');
   *u_b64++ = '\0';
   char *u_sig = strchr(u_b64, '|');
   *u_sig++ = '\0';

   // printf("u_pref=%s, u_b64=%s, u_sig=%s\n", u_prefix, u_b64, u_sig);

   char *txt =  (char*) malloc(10000);
   sprintf(txt, "%s|%s", u_prefix, u_b64);
   // printf ("intxt = %s\n", txt);
   char *sig = _hmac(key, txt);
   // printf ("sig = %s\n", sig);

   char *dec;
   int decl;
   _base64_to_data(&dec, &decl, u_b64, strlen(u_b64));
   dec[decl] = '\0';
   // printf("dec = %s\n", dec);

   char *x = strchr(dec, '|');
   *x = '\0';
   return (dec);
}

// make an iframe signed request
char *sign_web_request(char *ikey, char *skey, char *akey, char *username) {
   char *part1 = _sign_vals(skey, username, ikey, DUO_PREFIX, DUO_EXPIRE);
   // printf("part1 = %s\n", part1);
   char *part2 = _sign_vals(akey, username, ikey, APP_PREFIX, APP_EXPIRE);
   // printf("part2 = %s\n", part2);
   char *ret = (char*) malloc(strlen(part1)+strlen(part2)+4);
   strcat(strcat(strcpy(ret, part1), ":"), part2);
   free(part1);
   free(part2);
   return ret;
}

// verify a duo iframe response
char *verify_response(char *ikey, char *skey, char *akey, char *sigresp) {
   char *auth_sig = sigresp;
   char *app_sig = strchr(sigresp, ':');
   if (app_sig) *app_sig++ = '\0';
   else {
      app_sig = strstr(sigresp, "%3A");
      if (app_sig) {
         *app_sig = '\0';
         app_sig += 3;
      } else {
         return (NULL);
      }
   }
   char *auth_user = _parse_vals(skey, auth_sig, AUTH_PREFIX, ikey);
   char *app_user = _parse_vals(akey, app_sig, APP_PREFIX, ikey);
   return auth_user;
}



