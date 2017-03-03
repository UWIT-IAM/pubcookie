/*
 * https.h
 *
 * Copyright (c) 2011 Duo Security
 * All rights reserved, all wrongs reversed.
 */

#ifndef HTTPS_H
#define HTTPS_H

typedef struct https_request https_t;

#define DUO_NO_TIMEOUT -1

typedef enum {
        HTTPS_OK,
        HTTPS_ERR_SYSTEM,	/* system problem */
        HTTPS_ERR_LIB,		/* library problem */
        HTTPS_ERR_CLIENT,	/* something you did */
        HTTPS_ERR_SERVER,	/* something the server did */
} HTTPScode;

/* Initialize HTTPS library - do this once! */
HTTPScode   https_init(const char *useragent, const char *cafile,
                       const char *proxy);

/* Open HTTPS connection to host[:port] */
HTTPScode   https_open(https_t **hp, const char *host);

/* Send request, return 0 for success or -1 on error */
HTTPScode   https_send(https_t *h, const char *method, const char *uri,
                       const char *qs, const char *hdrs);

/* Read response, return HTTP status code, set body and length if available */
HTTPScode   https_recv(https_t *h, int *code, const char **body, int *length, int msecs_timeout);

/* Return and clear last API error */
const char *https_geterr(void);

/* Close HTTP connection */
void        https_close(https_t **hp);

#endif /* HTTPS_H */
