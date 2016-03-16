/*
 * librs_c_session.h
 *
 *  Created on: 2014/12/3
 *      Author: Hogan
 */

#ifndef LIBRS_C_SESSION_H_
#define LIBRS_C_SESSION_H_

#include <string.h>
#include <../global/c_session.h>

typedef struct librs_CSession {
	char host[128];
	char account[20];
	char pwd[20];
	int port;

    char error_message[256];
    int error_code;
} librs_c_session;

/* return 0: success 1: failed */
int
librs_initSession (librs_c_session *session,
                   const char *host,
                   int port,
                   const char *account,
                   const char *pwd);

/* Always return 0: success */
int
librs_closeSession (librs_c_session *session);

static inline void
librs_error_message_copy (librs_c_session *session,
                          c_session *rs_session)
{
    if (session == NULL || rs_session == NULL) {
        return;
    }

    memcpy (session->error_message, rs_session->error_message, sizeof (session->error_message));
    session->error_code = rs_session->error_code;
}

#endif /* LIBRS_C_SESSION_H_ */
