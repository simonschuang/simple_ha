#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "librs_c_session.h"

int
librs_initSession (librs_c_session *session,
                   const char *host,
                   int port,
                   const char *account,
                   const char *pwd)
{
    if (session == NULL ||
        host == NULL || strlen (host) == 0 ||
        account == NULL || strlen (account) == 0 ||
        pwd == NULL || strlen (pwd) == 0) {
        return 1;
    }

    memset (session, 0, sizeof (librs_c_session));
    snprintf (session->host, sizeof (session->host), "%s", host);
    snprintf (session->account, sizeof (session->account), "%s", account);
    session->port = port;
    snprintf (session->pwd, sizeof (session->pwd), "%s", pwd);

    return 0;
}

int
librs_closeSession (librs_c_session *session)
{
    return 0;
}
