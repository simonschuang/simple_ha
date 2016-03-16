#include <stdio.h>
#include "librs_L2.h"

PNodeStruct*
librs_getAllNode (librs_c_session *session)
{
    c_session rs_session;
    PNodeStruct *nodes = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    nodes = getAllNode (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return nodes;
}
