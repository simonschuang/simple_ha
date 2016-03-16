#include "librs_Monitor.h"

int
librs_createInstPerfByInstUUID (librs_c_session *session,
                                instPerf *inst_perf)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    createInstPerfByInstUUID (&rs_session,
                              inst_perf);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

int
librs_createNodePerfByIP (librs_c_session *session,
                          nodePerf *node_perf)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    createNodePerfByIP (&rs_session,
                        node_perf);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

int
librs_sendHttpLatency2RS (librs_c_session *session,
                          httpLatency *http_latency)
{
    /* TODO */
    return 0;
}

/* to insert bulk of nex-NULL-ENDED list of `instPerf`
 * into RS table `inst_performance`
 * expected to be called periodically, (every 3 sec, maybe)
 * return : 0 means NO Error, else means Error code
 * */
int
librs_createInstPerfList (librs_c_session *session,
                          const instPerf *pFirstInstPerf)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    createInstPerfList (&rs_session,
                        pFirstInstPerf);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

int
librs_createDailyInstPerf (librs_c_session *session,
                           const DailyPerfData *pDailyPerfData,
                           int iInstId,
                           int iVcId)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    createDailyInstPerf (&rs_session,
                         pDailyPerfData,
                         iInstId,
                         iVcId);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

int
librs_createDailyVcPerf (librs_c_session *session,
                         const int iVcId,
                         const DailyPerfData *pDailyPerfData,
                         int iVdcId)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    createDailyVcPerf (&rs_session,
                       iVcId,
                       pDailyPerfData,
                       iVdcId);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

int
librs_createDailyVdcPerf (librs_c_session *session,
                          const int iVdcId,
                          const DailyPerfData *pDailyPerfData)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    createDailyVdcPerf (&rs_session,
                        iVdcId,
                        pDailyPerfData);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

/* return 0 means no error existed */
int
librs_getIDsFromInstUuid (librs_c_session *session,
                          const char *szInstUuid,
                          int *piInstId,
                          int *piVcId,
                          int *piVdcId)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return -1;
    }

    getIDsFromInstUuid (&rs_session,
                        szInstUuid,
                        piInstId,
                        piVcId,
                        piVdcId);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return session->error_code;
}
