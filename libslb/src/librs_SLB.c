#include <stdio.h>
#include "librs_SLB.h"

struct LBRule *
librs_getRulesByVCUUID (librs_c_session *session,
                        char *vc_uuid)
{
    c_session rs_session;
    struct LBRule *rules = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    rules = getRulesByVCUUID (&rs_session,
                              vc_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return rules;
}

struct SLBInst *
librs_getInstByInstUUID (librs_c_session *session,
                         char *inst_uuid)
{
    c_session rs_session;
    struct SLBInst *inst = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    inst = getInstByInstUUID (&rs_session,
                              inst_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return inst;
}

struct SLBInst *
librs_getSSHGWByVCUUID (librs_c_session *session,
                        char *vc_uuid)
{
    c_session rs_session;
    struct SLBInst *inst = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    inst = getSSHGWByVCUUID (&rs_session,
                             vc_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return inst;
}

struct SLBInst *
librs_getRDPGWByVCUUID (librs_c_session *session,
                        char *vc_uuid)
{
    c_session rs_session;
    struct SLBInst *inst = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    inst = getRDPGWByVCUUID (&rs_session,
                             vc_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return inst;
}

//all LBRule
struct LBRule *
librs_getRulesAll (librs_c_session *session)
{
    c_session rs_session;
    struct LBRule *rules = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    rules = getRulesAll (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return rules;
}

//all SLBInst
struct SLBInst *
librs_getInstAll (librs_c_session *session)
{
    c_session rs_session;
    struct SLBInst *insts = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    insts = getInstAll (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return insts;
}

struct SlaPolicy *
librs_getSlaPolicybyVCUUID (librs_c_session *session,
                            char *vc_uuid)
{
    c_session rs_session;
    struct SlaPolicy *policy = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    policy = getSlaPolicybyVCUUID (&rs_session,
                                   vc_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return policy;
}

// L2 integration add two API
long
librs_getVdcIdByVCUUID (librs_c_session *session,
                        char *vc_uuid)
{
    c_session rs_session;
    long vdc_id = 0;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return 0;
    }

    vdc_id = getVdcIdByVCUUID (&rs_session,
                               vc_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return vdc_id;
}

struct IPRule *
librs_getPerVdcRangeByVDCID (librs_c_session *session,
                             long vdc_id)
{
    c_session rs_session;
    struct IPRule *rules = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    rules = getPerVdcRangeByVDCID (&rs_session,
                                   vdc_id);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return rules;
}

int
librs_createVdcPerfByVdcID (librs_c_session *session,
                            vdcPerf *vdc_perf)
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

    createVdcPerfByVdcID (&rs_session,
                          vdc_perf);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

struct SLBGw *
librs_getGwInfo (librs_c_session *session)
{
    c_session rs_session;
    struct SLBGw *rules = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    rules = getGwInfo (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return rules;
}

struct SLBSlb *
librs_getSlbInfo (librs_c_session *session)
{
    c_session rs_session;
    struct SLBSlb *rules = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    rules = getSlbInfo (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return rules;
}

subnet_rec *
librs_getSubnetByVdcId (librs_c_session *session,
                        const int iVdcId)
{
    c_session rs_session;
    subnet_rec *subnet_rs = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    subnet_rs = getSubnetByVdcId (&rs_session,
                                  iVdcId);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return subnet_rs;
}

void
librs_freeSubnetByVdcId (subnet_rec *pSubnetHead)
{
    freeSubnetByVdcId (pSubnetHead);
}

vnic_rec *
librs_getVnicByInstUuid (librs_c_session *session,
                         const char *szInstUuid)
{
    c_session rs_session;
    vnic_rec *vnic = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    vnic = getVnicByInstUuid (&rs_session,
                              szInstUuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return vnic;
}

void
librs_freeVnicByInstUuid (vnic_rec *pHead)
{
    freeVnicByInstUuid (pHead);
}

// SPFOUR-79
int
librs_setSubnetPmIp (librs_c_session *session,
                     int iSubnetId,
                     char *szPmIp)
{
    c_session rs_session;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return 0;
    }

    setSubnetPmIp (&rs_session,
                   iSubnetId,
                   szPmIp);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}
