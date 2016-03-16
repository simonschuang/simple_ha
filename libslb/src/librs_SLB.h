/*
 * librs_SLB.h
 *
 *  Created on: 2014/12/3
 *      Author: Hogan
 */

#ifndef LIBRS_SLB_H_
#define LIBRS_SLB_H_

#include <SLB.h>
#include "librs_c_session.h"

struct LBRule *
librs_getRulesByVCUUID (librs_c_session *session,
                        char *vc_uuid);

struct SLBInst *
librs_getInstByInstUUID (librs_c_session *session,
                         char *inst_uuid);

struct SLBInst *
librs_getSSHGWByVCUUID (librs_c_session *session,
                        char *vc_uuid);

struct SLBInst *
librs_getRDPGWByVCUUID (librs_c_session *session,
                        char *vc_uuid);

//all LBRule
struct LBRule *
librs_getRulesAll (librs_c_session *session);

//all SLBInst
struct SLBInst *
librs_getInstAll (librs_c_session *session);

struct SlaPolicy *
librs_getSlaPolicybyVCUUID (librs_c_session *session,
                            char *vc_uuid);

// L2 integration add two API
long
librs_getVdcIdByVCUUID (librs_c_session *session,
                        char *vc_uuid);

struct IPRule *
librs_getPerVdcRangeByVDCID (librs_c_session *session,
                             long vdc_id);

int
librs_createVdcPerfByVdcID (librs_c_session *session,
                            struct VDCPerf *vdc_perf);

struct SLBGw *
librs_getGwInfo (librs_c_session *session);

struct SLBSlb *
librs_getSlbInfo (librs_c_session *session);

struct _subnet_st *
librs_getSubnetByVdcId (librs_c_session *session,
                        const int iVdcId);

void
librs_freeSubnetByVdcId (struct _subnet_st *pSubnetHead);

struct _vnic_st *
librs_getVnicByInstUuid (librs_c_session *session,
                         const char *szInstUuid);

void
librs_freeVnicByInstUuid (struct _vnic_st *pHead);

// SPFOUR-79
int
librs_setSubnetPmIp (librs_c_session *session,
                     int iSubnetId,
                     char *szPmIp);

//todo: get cpu/memory loading data

#endif /* LIBRS_SLB_H_ */
