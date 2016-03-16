/*
 * librs_security.h
 *
 *  Created on: 2014/12/3
 *      Author: Hogan
 */

#ifndef LIBRS_SECURITY_H_
#define LIBRS_SECURITY_H_

#include <security.h>
#include "librs_c_session.h"

//get All Virtual Cluster information, include ip and fw id
vcList *
librs_getAllVCList (c_session *session);

//get node list (which include node ip address) by VDCUUID
ipList *
librs_getBroadcastIPListbyVDCUUID (c_session *session,
                                   char *vdcUUID);

//get VDC isolation table for Security Kernel by passing VDCUUID
vcInfo *
librs_getIpFilterTablebyVdcUUID (c_session *session,
                                 char *vdcUUID);

vcInfo *
librs_getIpFilterTablebyVdcID (c_session *session,
                               long vdc_id);

//get FW rules by fw policy id
fwRule *
librs_getFWPolicyRulebyFWID (c_session *session,
                             long fwID);

//get VC information from each node
vcList *
librs_getVCFWPolicyListbyNodeIP (c_session *session,
                                 char *nodeIP);

// ADD NEW API TO GET INST LIST
instInfo *
librs_getInstanceListbyNodeIP (c_session *session,
                               char *nodeIP);

//get all vdc information, include vdc_id, vdc0, vc, and inst struct data
vdcInfo *
librs_getAllVDCInfo (c_session *session,
                     long vdc0_option);	// vdc0_option is a bit vector to represent service node

//get service node information: node_id, service_name, ip address
serviceNodeInfo *
librs_getServiceNodeInfo (c_session *session,
                          long serviceNodeOption);

//get node list (which include node ip address) by VCUUID
ipList *
librs_getBroadcastIPListbyVCIP (c_session *session,
                                char *VCIP);

vdcInfo *
librs_getIpFilterTablebyNodeIP (c_session *session,
                                char *IP,
                                long vdc0_option);	// vdc0_option is a bit vector to represent service node

vmPWInfo *
librs_getVMPWInfobyVMMAC (c_session *session,
                          char *vmMac);

portInfo *
librs_getPortInfobyVCIP (c_session *session,
                         char *VCIP);
slbRuleInfo *
librs_getSLBRulebyCNIP (c_session *session,
                        char *CNIP);

//return if vm is LDAP ?
int
librs_getAuthTypebyMAC (c_session *session,
                        char *vmMac);

// appended by Jeff on 2011/10/06
instanceInfor_m1 *
librs_getInstanceListbyEMail (c_session *session,
                              char *EMail);

// ---------------------------for iii security api 2012/06/-- ---------------------------------------------

long
librs_getNodeIDbyHostName (c_session *session,
                           char *hostname);

vm_info_list *
librs_getVmInfo (c_session *session,
                 long long node_id);
int
librs_addSvmFilterIP (c_session *session,
                      iel_svm_filter_ip *filter_ip);

int
librs_addSvmInst (c_session *session,
                  iel_svm_inst *svn_inst);

int
librs_updateSvmInstbySvmSvStatus (c_session *session,
                                  int svm_sv_status,
                                  const char *uuid);

int
librs_updateSvmInstbyInspectStatus (c_session *session,
                                    int inspect_status,
                                    const char *uuid);

int
librs_updateInterFilterStatus (c_session *session,
                               const char *IPv4,
                               int status);

int
librs_updateIntraFilterstatus (c_session *session,
                               const char *IPv4,
                               const char *svm_uuid,
                               int status);

int
librs_deleteSvmInst (c_session *session,
                     const char *uuid);

int
librs_deleteOneSvmFilterIP (c_session *session,
                            const char *uuid);

int
librs_deleteSvmFilterIP (c_session *session,
                         const char *vm_uuid,
                         const char *svm_uuid);

iel_svm_inst *
librs_getAllSvmInst (c_session *session);

iel_vm_uuid_vcip *
librs_getIelVmUuidVcip (c_session *session,
                        long long nodeID);

vc_ip_list *
librs_getUniqueVcidByNodeid (c_session *session,
                             long long node_id);

int
librs_getVcidCount (c_session *session,
                    long long vc_id);

char *
librs_getFilterVmUuidbyVmPrivateIP (c_session *session,
                                    const char *IPv4,
                                    const char *svm_uuid);

vm_mac_list *
librs_getFilterVmMacbySvmIPVmIP (c_session *session,
                                 const char *svm_uuid,
                                 const char *vm_uuid);

node_host_name_list *
librs_getVmsCnHostNameByVCIP (c_session *session,
                              const char *vcIP);

int
librs_updateFilterStatusbyMac (c_session *session,
                               const char *mac,
                               int filter_status);

int
librs_updatevifbyUuid (c_session *session,
                       const char *uuid,
                       const char *vif_info);

int
librs_updateSvmFilterIpByVmUuid (c_session *session,
                                 const char *vm_uuid,
                                 const char *svm_uuid,
                                 long long node_id);

// ---------------------------common API 2012/07/09---------------------------------------------
pmNodeInfo *
librs_getAllPMInfo (c_session *session);

#endif /* LIBRS_SECURITY_H_ */
