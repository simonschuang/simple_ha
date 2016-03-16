#include <stdio.h>
#include "librs_security.h"

//get All Virtual Cluster information, include ip and fw id
vcList *
librs_getAllVCList (c_session *session)
{
    return NULL;
}

//get node list (which include node ip address) by VDCUUID
ipList *
librs_getBroadcastIPListbyVDCUUID (c_session *session,
                                   char *vdcUUID)
{
    return NULL;
}

//get VDC isolation table for Security Kernel by passing VDCUUID
vcInfo *
librs_getIpFilterTablebyVdcUUID (c_session *session,
                                 char *vdcUUID)
{
    return NULL;
}

vcInfo *
librs_getIpFilterTablebyVdcID (c_session *session,
                               long vdc_id)
{
    return NULL;
}

//get FW rules by fw policy id
fwRule *
librs_getFWPolicyRulebyFWID (c_session *session,
                             long fwID)
{
    return NULL;
}

//get VC information from each node
vcList *
librs_getVCFWPolicyListbyNodeIP (c_session *session,
                                 char *nodeIP)
{
    return NULL;
}

// ADD NEW API TO GET INST LIST
instInfo *
librs_getInstanceListbyNodeIP (c_session *session,
                               char *nodeIP)
{
    return NULL;
}

//get all vdc information, include vdc_id, vdc0, vc, and inst struct data
vdcInfo *
librs_getAllVDCInfo (c_session *session,
                     long vdc0_option) // vdc0_option is a bit vector to represent service node
{
    return NULL;
}

//get service node information: node_id, service_name, ip address
serviceNodeInfo *
librs_getServiceNodeInfo (c_session *session,
                          long serviceNodeOption)
{
    return NULL;
}

//get node list (which include node ip address) by VCUUID
ipList *
librs_getBroadcastIPListbyVCIP (c_session *session,
                                char *VCIP)
{
    return NULL;
}

vdcInfo *
librs_getIpFilterTablebyNodeIP (c_session *session,
                                char* IP,
                                long vdc0_option)	// vdc0_option is a bit vector to represent service node
{
    return NULL;
}

vmPWInfo *
librs_getVMPWInfobyVMMAC (c_session *session,
                          char *vmMac)
{
    return NULL;
}

portInfo *
librs_getPortInfobyVCIP (c_session *session,
                         char *VCIP)
{
    return NULL;
}

slbRuleInfo *
librs_getSLBRulebyCNIP (c_session *session,
                        char *CNIP)
{
    return NULL;
}

//return if vm is LDAP ?
int
librs_getAuthTypebyMAC (c_session *session,
                        char* vmMac)
{
    return 0;
}

// appended by Jeff on 2011/10/06
instanceInfor_m1 *
librs_getInstanceListbyEMail (c_session *session,
                              char* EMail)
{
    return NULL;
}

// ---------------------------for iii security api 2012/06/-- ---------------------------------------------

long
librs_getNodeIDbyHostName (c_session *session,
                           char *hostname)
{
    return 0;
}

vm_info_list *
librs_getVmInfo (c_session *session,
                 long long node_id)
{
    return NULL;
}

int
librs_addSvmFilterIP (c_session *session,
                      iel_svm_filter_ip *filter_ip)
{
    return 0;
}

int
librs_addSvmInst (c_session *session,
                  iel_svm_inst *svn_inst)
{
    return 0;
}

int
librs_updateSvmInstbySvmSvStatus (c_session *session,
                                  int svm_sv_status,
                                  const char *uuid)
{
    return 0;
}

int
librs_updateSvmInstbyInspectStatus (c_session *session,
                                    int inspect_status,
                                    const char *uuid)
{
    return 0;

}

int
librs_updateInterFilterStatus (c_session *session,
                               const char *IPv4,
                               int status)
{
    return 0;
}

int
librs_updateIntraFilterstatus (c_session *session,
                               const char *IPv4,
                               const char *svm_uuid,
                               int status)
{
    return 0;
}

int
librs_deleteSvmInst (c_session *session,
                     const char *uuid)
{
    return 0;
}

int
librs_deleteOneSvmFilterIP (c_session *session,
                            const char *uuid)
{
    return 0;
}

int
librs_deleteSvmFilterIP (c_session *session,
                         const char *vm_uuid,
                         const char *svm_uuid)
{
    return 0;
}

iel_svm_inst *
librs_getAllSvmInst (c_session *session)
{
    return NULL;
}

iel_vm_uuid_vcip *
librs_getIelVmUuidVcip (c_session *session,
                        long long nodeID)
{
    return NULL;
}

vc_ip_list *
librs_getUniqueVcidByNodeid (c_session *session,
                             long long node_id)
{
    return NULL;
}

int
librs_getVcidCount (c_session *session,
                    long long vc_id);

char *
librs_getFilterVmUuidbyVmPrivateIP (c_session *session,
                                    const char *IPv4,
                                    const char *svm_uuid)
{
    return NULL;
}

vm_mac_list *
librs_getFilterVmMacbySvmIPVmIP (c_session *session,
                                 const char *svm_uuid,
                                 const char *vm_uuid)
{
    return NULL;
}

node_host_name_list *
librs_getVmsCnHostNameByVCIP (c_session *session,
                              const char *vcIP)
{
    return NULL;
}

int
librs_updateFilterStatusbyMac (c_session *session,
                               const char *mac,
                               int filter_status)
{
    return 0;
}

int
librs_updatevifbyUuid (c_session *session,
                       const char *uuid,
                       const char *vif_info)
{
    return 0;
}

int
librs_updateSvmFilterIpByVmUuid (c_session *session,
                                 const char *vm_uuid,
                                 const char *svm_uuid,
                                 long long node_id)
{
    return 0;
}

// ---------------------------common API 2012/07/09---------------------------------------------
pmNodeInfo *
librs_getAllPMInfo (c_session *session)
{
    return NULL;
}

