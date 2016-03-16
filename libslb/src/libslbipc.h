#ifndef __LIBSLBIPC_H_INCLUDED__
#define __LIBSLBIPC_SLB_H_INCLUDED__

#define SEND_TIMEOUT 1000  // 1000 ms

// _vc_uuid should be freed by caller
// Return 0: success
// Return -1: fail
int libslbipc_getVcUuidByVmUuid(char **_vc_uuid, const char *_vm_uuid);

// _cnIp points to an existing structure in_addr
// Return 0: success
// Return -1: fail
int libslbipc_getCnIpByVmUuid(struct in_addr *_cnIp, const char *_vm_uuid);

// _slbIp points to an existing structure in_addr
// Return 0: success
// Return -1: fail
int libslbipc_getSlbIpByVmUuid(struct in_addr *_slbIp, const char *_vm_uuid);

// _vmIp points to an existing structure in_addr
// Return 0: success
// Return -1: fail
int libslbipc_getVmIpByVmUuid(struct in_addr *_vmIp, const char *_vm_uuid);

// _vcIp points to an existing structure in_addr
// Return 0: success
// Return -1: fail
int libslbipc_getVcIpByVmUuid(struct in_addr *_vcIp, const char *_vm_uuid);

// _slbIp points to an existing structure in_addr
// Return 0: success
// Return -1: fail
int libslbipc_getSlbIpByVcUuid(struct in_addr *_slbIp, const char *_vc_uuid);

// _vcIp points to an existing structure in_addr
// Return 0: success
// Return -1: fail
int libslbipc_getVcIpByVcUuid(struct in_addr *_vcIp, const char *_vc_uuid);

#endif
