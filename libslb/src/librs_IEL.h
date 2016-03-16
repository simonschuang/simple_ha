/*
 * librs_IEL.h
 *
 *  Created on: 2014/12/3
 *      Author: Hogan
 */

#ifndef LIBRS_IEL_H_
#define LIBRS_IEL_H_

#include <IEL.h>
#include "librs_c_session.h"

// Return a list of all VC SLA with NULL tail
ielVcSla *
librs_getIelVcSlaAll (librs_c_session *session);

// VC SLA
ielVcSla *
librs_getIelVcSlaByUuid (librs_c_session *session,
                         char *vc_sla_uuid);

// All ISP bandwidth
ielIspBandwidth *
librs_getIelIspBandwidthAll (librs_c_session *session);

// ISP bandwidth by ID
ielIspBandwidth *
librs_getIelIspBandwidthById (librs_c_session *session,
                              int id);

long
librs_getLocalZoneID (librs_c_session *session);

// Return a single-link list of all Zone-VPN services
// The first parameter is a RS session
// The second parameter is to store the number of Zone-VPN services
ielVpn *
librs_getAllIelLocalZoneVpn (librs_c_session *session,
                             int *num_p);

int
librs_freeAllIelLocalZoneVpn (librs_c_session *session,
                              ielVpn *pIelVpnHead);

// Get a single-link list of Zone-VPN connections from RS
// The first parameter is a RS session
// The second parameter is to store the number of Zone-VPN connections
ielZoneVpnConnection *
librs_getAllIelZoneVpnConnection (librs_c_session *session,
                                  int *num_p);

int
librs_freeAllIelZoneVpnConnection (librs_c_session *session,
                                   ielZoneVpnConnection *zon_vpn_connection);


// Set the status of all Zone-VPN connections 
// The first parameter is a RS session
// The second parameter is a single-link list of Zone-VPN connections
// Return 0: success
// Return -1: fail
int
librs_setAllIelZoneVpnConnectionStatus (librs_c_session *session,
                                        ielZoneVpnConnection *zon_vpn_connection);

// Get a single-link list of Zone-VPN public interface
// The first parameter is a RS session
// The second parameter is to store the number of public interfaces
ielZoneVpnPublicInterface *
librs_getAllIelZoneVpnPublicInterface (librs_c_session *session,
                                       int *num_p);

int
librs_freeAllIelZoneVpnPublicInterface (librs_c_session *session,
                                        ielZoneVpnPublicInterface *pHead);
#endif /* LIBRS_IEL_H_ */
