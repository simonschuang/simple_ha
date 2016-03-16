#include <stdio.h>
#include "librs_IEL.h"

// Return a list of all VC SLA with NULL tail
ielVcSla *
librs_getIelVcSlaAll (librs_c_session *session)
{
    c_session rs_session;
    ielVcSla *ielVcSla = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    ielVcSla = getIelVcSlaAll (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return ielVcSla;
}

// VC SLA
ielVcSla *
librs_getIelVcSlaByUuid (librs_c_session *session,
                         char *vc_sla_uuid)
{
    c_session rs_session;
    ielVcSla *ielVcSla = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    ielVcSla = getIelVcSlaByUuid (&rs_session,
                                  vc_sla_uuid);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return ielVcSla;
}

// All ISP bandwidth
ielIspBandwidth *
librs_getIelIspBandwidthAll (librs_c_session *session)
{
    c_session rs_session;
    ielIspBandwidth *isp = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    isp = getIelIspBandwidthAll (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return isp;
}

// ISP bandwidth by ID
ielIspBandwidth *
librs_getIelIspBandwidthById (librs_c_session *session,
                              int id)
{
    c_session rs_session;
    ielIspBandwidth *isp = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    isp = getIelIspBandwidthById (&rs_session,
                                  id);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return isp;
}

long
librs_getLocalZoneID (librs_c_session *session)
{
    c_session rs_session;
    long zoneId = 0;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return 0;
    }

    zoneId = getLocalZoneID (&rs_session);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return zoneId;
}

// Return a single-link list of all Zone-VPN services
// The first parameter is a RS session
// The second parameter is to store the number of Zone-VPN services
ielVpn *
librs_getAllIelLocalZoneVpn (librs_c_session *session,
                             int *num_p)
{
    c_session rs_session;
    ielVpn *vpn_list = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    vpn_list = getAllIelLocalZoneVpn (&rs_session,
                                      num_p);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return vpn_list;
}

int
librs_freeAllIelLocalZoneVpn (librs_c_session *session,
                              ielVpn *pIelVpnHead)
{
    return freeAllIelLocalZoneVpn (NULL,
                                   pIelVpnHead);
}

// Get a single-link list of Zone-VPN connections from RS
// The first parameter is a RS session
// The second parameter is to store the number of Zone-VPN connections
ielZoneVpnConnection *
librs_getAllIelZoneVpnConnection (librs_c_session *session,
                                  int *num_p)
{
    c_session rs_session;
    ielZoneVpnConnection *vpn_list = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    vpn_list = getAllIelZoneVpnConnection (&rs_session,
                                           num_p);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return vpn_list;
}

int
librs_freeAllIelZoneVpnConnection (librs_c_session *session,
                                   ielZoneVpnConnection *zon_vpn_connection)
{
    return freeAllIelZoneVpnConnection (NULL, zon_vpn_connection);
}


// Set the status of all Zone-VPN connections 
// The first parameter is a RS session
// The second parameter is a single-link list of Zone-VPN connections
// Return 0: success
// Return -1: fail
int
librs_setAllIelZoneVpnConnectionStatus (librs_c_session *session,
                                        ielZoneVpnConnection *zon_vpn_connection)
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

    setAllIelZoneVpnConnectionStatus (&rs_session,
                                      zon_vpn_connection);
    closeSession (&rs_session);

    /* Due to closeSession will commit really, so we copy the
       error_code and error_message after closeSession */
    librs_error_message_copy (session,
                              &rs_session);

    return session->error_code;
}

// Get a single-link list of Zone-VPN public interface
// The first parameter is a RS session
// The second parameter is to store the number of public interfaces
ielZoneVpnPublicInterface *
librs_getAllIelZoneVpnPublicInterface (librs_c_session *session,
                                       int *num_p)
{
    c_session rs_session;
    ielZoneVpnPublicInterface *interfaces = NULL;

    if (initSession (&rs_session,
                     session->host,
                     session->port,
                     session->account,
                     session->pwd) != 0) {
        librs_error_message_copy (session,
                                  &rs_session);
        return NULL;
    }

    interfaces = getAllIelZoneVpnPublicInterface (&rs_session,
                                                  num_p);
    librs_error_message_copy (session,
                              &rs_session);
    closeSession (&rs_session);

    return interfaces;
}

int
librs_freeAllIelZoneVpnPublicInterface (librs_c_session *session,
                                        ielZoneVpnPublicInterface *pHead)
{
    return freeAllIelZoneVpnPublicInterface (NULL,
                                             pHead);
}
