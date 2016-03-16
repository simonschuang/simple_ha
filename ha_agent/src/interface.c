/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Read local machine's interface
 * Filename:    interface.c
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 *
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
//#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "interface.h"
#include "logger.h"

static int if_check(char *if_name, struct sockaddr *addr)
{
    struct ifreq ifr;
    struct in_addr addr_info;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_message(LOG_ERR, "cannot open socket!");
        return -1;
    }

    strncpy(ifr.ifr_name, if_name, strlen(if_name)+1);
    /* Check interface up or down */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        if ((ifr.ifr_flags & IFF_UP) && (ifr.ifr_flags & IFF_RUNNING)) {
            /* Get HW MAC address */
            if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
                if (!HWADDR_IS_ZERO(ifr.ifr_hwaddr.sa_data)) {
                    ifr.ifr_addr.sa_family = AF_INET;

                    /* Check netmask first, the netmask shouldn't be
                       specified as 255.255.255.255  */
                    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
                        addr_info = ((struct sockaddr_in *) &ifr.ifr_netmask)->sin_addr;
                        if ((((char *) &addr_info)[0] & 0xff) &&
                            (((char *) &addr_info)[1] & 0xff) &&
                            (((char *) &addr_info)[2] & 0xff) &&
                            (((char *) &addr_info)[3] & 0xff)) {
                            close(fd);
                            return -1;
                        }
                    }

                    /* Get IP address */
                    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
                        *addr = ifr.ifr_addr;
                        close(fd);
                        return 0;
                    }
                }
            }
        }
    }
    close(fd);
    return -1;
}

int bind_if_init(HA_AGENT *handle)
{
    struct if_nameindex *pif, *head;
    struct sockaddr addr;
    char *bind_if_name = ha_agent_if_name_get (handle);
    char hostname[LIBHA_HOSTNAME_LEN] = {0};
    
    gethostname(hostname, LIBHA_HOSTNAME_LEN);

    head = pif = if_nameindex();
    if (!pif) {
        return -1;
    }
    while (pif->if_index) {
        /* match interface name */
        if (bind_if_name) {
            log_message(LOG_INFO, "finding [%s], check [%s]", bind_if_name, pif->if_name);
            if (strcmp(bind_if_name, pif->if_name) == 0) {
                if (if_check(pif->if_name, &addr) < 0) {
                    if_freenameindex(head);
                    return -1;
                }
                ha_agent_if_addr_set (&(((struct sockaddr_in *) &addr)->sin_addr), handle);
                if (ha_agent_node_addr_set (&(((struct sockaddr_in *) &addr)->sin_addr), hostname, handle) < 0) {
                    log_message(LOG_INFO, "failed to bind interface: %s", pif->if_name);
                    if_freenameindex(head);
                    return -1;
                }
                log_message(LOG_INFO, "bind to interface: %s:%s", pif->if_name,
                inet_ntoa((((struct sockaddr_in *) &addr)->sin_addr)));
                if_freenameindex(head);
                return 0;
            } else {
                pif++;
                continue;
            }
        }

        /* no designated if */
        if ((strncmp(pif->if_name, "vir", 3) == 0) ||
            (strncmp(pif->if_name, "vif", 3) == 0) ||
            (strncmp(pif->if_name, "sit", 3) == 0) ||
            (strncmp(pif->if_name, "veth", 4) == 0)) {
            pif++;
            continue;
        }
 
        if (if_check(pif->if_name, &addr) < 0) {
            pif++;
            continue;
        }

        /* bind to first if */
        ha_agent_if_name_set (strdup(pif->if_name), handle);
        ha_agent_if_addr_set (&(((struct sockaddr_in *) &addr)->sin_addr), handle);
        if (ha_agent_node_addr_set (&(((struct sockaddr_in *) &addr)->sin_addr), hostname, handle) < 0) {
            log_message(LOG_INFO, "failed to bind interface: %s", pif->if_name);
            break;
        }
        log_message(LOG_INFO, "bind to interface: %s:%s", pif->if_name,
            inet_ntoa((((struct sockaddr_in *) &addr)->sin_addr)));
        if_freenameindex(head);
        return 0;
    }
    if_freenameindex(head);
    return -1;
}
