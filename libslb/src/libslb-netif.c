#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <limits.h>

#include "libslb-netif.h"

#define LIBSLB_PRIMARY_NETIF_PATTEN "br"
#define LIBSLB_SECONDARY_NETIF_PATTEN "eth"

char *
libslb_priv_netif_name_get (void)
{
    struct ifreq ifr;
    int fd = -1;
    int priority = INT_MAX;  // INT_MAX: default, 1: primary, 2: secondary
    int priority_tmp = INT_MAX;  // Temporary priority
    struct if_nameindex *pif = NULL, *head = NULL;
    char *target_if = NULL;  // The properest network interface name that found
    char *ret = NULL;  // Return value

    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        goto out;
    }

    head = if_nameindex();
    if (!head) {
        // Not found any network interface
        goto out;
    }

    for (pif = head; pif->if_index; pif++) {
        if (strncmp (pif->if_name,
                     LIBSLB_PRIMARY_NETIF_PATTEN,
                     strlen(LIBSLB_PRIMARY_NETIF_PATTEN)) == 0 &&
            priority > 1)
            priority_tmp = 1;
        else if (strncmp (pif->if_name,
                          LIBSLB_SECONDARY_NETIF_PATTEN,
                          strlen(LIBSLB_SECONDARY_NETIF_PATTEN)) == 0 &&
                 priority > 2)
            priority_tmp = 2;
        else {
            continue;
        }

        /* Check interface up or down */
        snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", pif->if_name);
        if (ioctl (fd, SIOCGIFFLAGS, &ifr) < 0) {
            continue;
        } else if (!(ifr.ifr_flags & IFF_UP) || !(ifr.ifr_flags & IFF_RUNNING)) {
            continue;
        }
        priority = priority_tmp;
        target_if = pif->if_name;

        if (priority == 1) {
            break;
        }
    }

    if (target_if)
        ret = strdup (target_if);

 out:
    target_if = NULL;

    if (head != NULL) {
        if_freenameindex (head);
    }

    if (fd != -1) {
        close (fd);
    }

    return ret;
}

int
libslb_netif_ip_get_by_name (const char *netif_name,
                             struct in_addr *addr)
{
    int fd = -1;
    struct ifreq ifr;
    int ret = -1;

    if (netif_name == NULL || strlen (netif_name) <= 0 || addr == NULL ) {
        return -1;
    }

    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy (ifr.ifr_name, netif_name);

    if (ioctl (fd, SIOCGIFADDR, &ifr) < 0) {
        goto libslb_netif_ip_get_by_name_finish;
    }

    *addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

    ret = 0;

 libslb_netif_ip_get_by_name_finish:

    if (fd != -1) {
        close (fd);
    }

    return ret;
}

int
libslb_netif_mac_get_by_name (const char *netif_name,
                              char *mac,
                              int size)
{
    int fd = -1;
    struct ifreq ifr;
    int ret = -1;

    if (netif_name == NULL || strlen (netif_name) <= 0 ||
        mac == NULL || size < ETH_ALEN) {
        return -1;
    }

    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strcpy (ifr.ifr_name, netif_name);

    if (ioctl (fd, SIOCGIFHWADDR, &ifr) < 0) {
        goto libslb_netif_mac_get_by_name_finish;
    }

    memcpy (mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    ret = 0;

 libslb_netif_mac_get_by_name_finish:

    if (fd != -1) {
        close (fd);
    }

    return ret;
}
