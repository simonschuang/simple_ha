#ifndef __LIBSLB_NETIF_H__
#define __LIBSLB_NETIF_H__


/* Return pointer shall be freed by upper layer */
char *
libslb_priv_netif_name_get (void);

int
libslb_netif_ip_get_by_name (const char *netif_name,
                             struct in_addr *addr);

int
libslb_netif_mac_get_by_name (const char *netif_name,
                              char *mac,
                              int size);

#endif
