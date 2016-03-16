/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: HA daemon file
 * Filename:    ha-agent.c
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 *              Hogan Lee, <hogan_lee@itri.org.tw>
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <daemon.h>
#include <libha.h>
#include <libsock-ipc.h>
/* local include */
#include "ha-agent.h"
#include "logger.h"
#include "sockets.h"

#define LIBHA_SERVER_SEND_REPLY_TIMEOUT 10 /* 10ms */
#define LIBHA_CONFIG_FILE "/usr/cloudos/slb/ha_agent.conf"
#define LIBHA_CONFIG_FILE_GROUP_ID_TAG "group_id="

/* ------ ha_agent ------ */
enum HA_MSG_TYPES {
    HA_MSG_TYPE_BASE = 63,

    // multicast msg
    HA_MSG_TYPE_HELLO, /* struct msg_hello */
    HA_MSG_TYPE_ANNOUNCE_MASTER, /* struct msg_anc_master */

    // hear beat msg
    HA_MSG_TYPE_HB, /* struct msg_hb */

    // message
    HA_MSG_TYPE_MEMBER_LIST_UPDATE, /* struct msg_node_list */
    HA_MSG_TYPE_FAILOVER, /* struct msg_node_list */
    HA_MSG_TYPE_NODE_STOP, /* struct msg_node_list */
    HA_MSG_TYPE_TO_INIT, /* struct msg_header */
    HA_MSG_TYPE_CHECK, /* struct msg_header */
    HA_MSG_TYPE_ALIVE, /* struct msg_header */

    // service
    HA_MSG_TYPE_SERVICE_UPDATE, /* struct msg_sync_service */

    HA_MSG_TYPE_END
};
enum HA_AGENT_ACTIVE {
    HA_STATE_ACTIVE,
    HA_STATE_INACTIVE
};
struct ha_node {
    LIBHA_MEMBER info;
    enum HA_AGENT_ACTIVE state;
    GList *service_list; /* libha.h: LIBHA_REGISTER */
};
struct msg_header {
    short magic; /* HA_MSG_MAGIC */
    short version; /* HA_MSG_VERSION */
    enum HA_MSG_TYPES type;
};
#define HOSTNAME_LEN 30
#define KEY_LEN 4
#define hdr_magic    header.magic
#define hdr_version  header.version
#define hdr_type     header.type
struct msg_anc_master {
    struct msg_header header;
    char key[KEY_LEN];  // PRM IP address
    unsigned long long up_time;
};
struct master_data {
    struct timeval timedout;
    struct msg_anc_master msg;
    int mcast_recv_sock;
};
struct ha_hb_data {
    struct timeval timedout;
    unsigned long next_hb_msec;
    struct in_addr addr;
    struct timeval failover_timedout;
    int hb_sock;
};
struct ha_hb_thread_data {
    unsigned long interval_msec;    // 1000 = 1 second
    struct timeval l_senttime;
    struct in_addr target;
    char stop;
};
enum HA_AGENT_STATES {
    HA_STATE_INIT,
    HA_STATE_RUNNING,
    HA_STATE_SPLIT_BRAIN,
    HA_STATE_FAILOVER,
    HA_STATE_EXITING
};
struct ha_agent {
    LIBSOCK_IPC_SERVER *server_ipc;
    enum HA_AGENT_STATES state;
    unsigned long long up_time;
    char *bind_if_name;
    struct in_addr group_id;
    struct in_addr bind_if_addr;

    /* The first node shall be local */
    GList *ha_node_list; /* struct ha_node */

    struct master_data *master_data; /* struct master_data */
    struct ha_hb_data *hb_data;
    int msg_sock;

    /* thread data */
    unsigned long hb_ptid;
    struct ha_hb_thread_data hb_thread_data;

};
/* ------ end ha_agent ------ */

/* --- define messages format --- */

#define HA_ANC_MASTER_LEN    (sizeof(struct msg_anc_master))
struct msg_hello {
    struct msg_header header;
    char key[KEY_LEN];  // PRM IP address
    char hostname[LIBHA_HOSTNAME_LEN];  // localhost name
};

#define HA_ANC_MASTER_INTERVAL 15000000  // useconds 15s

struct msg_services {
    int total;
    LIBHA_REGISTER service[0];
};
struct ha_node_info {
    struct in_addr addr;
    char hostname[LIBHA_HOSTNAME_LEN];
    struct msg_services services;
};
enum HA_FAILOVER_TYPE {
    HA_FAILOVER_TYPE_NONE,
    HA_FAILOVER_TYPE_STOP,
    HA_FAILOVER_TYPE_FAIL
};
struct msg_node_list {
    struct msg_header header;
    int total;
    struct ha_node_info ha_info[0];
};
struct msg_sync_node_list {
    struct msg_header header;
    int total;
    struct ha_node_info ha_info[0];
};
struct msg_hb {
    struct msg_header header;
    unsigned long next_hb_msec;
};
#define HA_HB_MSG_LEN (sizeof(struct msg_hb))

struct msg_alive {
    struct msg_header header;
    int is_the_same_group;
};
struct msg_sync_service {
    struct msg_header header;
    struct msg_services services;
};

#define HA_FAILOVER_TIMEOUT 300000 // 0.3 seconds

/* --- end define messages format --- */

#define ADDR_EMPTY(addr)    ((((char *)addr)[0] == 0) &&    \
                             (((char *)addr)[1] == 0) &&    \
                             (((char *)addr)[2] == 0) &&    \
                             (((char *)addr)[3] == 0))
#define HA_MULTICAST_ADDR "224.0.0.82"
#define HA_MULTICAST_PORT "8849"
#define HA_INIT_TIMEOUT 1 // 1 second
#define HA_MESSAGE_PORT 15010
#define HA_HEARBEAT_PORT 15012

#define HA_MSG_MAGIC 24932
#define HA_MSG_VERSION 1
#define HA_MSG_MAX_LEN 512

#define HA_HB_INTERVAL_MS 3000 // 3 seconds

static int
ha_agent_service_change_send_to_daemon (struct ha_agent *handle,
                                        struct in_addr *addr,
                                        const char *hostname,
                                        enum LIBHA_STATE remote_state,
                                        enum LIBHA_SERVICE_OP op_state,
                                        LIBHA_REGISTER *service);

inline static struct ha_node *
local_ha_node (struct ha_agent *handle)
{
    GList *glist = g_list_first (handle->ha_node_list);
    if (glist) {
        return (struct ha_node *) glist->data;
    }
    return NULL;
}

inline static struct in_addr *
get_local_addr (struct ha_agent *handle)
{
    struct ha_node *node;
    GList *glist = g_list_first (handle->ha_node_list);
    if (glist) {
        node = (struct ha_node *) glist->data;
        return &node->info.addr;
    }
    return NULL;
}

inline static void
update_timer (struct timeval *timedout)
{
    gettimeofday (timedout, NULL);
}

inline static int
addrcmp (struct in_addr *addr1, struct in_addr *addr2)
{
    return memcmp (addr1, addr2, sizeof (struct in_addr));
}

static gint
ha_agent_service_find_func (gconstpointer a,
                            gconstpointer b)
{
    LIBHA_REGISTER *reg_msg_a, *reg_msg_b;

    reg_msg_a = (LIBHA_REGISTER *) a;
    reg_msg_b = (LIBHA_REGISTER *) b;

    return strcmp (reg_msg_a->s_name, reg_msg_b->s_name);
}

static gint
ha_agent_service_compare_func (gconstpointer a,
                               gconstpointer b,
                               gpointer user_data)
{
    LIBHA_REGISTER *reg_msg_a, *reg_msg_b;

    reg_msg_a = (LIBHA_REGISTER *) a;
    reg_msg_b = (LIBHA_REGISTER *) b;

    return strcmp (reg_msg_a->s_name, reg_msg_b->s_name);
}

static void
ha_agent_ha_nodes_info_dump (struct ha_agent *handle)
{
#if 1 /* Enable this line to dump all ha node information */
    struct ha_node *node;
    LIBHA_REGISTER *service;
    GList *node_list, *service_list;
    char ip[16];

    printf ("====== HA nodes information ======\n");

    for (node_list = g_list_first (handle->ha_node_list);
         node_list;
         node_list = g_list_next (node_list)) {
        node = (struct ha_node *) node_list->data;
        if (node == NULL) {
            continue;
        }

        inet_ntop (AF_INET, &(node->info.addr), ip, sizeof (ip));
        printf ("Node: %s\t addr:%s\t active:%s, service count:%d\n",
                (node->info.state == LIBHA_STATE_MASTER) ? "Master" : "Slave",
                ip,
                (node->state == HA_STATE_ACTIVE) ? "active" : "inactive",
                g_list_length (node->service_list));

        for (service_list = g_list_first (node->service_list);
             service_list;
             service_list = g_list_next (service_list)) {
            service = (LIBHA_REGISTER *) service_list->data;
            if (service == NULL) {
                continue;
            }

            printf ("\t Service name: %s\n", service->s_name);
        }
    }

    printf ("==================================\n");
#endif
}

static void
ha_agent_service_list_free (GList *glist, struct ha_node *node)
{
    if (glist == NULL) {
        return;
    }

    ha_agent_service_list_free (g_list_next (glist), node);
    if (glist->data) {
        free (glist->data);
    }
    node->service_list = g_list_delete_link (node->service_list, glist);
}

static struct ha_node *
ha_node_new (struct ha_agent *handle,
             struct ha_node_info *ha_info)
{
    struct ha_node *node;
    LIBHA_REGISTER *service;
    int i;

    node = (struct ha_node *) calloc (1, sizeof (struct ha_node));
    if (node) {
        node->info.addr = ha_info->addr;
        node->info.state = LIBHA_STATE_SLAVE;
        strcpy(node->info.hostname, ha_info->hostname);
        node->state = HA_STATE_ACTIVE;

        /* Create service list */
        for (i = 0; i < ha_info->services.total; i++) {
            service = (LIBHA_REGISTER *) calloc (1, sizeof (LIBHA_REGISTER));
            if (service == NULL) {
                log_message (LOG_ERR, "%s:%d: Out of memory",
                             __FILE__, __LINE__);
                goto ha_node_new_failed;
            }

            memcpy (service, &(ha_info->services.service[i]), sizeof (LIBHA_REGISTER));
            node->service_list =
                g_list_insert_sorted_with_data (node->service_list,
                                                service,
                                                ha_agent_service_compare_func,
                                                NULL);

            /* Send LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE message to daemon */
            ha_agent_service_change_send_to_daemon (handle,
                                                    &(node->info.addr),
                                                    node->info.hostname,
                                                    node->info.state,
                                                    LIBHA_SERVICE_OP_ADD,
                                                    service);
        }
    }
    return node;

 ha_node_new_failed:

    if (node) {
        ha_agent_service_list_free (node->service_list, node);
        free (node);
    }

    return NULL;
}

static gint
ha_node_find_by_addr_func (gconstpointer a, gconstpointer b)
{
    struct ha_node *node;
    struct in_addr *addr;

    node = (struct ha_node *)a;
    addr = (struct in_addr *)b;
    return (addrcmp(&node->info.addr, addr) != 0) ? -1 : 0;
}

struct ha_node *
get_ha_node_by_addr (GList *glist_head,
                     struct in_addr *addr)
{
    struct ha_node *node;
    GList *glist;
    glist = g_list_find_custom (glist_head, addr,
                                ha_node_find_by_addr_func);
    if (glist) {
        node = (struct ha_node *) glist->data;
        return node;
    }
    return NULL;
}

/*
 * return node index if exist, return -1 if failed
 * */
static int
ha_agent_ha_node_add (struct ha_agent *handle,
                      struct ha_node_info *ha_info,
                      int last_index)
{
    struct ha_node *node;
    GList *glist;

    glist = g_list_find_custom (handle->ha_node_list, &(ha_info->addr),
                                ha_node_find_by_addr_func);
    if (glist) {
        node = (struct ha_node *) glist->data;
        return g_list_position (handle->ha_node_list, glist);
    }

    node = ha_node_new (handle, ha_info);
    if (node) {
        if (last_index > -1) {
            last_index = last_index + 1;

            handle->ha_node_list = g_list_insert (handle->ha_node_list,
                                                  node, last_index);
        } else {
            handle->ha_node_list = g_list_append (handle->ha_node_list,
                                                  node);
        }

        return g_list_index (handle->ha_node_list, node);
    }
    return -1;
}

static int
msg_node_list_find (struct msg_node_list *list,
                    struct in_addr *addr,
                    struct ha_agent *handle)
{
    struct ha_node_info *ha_info_p;
    GList *glist;
    int count, offset;

    glist = g_list_find_custom (handle->ha_node_list, addr,
                                ha_node_find_by_addr_func);

    ha_info_p = list->ha_info;
    for (count = 0; count < list->total; count++) {
        if (addrcmp (&(ha_info_p->addr), addr) == 0) {
            return 1;
        }

        /* Calcuate the next ha_info position */
        offset = sizeof (struct ha_node_info) +
            (ha_info_p->services.total * sizeof (LIBHA_REGISTER));
        ha_info_p = (struct ha_node_info *) ((char *) ha_info_p + offset);
    }
    return 0;
}

static int
ha_agent_init (struct ha_agent *handle)
{
    struct hostent *hp;
    struct timeval tv;
    int count = 0;
    FILE *fp = NULL;
    char *line = NULL;
    size_t line_buf_len = 0;
    int line_len;
    unsigned long group_id = 0;

    handle->state = HA_STATE_INIT;
    gettimeofday (&tv, NULL);
    handle->up_time = tv.tv_sec * 1000000 + tv.tv_usec;

    /* Obtain the group id from configuration file */
    log_message (LOG_INFO, "Try to obtain the group id from %s", LIBHA_CONFIG_FILE);
    fp = fopen(LIBHA_CONFIG_FILE, "r");
    if (fp) {
        while (1) {
            line_len = getline (&line, &line_buf_len, fp);
            if (line_len < 0) {
                break;
            }

            if (strstr (line, LIBHA_CONFIG_FILE_GROUP_ID_TAG) == 0) {
                continue;
            }

            group_id = strtoul (line + strlen (LIBHA_CONFIG_FILE_GROUP_ID_TAG), NULL, 10);
            break;
        }

        fclose (fp);
        fp = NULL;
    } else {
        log_message (LOG_WARNING, "%s:%d: cannot obtain the group id from %s, because file not found",
                     __FILE__, __LINE__,
                     LIBHA_CONFIG_FILE);
    }

    if (line) {
        free (line);
        line = NULL;
    }

    if (group_id != 0) {
        log_message (LOG_INFO, "Obtain the group id from %s success, group ID %lu",
                     LIBHA_CONFIG_FILE,
                     group_id);
        ha_agent_key_set (handle, &group_id, sizeof (group_id));
        return 0;
    } else {
        log_message (LOG_WARNING, "%s:%d: cannot obtain the group id from %s",
                     __FILE__, __LINE__,
                     LIBHA_CONFIG_FILE);
    }

    log_message (LOG_INFO, "Try to resolve rs.ccma.itri");
    /* TODO: Fix block too long issue */
    do {
        hp = gethostbyname ("rs.ccma.itri");
        if (hp == NULL) {
            if (++count >= 10) {
                log_message (LOG_WARNING, "%s:%d: cannot resolve rs.ccma.itri %s",
                             __FILE__, __LINE__, strerror(h_errno));
#if 0 /* Test case: Enable this line to test the different hello key */
                struct in_addr inp;
                inet_aton ("192.168.1.1", &inp);
                ha_agent_key_set (handle, &inp, sizeof (struct in_addr));
#endif
                return 0;
            }
            usleep (100000); // 0.1 second
        }
    } while (!hp);
    log_message (LOG_INFO, "Resolve rs.ccma.itri success");

    ha_agent_key_set (handle, hp->h_addr_list[0], hp->h_length);

    return 0;
}

static void
ha_agent_ha_node_list_free (GList *glist, struct ha_agent *handle)
{
    struct ha_node *node;

    if (glist == NULL) {
        return;
    }

    ha_agent_ha_node_list_free (g_list_next (glist), handle);
    if (glist->data) {
        node = (struct ha_node *) glist->data;
        ha_agent_service_list_free (node->service_list, node);
        free (node);
    }
    handle->ha_node_list = g_list_delete_link (handle->ha_node_list, glist);
}

static void
master_data_free(struct master_data *data)
{
    if (data == NULL) {
        return;
    }

    close (data->mcast_recv_sock);
    free (data);
}

static void
hb_data_free(struct ha_hb_data *data)
{
    if (data == NULL) {
        return;
    }

    close (data->hb_sock);
    free (data);
}

static void
node_list_set_inactive (GList *glist)
{
    struct ha_node *node;
    if (glist) {
        node = (struct ha_node *) glist->data;
        node->state = HA_STATE_INACTIVE;
        node_list_set_inactive (g_list_next (glist));
    }
}

static int
ha_set_active (struct in_addr *addr, struct msg_alive *alive_msg, struct ha_agent *handle)
{
    struct ha_node *node = get_ha_node_by_addr (handle->ha_node_list, addr);
    char ip[16];

    if (!alive_msg->is_the_same_group) {
        /* This node isn't the same group with us, so ignore it */
        inet_ntop (AF_INET, addr, ip, sizeof (ip));
        log_message (LOG_ERR, "%s:%d: The node %s isn't the same group",
                     __FILE__, __LINE__, ip);
        return -1;
    }

    if (node) {
        node->state = HA_STATE_ACTIVE;
        return 0;
    }
    return -1;
}

static struct ha_node *
get_master_node (GList *glist)
{
    struct ha_node *node;

    while (glist) {
        node = (struct ha_node *) glist->data;
        if (node->info.state == LIBHA_STATE_MASTER && node->state == HA_STATE_ACTIVE) {
            return node;
        }
        glist = g_list_next (glist);
    }
    return NULL;
}

static struct ha_node *
master_ha_node (struct ha_agent *handle)
{
    struct ha_node *node;

    node = get_master_node (handle->ha_node_list);
    if (node) {
        return node;
    }

    node = local_ha_node (handle);
    if (node == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        return NULL;
    }

    log_message (LOG_WARNING, "Because no other master node, so the Local is master now");
    node->info.state = LIBHA_STATE_MASTER;

    return node;
}

/* ------ all messages ------ */
static int
ha_agent_service_node_list_count_get (struct ha_node *node)
{
    return g_list_length (node->service_list);
}

static int
ha_agent_msg_service_list_set (struct ha_node *node,
                               struct msg_services *services)
{
    LIBHA_REGISTER *service;
    GList *glist;
    int count = 0, total_service_count;

    total_service_count = ha_agent_service_node_list_count_get (node);
    if (total_service_count == 0) {
        return 0;
    }

    glist = g_list_first (node->service_list);
    while (glist) {
        service = (LIBHA_REGISTER *) glist->data;
        if (service == NULL) {
            log_message (LOG_ERR, "%s:%d: Service node doesn't have any data",
                         __FILE__, __LINE__);
            services->total = count;
            return -1;
        }
        memcpy (&(services->service[count]), service, sizeof (LIBHA_REGISTER));
        count++;
        glist = g_list_next (glist);
    }
    services->total = count;

    return 0;
}

static int
ha_agent_ha_node_list_count_get (GList *glist,
                                 enum HA_AGENT_ACTIVE flag,
                                 int *total_service_count)
{
    struct ha_node *node;
    GList *index;
    int count = 0;

    index = g_list_first (glist);
    while (index) {
        node = (struct ha_node *) index->data;
        if (node->state == flag) {
            if (total_service_count) {
                *total_service_count += ha_agent_service_node_list_count_get (node);
            }
            count++;
        }
        index = g_list_next (index);
    }
    return count;
}

static int
ha_agent_ha_node_list_set (GList *glist,
                           struct ha_node_info *ha_info,
                           enum HA_AGENT_ACTIVE flag)
{
    struct ha_node *node;
    struct ha_node_info *ha_info_p;
    GList *index;
    int count = 0, offset;

    ha_info_p = ha_info;

    index = g_list_first (glist);
    while (index) {
        node = (struct ha_node *) index->data;
        if (node->state == flag) {
            ha_info_p->addr = node->info.addr;
            strcpy(ha_info_p->hostname, node->info.hostname);
            ha_agent_msg_service_list_set (node, &(ha_info_p->services));

            /* Calcuate the next ha_info position */
            offset = sizeof (struct ha_node_info) +
                (ha_info_p->services.total * sizeof (LIBHA_REGISTER));
            ha_info_p = (struct ha_node_info *) ((char *) ha_info_p + offset);
            count++;
        }
        index = g_list_next (index);
    }

    return 0;
}

static void
ha_agent_header_msg_init (struct msg_header *hdr, enum HA_MSG_TYPES type)
{
    hdr->magic = HA_MSG_MAGIC;
    hdr->version = HA_MSG_VERSION;
    hdr->type = type;
}

static enum HA_MSG_TYPES
msg_type_get (char *msg)
{
    struct msg_header *header = (struct msg_header *)msg;

    if (header->magic == HA_MSG_MAGIC) {
        if (header->version == HA_MSG_VERSION) {
            return header->type;
        }
    }
    return 0;
}

static void
ha_agent_hello_msg_init (struct msg_hello *msg, struct ha_agent *handle)
{
    GList *glist;
    struct ha_node *node;

    memset (msg, 0, sizeof (struct msg_hello));
    ha_agent_header_msg_init (&msg->header, HA_MSG_TYPE_HELLO);
    glist = g_list_first (handle->ha_node_list);
    node = (struct ha_node *)glist->data;
    strcpy(msg->hostname, node->info.hostname);
    memcpy (msg->key, &handle->group_id, sizeof (struct in_addr));
}

static void *
ha_agent_hb_msg_create (unsigned long time)
{
    struct msg_hb *msg;
    msg = calloc (1, HA_HB_MSG_LEN);

    if (!msg) {
        return NULL;
    }

    ha_agent_header_msg_init (&(msg->header), HA_MSG_TYPE_HB);
    msg->next_hb_msec = time;
    return msg;
}

static void *
ha_agent_alive_msg_create (int is_the_same_group)
{
    struct msg_alive *msg;
    msg = calloc (1, sizeof (struct msg_alive));

    if (!msg) {
        return NULL;
    }

    ha_agent_header_msg_init (&(msg->header), HA_MSG_TYPE_ALIVE);
    msg->is_the_same_group = is_the_same_group;
    return msg;
}

static void *
ha_agent_service_update_msg_create (struct ha_agent *handle, int *len)
{
    struct msg_sync_service *msg;
    struct ha_node *this;
    int msg_len;
    int total_service_count;

    this = local_ha_node (handle);
    if (this == NULL) {
        return NULL;
    }

    total_service_count = ha_agent_service_node_list_count_get (this);
    msg_len = sizeof (struct msg_sync_service) +
        total_service_count * sizeof (LIBHA_REGISTER);

    msg = calloc (1, msg_len);
    if (!msg) {
        return NULL;
    }

    ha_agent_header_msg_init (&(msg->header), HA_MSG_TYPE_SERVICE_UPDATE);
    if (ha_agent_msg_service_list_set (this, &(msg->services)) != 0) {
        goto ha_agent_service_update_msg_create_failed;
    }

    *len = msg_len;

    return msg;

 ha_agent_service_update_msg_create_failed:

    if (msg) {
        free (msg);
    }

    return NULL;
}

static struct msg_node_list *
ha_agent_ha_node_list_msg_create (struct ha_agent *handle,
                                  enum HA_MSG_TYPES type,
                                  int *len)
{
    struct msg_node_list *msg = NULL;
    int total_ha_node_count = 0, total_service_count = 0;
    int msg_len;
    enum HA_AGENT_ACTIVE flag;

    if (type == HA_MSG_TYPE_MEMBER_LIST_UPDATE) {
        flag = HA_STATE_ACTIVE;
    } else if ((type == HA_MSG_TYPE_FAILOVER) ||
               (type == HA_MSG_TYPE_NODE_STOP)) {
        flag = HA_STATE_INACTIVE;
    } else {
        log_message (LOG_ERR, "%s:%d: Unknow message type %d",
                     __FILE__, __LINE__, type);
        return NULL;
    }

    total_ha_node_count =
        ha_agent_ha_node_list_count_get (g_list_first (handle->ha_node_list),
                                         flag,
                                         &total_service_count);
    if (total_ha_node_count == 0) {
        if (flag == HA_STATE_ACTIVE) {
            log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                         __FILE__, __LINE__);
        }
        return NULL;
    }

    /* Allocate all of the memory for storing HA and service
       information */
    msg_len = sizeof (struct msg_node_list) +
        total_ha_node_count * sizeof (struct ha_node_info) +
        total_service_count * sizeof (LIBHA_REGISTER);

    msg = (struct msg_node_list *) calloc (1, msg_len);
    if (!msg){
        log_message (LOG_ERR, "%s:%d: malloc failed at ha_agent_ha_node_list_msg_create",
                     __FILE__, __LINE__);
        return NULL;
    }
    ha_agent_header_msg_init ((struct msg_header *) &msg->header, type);
    msg->total = total_ha_node_count;
    ha_agent_ha_node_list_set (handle->ha_node_list, msg->ha_info, flag);
    *len = msg_len;

    return msg;
}

static void *
ha_agent_msg_create (struct ha_agent *handle, enum HA_MSG_TYPES type, int *len)
{
    void *msg = NULL;
    int i_type = type;
    switch (i_type) {
    case HA_MSG_TYPE_HELLO:
        msg = calloc (1, sizeof (struct msg_hello));
        if (msg) {
            ha_agent_hello_msg_init (msg, handle);
            *len = sizeof (struct msg_hello);
        }
        break;
    case HA_MSG_TYPE_HB:
        msg = ha_agent_hb_msg_create (HA_HB_INTERVAL_MS);
        if (msg) {
            *len = sizeof (struct msg_hb);
        }
        break;
    case HA_MSG_TYPE_MEMBER_LIST_UPDATE:
        msg = ha_agent_ha_node_list_msg_create (handle, HA_MSG_TYPE_MEMBER_LIST_UPDATE, len);
        break;
    case HA_MSG_TYPE_FAILOVER:
        msg = ha_agent_ha_node_list_msg_create (handle, HA_MSG_TYPE_FAILOVER, len);
        break;
    case HA_MSG_TYPE_NODE_STOP:
        msg = ha_agent_ha_node_list_msg_create (handle, HA_MSG_TYPE_NODE_STOP, len);
        break;
    case HA_MSG_TYPE_TO_INIT:
        msg = calloc (1, sizeof (struct msg_header));
        if (msg) {
            ha_agent_header_msg_init (msg, HA_MSG_TYPE_TO_INIT);
            *len = sizeof (struct msg_header);
        }
        break;
    case HA_MSG_TYPE_CHECK:
        msg = calloc (1, sizeof (struct msg_header));
        if (msg) {
            ha_agent_header_msg_init (msg, HA_MSG_TYPE_CHECK);
            *len = sizeof (struct msg_header);
        }
        break;
    case HA_MSG_TYPE_ALIVE:
        msg = ha_agent_alive_msg_create (TRUE);
        if (msg) {
            *len = sizeof (struct msg_alive);
        }
        break;
    case HA_MSG_TYPE_SERVICE_UPDATE:
        msg = ha_agent_service_update_msg_create (handle, len);
        break;
    default:
        log_message (LOG_ERR, "%s:%d: Unknown message type %d",
                     __FILE__, __LINE__, type);
        break;
    }
    return msg;
}
/* ------ end all messages ------ */

static void
sendtolist (int sock, void *msg, int len, GList *glist)
{
    struct ha_node *node;
    char ip[16];
    if (glist) {
        node = (struct ha_node *) glist->data;
        if (sendtoaddr (sock, msg, len, &node->info.addr, HA_MESSAGE_PORT) <= 0 &&
            len > 0) {
            inet_ntop (AF_INET, &(node->info.addr), ip, sizeof (ip));
            log_message (LOG_ERR, "%s:%d: Send to %s failed",
                         __FILE__, __LINE__, ip);
        }
        sendtolist (sock, msg, len, g_list_next (glist));
    }
}

/*
 * Find Master by muticast (224.0.0.82:8849)
 * Return 1 if found master
 * Return 0 if not found master
 * Return -1 if any error
 */
static int
ha_agent_mcast_send (struct ha_agent *handle)
{
    struct msg_hello *request;
    int sock, ret, len;

    log_message (LOG_INFO, "Searching master node...");
    request = ha_agent_msg_create (handle, HA_MSG_TYPE_HELLO ,&len);
    if (!request) {
        return -1;
    }

    /* Open socket */
    sock = open_socket_mcast_client (0, handle->bind_if_name,
        &handle->bind_if_addr);
    if (sock < 0) {
        return -1;
    }

    /* Send request */
    ret = (int) sendtomcast (sock, request, len,
                             HA_MULTICAST_ADDR,
                             atoi (HA_MULTICAST_PORT));
    if (ret < 0) {
        log_message (LOG_ERR, "%s:%d: sendtohost error: %s",
                     __FILE__, __LINE__, strerror(errno));
        close (sock);
        return -1;
    }

    free (request);
    close (sock);
    return 0;
}

/*
 * Detect split brain
 */
static int
ha_agent_multicast_send_by_master (struct ha_agent *handle)
{
    struct master_data *data;
    int sock, ret = 0;

    data = handle->master_data;
    /* Send request */
    sock = open_socket_mcast_client (0, handle->bind_if_name,
        &handle->bind_if_addr);
    if (sock < 0) {
        log_message (LOG_ERR, "%s:%d: cannot open mcast sock %s",
                     __FILE__, __LINE__, strerror(errno));
        return -1;
    }

    ret = (int) sendtomcast (sock, &data->msg, HA_ANC_MASTER_LEN,
                             HA_MULTICAST_ADDR, atoi (HA_MULTICAST_PORT));
    if (ret < 0) {
        log_message (LOG_ERR, "%s:%d: sendtohost error: %s",
                     __FILE__, __LINE__, strerror(errno));
        close (sock);
        return -1;
    }

    close (sock);

    return ret;
}

static int
ha_agent_alive_send (struct in_addr *addr, struct ha_agent *handle)
{
    struct msg_alive *msg;
    struct ha_node *node;
    int sock, len;
    char ip[16];

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_ALIVE, &len);
    if (!msg) {
        return -1;
    }

    node = get_ha_node_by_addr (handle->ha_node_list, addr);
    if (node) {
        msg->is_the_same_group = TRUE;
    } else {
        msg->is_the_same_group = FALSE;
    }

    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message(LOG_ERR, "%s:%d: new sock for reply alive failed",
                    __FILE__, __LINE__);
        return -1;
    }

    inet_ntop (AF_INET, addr, ip, sizeof (ip));
    log_message (LOG_INFO, "Send HA_MSG_TYPE_ALIVE to %s", ip);

    if (sendtoaddr (sock, msg, len, addr, HA_MESSAGE_PORT) <= 0) {
        log_message (LOG_ERR, "%s:%d: Send HA_MSG_TYPE_ALIVE to %s failed",
                     __FILE__, __LINE__, ip);
    }
    free (msg);
    close (sock);
    return 0;
}

static int
ha_agent_failover_send (struct ha_agent *handle)
{
    struct msg_header *msg;
    int sock, len;
    GList *glist;

    glist = g_list_first (handle->ha_node_list);
    if (glist == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        return -1;
    }
    glist = g_list_next (glist);
    if (glist == NULL) {
        /* No other HA node */
        return 0;
    }

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_CHECK, &len);
    if (!msg) {
        return -1;
    }
    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new sock for check failed",
                     __FILE__, __LINE__);
        free (msg);
        return -1;
    }

    log_message (LOG_INFO, "Send HA_MSG_TYPE_CHECK to other HA nodes");
    sendtolist (sock, msg, len, glist);

    free (msg);
    close (sock);
    handle->state = HA_STATE_FAILOVER;
    node_list_set_inactive (handle->ha_node_list->next);
    return 0;
}

static int
ha_agent_service_update_send (struct ha_agent *handle)
{
    struct msg_sync_service *msg = NULL;
    int sock, len;
    GList *glist;

    glist = g_list_first (handle->ha_node_list);
    if (glist == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        return -1;
    }
    glist = g_list_next (glist);
    if (glist == NULL) {
        /* No other HA node, it's normally */
        return 0;
    }

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_SERVICE_UPDATE, &len);
    if (msg == NULL) {
        log_message (LOG_ERR, "%s:%d: Out of memory",
                     __FILE__, __LINE__);
        return -1;
    }

    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new sock for check failed",
                     __FILE__, __LINE__);
        free (msg);
        return -1;
    }

    log_message (LOG_INFO, "Send HA_MSG_TYPE_SERVICE_UPDATE to other HA nodes");
    sendtolist (sock, msg, len, glist);

    free (msg);
    close (sock);

    return 0;
}

static int
ha_agent_node_stop_send_to_master (struct ha_agent *handle)
{
    struct ha_node *master = master_ha_node (handle);
    struct msg_node_list *msg;
    int sock, msg_len;
    char ip[16];

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_NODE_STOP, &msg_len);
    if (!msg) {
        return -1;
    }

    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new to master sock failed",
                     __FILE__, __LINE__);
        free (msg);
        return -1;
    }

    inet_ntop (AF_INET, &(master->info.addr), ip, sizeof (ip));
    log_message (LOG_INFO, "Send HA_MSG_TYPE_NODE_STOP to %s", ip);

    if (sendtoaddr (sock, msg, msg_len, &master->info.addr, HA_MESSAGE_PORT) <= 0) {
        log_message (LOG_ERR, "%s:%d: Send HA_MSG_TYPE_NODE_STOP to %s failed",
                     __FILE__, __LINE__, ip);
    }
    close (sock);
    free (msg);
    return 0;
}

static int
ha_agent_failover_send_to_master (struct ha_agent *handle)
{
    struct ha_node *master = master_ha_node (handle);
    struct msg_node_list *msg;
    int sock, msg_len;
    char ip[16];

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_FAILOVER, &msg_len);
    if (!msg) {
        return -1;
    }

    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new to master sock failed",
                     __FILE__, __LINE__);
        free (msg);
        return -1;
    }

    inet_ntop (AF_INET, &(master->info.addr), ip, sizeof (ip));
    log_message (LOG_INFO, "Send HA_MSG_TYPE_FAILOVER to master %s", ip);

    if (sendtoaddr (sock, msg, msg_len, &master->info.addr, HA_MESSAGE_PORT) <= 0) {
        log_message (LOG_ERR, "%s:%d: Send HA_MSG_TYPE_FAILOVER to %s failed",
                     __FILE__, __LINE__, ip);
    }
    close (sock);
    free (msg);
    return 0;
}

static int
ha_agent_service_change_send_to_daemon (struct ha_agent *handle,
                                        struct in_addr *addr,
                                        const char *hostname,
                                        enum LIBHA_STATE remote_state,
                                        enum LIBHA_SERVICE_OP op_state,
                                        LIBHA_REGISTER *service)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *ipc_msg = NULL;
    LIBHA_NOTIFY_REMOTE msg;
    struct ha_node *this;
    GList *list;
    enum LIBSOCK_IPC_RESULT ipc_ret;
    char ip[16];
    int ret = -1;

    this = local_ha_node (handle);
    if (this == NULL) {
        return -1;
    }

    list = g_list_find_custom (this->service_list,
                               service,
                               ha_agent_service_find_func);
    if (list == NULL) {
        /* Local doesn't have the same service, so ignore it */
        return 0;
    }

    ipc_ret = libsock_ipc_client_create (&client_ipc);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        log_message (LOG_ERR, "%s:%d: libsock_ipc_client_create failed, because %s",
                     __FILE__, __LINE__,
                     libsock_ipc_result_string_get (ipc_ret));
        return -1;
    }

    memset (&msg, 0, sizeof (LIBHA_NOTIFY_REMOTE));
    msg.op_state = op_state;
    msg.addr = *addr;
    strcpy(msg.hostname, hostname);
    msg.remote_state = remote_state;
    msg.local_state = this->info.state;

    ipc_ret = libsock_ipc_msg_create (LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE,
                                      (const char *) &msg,
                                      sizeof (LIBHA_NOTIFY_REMOTE),
                                      &ipc_msg);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        log_message (LOG_ERR, "%s:%d: libsock_ipc_msg_create failed, because %s",
                     __FILE__, __LINE__,
                     libsock_ipc_result_string_get (ipc_ret));
        goto ha_agent_service_change_send_to_daemon_finished;
    }

    /* Send IPC to daemon */
    ipc_ret = libsock_ipc_client_msg_send_with_no_reply (client_ipc,
                                                         service->s_name,
                                                         ipc_msg);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        log_message (LOG_ERR, "%s:%d: libsock_ipc_client_msg_send_with_no_reply failed, because %s",
                     __FILE__, __LINE__,
                     libsock_ipc_result_string_get (ipc_ret));
        goto ha_agent_service_change_send_to_daemon_finished;
    }

    inet_ntop (AF_INET, addr, ip, sizeof (ip));
    log_message (LOG_INFO, "Send LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE to service [%s], op [%s], addr [%s]",
                 service->s_name,
                 (op_state == LIBHA_SERVICE_OP_ADD) ? "add" : "delete",
                 ip,
                 addr);

    ret = 0;

 ha_agent_service_change_send_to_daemon_finished:

    if (ipc_msg) {
        libsock_ipc_msg_free (&ipc_msg);
    }

    if (client_ipc) {
        libsock_ipc_client_free (&client_ipc);
    }

    return ret;
}

static void
update_master_node (struct ha_agent *handle, struct ha_node *tmp)
{
    struct ha_node *node;
    GList *glist;

    glist = g_list_first (handle->ha_node_list);
    while (glist) {
        node = (struct ha_node *) glist->data;
        if (node->info.state == LIBHA_STATE_MASTER && node->state == HA_STATE_ACTIVE) {
            if (addrcmp (&node->info.addr, &tmp->info.addr) != 0) {
                node->info.state = LIBHA_STATE_SLAVE;
                tmp->info.state = LIBHA_STATE_MASTER;
            }
            return;
        }
        glist = g_list_next (glist);
    }
    tmp->info.state = LIBHA_STATE_MASTER;
}

static int
ha_agent_ha_node_add_list (struct msg_node_list *list, struct ha_agent *handle)
{
    struct ha_node_info *ha_info_p;
    struct ha_node *node, *master, *this;
    int count, index, offset, cur_count = 0;

    cur_count = g_list_length (handle->ha_node_list);

    master = get_master_node (g_list_first (handle->ha_node_list));
    ha_info_p = list->ha_info;
    index = -1;
    for (count = 0; count < list->total; count++) {
        index = ha_agent_ha_node_add (handle, ha_info_p, index);
        /* Calcuate the next ha_info position */
        offset = sizeof (struct ha_node_info) +
            (ha_info_p->services.total * sizeof (LIBHA_REGISTER));
        ha_info_p = (struct ha_node_info *) ((char *) ha_info_p + offset);
    }

    if (list->total >= 1) {
        ha_info_p = list->ha_info;

        /* The first node should be master */
        node = get_ha_node_by_addr (handle->ha_node_list, &(ha_info_p->addr));
        update_master_node (handle, node);
    }

    /*
     * Try to receive Hello response, but timeout happen,
     * then this condition will be triggered
     */
    if (cur_count == 1 && list->total >= 1) {
        this = local_ha_node (handle);
        if (this->info.state == LIBHA_STATE_SLAVE) {
            log_message (LOG_INFO, "Local is slave.");
        }

        /* Some services already registe, so send service
           update to all of the HA agent */
        ha_agent_service_update_send (handle);
    }

    return 0;
}

static int
del_ha_node (struct in_addr *addr, struct ha_agent *handle)
{
    GList *glist;
    struct ha_node *node;

    glist = g_list_find_custom (handle->ha_node_list, addr,
                                ha_node_find_by_addr_func);
    if (glist) {
        if (glist->data) {
            node = (struct ha_node *) glist->data;
            ha_agent_service_list_free (node->service_list, node);
            free (glist->data);
        }
        handle->ha_node_list = g_list_delete_link (handle->ha_node_list, glist);
    }
    return 0;
}


static int
ha_agent_ha_node_list_remove_handle (struct msg_node_list *list, struct ha_agent *handle)
{
    struct ha_node_info *ha_info_p;
    struct ha_node *this;
    struct msg_services *services;
    LIBHA_REGISTER *service;
    int node_index, service_index;
    int offset;

    this = local_ha_node (handle);

    ha_info_p = list->ha_info;
    for (node_index = 0; node_index < list->total; node_index++) {
        services = &(ha_info_p->services);
        for (service_index = 0; service_index < services->total; service_index++) {
            service = &(services->service[service_index]);
            if (g_list_find_custom (this->service_list,
                                    service,
                                    ha_agent_service_find_func) == NULL) {
                continue;
            }

            /* Send LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE to daemons */
            ha_agent_service_change_send_to_daemon (handle,
                                                    &(ha_info_p->addr),
                                                    ha_info_p->hostname,
                                                    LIBHA_STATE_SLAVE, /* Always slave */
                                                    LIBHA_SERVICE_OP_DEL,
                                                    service);
        }
        del_ha_node (&(ha_info_p->addr), handle);

        /* Calcuate the next ha_info position */
        offset = sizeof (struct ha_node_info) +
            (ha_info_p->services.total * sizeof (LIBHA_REGISTER));
        ha_info_p = (struct ha_node_info *) ((char *) ha_info_p + offset);
    }
    return 0;
}

/* remote nodes which are not in the list */
static int
del_ha_node_not_in_list (struct msg_node_list *list,
                         struct ha_agent *handle)
{
    struct ha_node *node, *this;
    LIBHA_REGISTER *service;
    GList *glist, *service_list;
    int ret;

    this = local_ha_node (handle);

    glist = g_list_first (handle->ha_node_list);
    node = (struct ha_node *) glist->data;
    ret = msg_node_list_find (list, &node->info.addr, handle);
    if (!ret) {
        log_message (LOG_ERR, "%s:%d: local node is not in the list!",
                     __FILE__, __LINE__);
        return -1;
    }
    glist = g_list_next (glist);

    while (glist) {
        node = (struct ha_node *) glist->data;
        ret = msg_node_list_find (list, &node->info.addr, handle);
        if (!ret) {
            if (glist->data) {
                for (service_list = g_list_first (node->service_list);
                     service_list;
                     service_list = g_list_next (service_list)) {
                    service = (LIBHA_REGISTER *) service_list->data;
                    if (service == NULL) {
                        continue;
                    }

                    if (g_list_find_custom (this->service_list,
                                            service,
                                            ha_agent_service_find_func) == NULL) {
                        continue;
                    }

                    /* Send LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE to daemons */
                    ha_agent_service_change_send_to_daemon (handle,
                                                            &(node->info.addr),
                                                            node->info.hostname,
                                                            node->info.state,
                                                            LIBHA_SERVICE_OP_DEL,
                                                            service);
                }

                ha_agent_service_list_free (node->service_list, node);
                free (glist->data);
            }
            handle->ha_node_list =
                g_list_delete_link (handle->ha_node_list, glist);
        }
        glist = g_list_next (glist);
    }
    return 0;
}

static int
ha_agent_ha_node_list_update (struct msg_node_list *list, struct ha_agent *handle)
{
    ha_agent_ha_node_add_list (list, handle);
    del_ha_node_not_in_list (list, handle);

    return 0;
}

static int
ha_node_list_fail (struct msg_node_list *list, struct ha_agent *handle)
{
    struct msg_node_list *msg;
    struct ha_node *this;
    int sock, len;
    GList *glist;

    /* remove failed node */
    ha_agent_ha_node_list_remove_handle (list, handle);

    /* check become master */
    if (get_master_node (handle->ha_node_list) == NULL) {
        this = local_ha_node (handle);
        this->info.state = LIBHA_STATE_MASTER;
        log_message (LOG_INFO, "Local is master");
    }

    glist = g_list_first (handle->ha_node_list);
    if (glist == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        return -1;
    }
    glist = g_list_next (glist);
    if (glist == NULL) {
        /* No other HA node */
        return 0;
    }

    /* sync new list to other slaves */
    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message(LOG_ERR, "%s:%d: new sock for check failed",
                    __FILE__, __LINE__);
        return -1;
    }

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_MEMBER_LIST_UPDATE, &len);
    if (msg) {
        log_message (LOG_INFO, "Send HA_MSG_TYPE_MEMBER_LIST_UPDATE to other HA nodes");
        sendtolist (sock, msg, len, glist);
        free (msg);
    }
    close (sock);
    return 0;
}

static int
ha_node_list_stop (struct msg_node_list *list, struct ha_agent *handle)
{
    struct msg_node_list *msg;
    struct ha_node *this;
    int sock, len;
    GList *glist;

    /* remove stop node */
    ha_agent_ha_node_list_remove_handle (list, handle);

    /* check become master */
    if (get_master_node (handle->ha_node_list) == NULL) {
        this = local_ha_node (handle);
        this->info.state = LIBHA_STATE_MASTER;
        log_message (LOG_INFO, "Local is master");
    }

    glist = g_list_first (handle->ha_node_list);
    if (glist == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        return -1;
    }
    glist = g_list_next (glist);
    if (glist == NULL) {
        /* No other HA node */
        return 0;
    }

    /* sync new list to other slaves */
    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new sock for check failed",
                     __FILE__, __LINE__);
        return -1;
    }
    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_MEMBER_LIST_UPDATE, &len);
    if (msg) {
        log_message (LOG_INFO, "Send HA_MSG_TYPE_MEMBER_LIST_UPDATE to other HA nodes");
        sendtolist (sock, msg, len, glist);
        free (msg);
    }
    close (sock);
    return 0;
}

static int
ha_agent_service_update (struct in_addr *addr,
                         struct msg_sync_service *msg,
                         struct ha_agent *handle)
{
    struct ha_node *node;
    LIBHA_REGISTER *service;
    GList *list, *next;
    gboolean is_found;
    int i;
    char ip[16];

    node = get_ha_node_by_addr (handle->ha_node_list, addr);
    if (node == NULL) {
        return -1;
    }

    inet_ntop (AF_INET, addr, ip, sizeof (ip));

    /* Is any service added */
    for (i = 0; i < msg->services.total; i++) {
        list = g_list_find_custom (node->service_list,
                                   &(msg->services.service[i]),
                                   ha_agent_service_find_func);
        if (list) {
            continue;
        }

        /* Not in list, so sdd a service to list */
        service = (LIBHA_REGISTER *) calloc (1, sizeof (LIBHA_REGISTER));
        if (service == NULL) {
            log_message (LOG_ERR, "%s:%d: Out of memory",
                         __FILE__, __LINE__);
            return -1;
        }

        memcpy (service, &(msg->services.service[i]), sizeof (LIBHA_REGISTER));
        node->service_list =
            g_list_insert_sorted_with_data (node->service_list,
                                            service,
                                            ha_agent_service_compare_func,
                                            NULL);

        log_message (LOG_INFO, "%s added a service [%s]",
                     ip, service->s_name);

        /* Send LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE message to daemon */
        ha_agent_service_change_send_to_daemon (handle,
                                                addr,
                                                node->info.hostname,
                                                node->info.state,
                                                LIBHA_SERVICE_OP_ADD,
                                                service);
    }

    /* Is any service deleted */
    list = g_list_first (node->service_list);
    while (list) {
        next = g_list_next (list);
        service = (LIBHA_REGISTER *) list->data;

        is_found = FALSE;
        for (i = 0; i < msg->services.total; i++) {
            if (strcmp (service->s_name,
                        msg->services.service[i].s_name) == 0) {
                is_found = TRUE;
                break;
            }
        }

        if (!is_found) {
            /* Send LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE message to daemon */
            ha_agent_service_change_send_to_daemon (handle,
                                                    addr,
                                                    node->info.hostname,
                                                    node->info.state,
                                                    LIBHA_SERVICE_OP_DEL,
                                                    service);

            log_message (LOG_INFO, "%s deleted a service [%s]",
                         ip, service->s_name);
            node->service_list = g_list_delete_link (node->service_list, list);
            free (service);
        }

        list = next;
    }

    return 0;
}

static int
recv_master_reply_timeout (struct ha_agent *handle, int timeout)
{
    struct timeval timedone;
    struct sockaddr_in from;
    struct in_addr *src_addr;
    struct ha_node *this;
    char reply[HA_MSG_MAX_LEN];
    int nbytes;

    src_addr = get_local_addr (handle);
    add2currenttime (&timedone, timeout);
    memset (reply, 0, HA_MSG_MAX_LEN);
    while ((nbytes = recvfromtimedone (handle->msg_sock, reply, HA_MSG_MAX_LEN,
                                       &from, timedone)) > 0) {
        /* filter local sent packets */
        if (addrcmp (&from.sin_addr, src_addr) != 0) {
            /* msg types */
            if (msg_type_get (reply) == HA_MSG_TYPE_MEMBER_LIST_UPDATE) {
                log_message (LOG_INFO, "Received HA_MSG_TYPE_MEMBER_LIST_UPDATE from master");
                /* process update member list message */
                ha_agent_ha_node_add_list ((struct msg_node_list *)reply, handle);

                this = local_ha_node (handle);
                if (g_list_length (this->service_list) != 0) {
                    /* Some services already registe, so send service
                       update to all of the HA agent */
                    ha_agent_service_update_send (handle);
                }

                /* For debugging */
                ha_agent_ha_nodes_info_dump (handle);

                return 1;
            }
        }
        log_message (LOG_DEBUG, "get something wrong");
        memset (reply, 0, HA_MSG_MAX_LEN);
    }
    /* no master found */
    return 0;
}

static struct master_data *
new_master_data (struct ha_agent *handle)
{
    struct master_data *data = calloc (1, sizeof (struct master_data));
    struct msg_anc_master *msg;
    if (!data) {
        log_message (LOG_ERR, "%s:%d: cannot malloc memory %s",
                     __FILE__, __LINE__, strerror (errno));
        return NULL;
    }
    msg = &data->msg;
    ha_agent_header_msg_init (&msg->header, HA_MSG_TYPE_ANNOUNCE_MASTER);
    memcpy (msg->key, &handle->group_id, sizeof(struct in_addr));
    msg->up_time = handle->up_time;

    data->timedout.tv_sec = 0;
    data->timedout.tv_usec = 0;
    data->mcast_recv_sock = open_socket_mcast_server (HA_MULTICAST_ADDR,
                                                      atoi (HA_MULTICAST_PORT),
                                                      handle->bind_if_addr);
    if (data->mcast_recv_sock < 0) {
        log_message(LOG_ERR, "%s:%d: initial mcast socket failed",
                    __FILE__, __LINE__);
        free (data);
        return NULL;
    }
    return data;
}

static int
check_timeout (struct timeval timedout,
               unsigned long long interval,
               struct timeval *time_diff)
{
    struct timeval timeoutp;
    int sec = interval/MILLION;
    unsigned long usec = interval%MILLION;

    gettimeofday (&timeoutp, NULL);
    timeoutp.tv_sec = timeoutp.tv_sec - timedout.tv_sec;
    timeoutp.tv_usec = timeoutp.tv_usec - timedout.tv_usec;

    if (timeoutp.tv_usec >= MILLION) {
        timeoutp.tv_sec++;
        timeoutp.tv_usec -= MILLION;
    }
    if (timeoutp.tv_usec < 0) {
        timeoutp.tv_sec--;
        timeoutp.tv_usec += MILLION;
    }
    if (time_diff) {
        time_diff->tv_sec = timeoutp.tv_sec;
        time_diff->tv_usec = timeoutp.tv_usec;
    }
    if ((timeoutp.tv_sec > sec) ||
        ((timeoutp.tv_sec == sec) && (timeoutp.tv_usec >= usec))) {
        errno = ETIME;
        return -1;
    }
    return 0;
}

static int
msg_anc_handler (struct ha_agent *handle,
                 struct msg_anc_master *msg,
                 struct in_addr *from)
{
    char ip[16];

    if (memcmp (msg->key, &handle->group_id, KEY_LEN) != 0) {
        return 0;
    }

    inet_ntop (AF_INET, from, ip, sizeof (ip));
    log_message (LOG_INFO, "Received HA_MSG_TYPE_ANNOUNCE_MASTER from %s, but local is master", ip);

    if (msg->up_time <= handle->up_time) {
        handle->state = HA_STATE_SPLIT_BRAIN;
        log_message (LOG_ERR, "%s:%d: Split brain, %s is real master",
                     __FILE__, __LINE__, ip);
        return -1;
    }

    log_message (LOG_WARNING, "Found another master node, but the local is real master");

    return 0;
}

static int
msg_hello_handler (struct ha_agent *handle,
                   struct msg_hello *hello_msg,
                   struct in_addr *from)
{
    struct msg_node_list *msg;
    struct ha_node_info ha_info;
    GList *glist;
    int sock, len;
    char ip[16];

    if (memcmp (hello_msg->key, &handle->group_id, KEY_LEN) != 0) {
        return 0;
    }

    inet_ntop (AF_INET, from, ip, sizeof (ip));
    log_message (LOG_INFO, "Received HA_MSG_TYPE_HELLO, from: %s, send reply", ip);

    memset (&ha_info, 0, sizeof (struct ha_node_info));
    ha_info.addr = *from;
    strcpy(ha_info.hostname, hello_msg->hostname);
    if (ha_agent_ha_node_add (handle, &ha_info, -1) <= 0) {
        return 0;
    }

    if ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new sock for hello msg failed",
                     __FILE__, __LINE__);
        return -1;
    }

    glist = g_list_first (handle->ha_node_list);
    if (glist == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        close (sock);
        return -1;
    }
    glist = g_list_next (glist);
    if (glist == NULL) {
        close (sock);
        /* No other HA node */
        return 0;
    }

    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_MEMBER_LIST_UPDATE, &len);
    if (!msg) {
        close (sock);
        return -1;
    }

    log_message (LOG_INFO, "Send HA_MSG_TYPE_MEMBER_LIST_UPDATE to other HA nodes");
    sendtolist (sock, msg, len, glist);

    free (msg);
    close (sock);

    /* For debugging */
    ha_agent_ha_nodes_info_dump (handle);

    return 0;
}

static int
master_multicast_recv (struct ha_agent *handle)
{
    char recv_buff[HA_MSG_MAX_LEN];
    struct sockaddr_in from;
    struct master_data *data;
    enum HA_MSG_TYPES type;
    struct in_addr *addr;
    unsigned int len;
    int recv_len;

    len = sizeof (struct sockaddr_in);
    data = handle->master_data;
    memset (recv_buff, 0, HA_MSG_MAX_LEN);
    /* non-block mode */
    if ((recv_len = recvfrom (data->mcast_recv_sock, recv_buff,
                              HA_MSG_MAX_LEN, MSG_DONTWAIT,
                              (struct sockaddr *) &from, &len)) < 0) {
        if (errno == EAGAIN) {
            return 0;
        }
        log_message (LOG_ERR, "%s:%d: recvfrom() failed because %s",
                     __FILE__, __LINE__, strerror (errno));
        return -1;
    }

    if (recv_len > 0) {
        addr = get_local_addr (handle);
        if (addrcmp (&from.sin_addr, addr) != 0) {
            type = msg_type_get (recv_buff);
            if (type == HA_MSG_TYPE_ANNOUNCE_MASTER) {
                return msg_anc_handler (handle,
                                        (struct msg_anc_master *)recv_buff,
                                        (struct in_addr *)&from.sin_addr);

            } else if (type == HA_MSG_TYPE_HELLO) {
                return msg_hello_handler(handle,
                                         (struct msg_hello *)recv_buff,
                                         (struct in_addr *)&from.sin_addr);
            }
        }
    }
    return 0;
}

static struct ha_node *
get_hb_sender_node (struct ha_agent *handle)
{
    struct ha_node *node;
    GList *glist;

    glist = g_list_last (handle->ha_node_list);
    while (glist && glist != handle->ha_node_list) {
        node = (struct ha_node *)glist->data;
        if (node->state == HA_STATE_ACTIVE) {
            return node;
        }
        glist = g_list_previous (glist);
    }
    return NULL;
}

static struct ha_node *
get_hb_receiver_node (struct ha_agent *handle)
{
    GList *glist;

    glist = g_list_first (handle->ha_node_list);
    if (glist) {
        /* The first node is local, we shall ignore it and check next
           node */
        glist = g_list_next (glist);
        if (glist == NULL) {
            return NULL;
        }

        /* Always send to next node, even the node state is inactive */
        return (struct ha_node *) glist->data;
    }
    return NULL;
}

static struct ha_hb_data *
new_hb_data (struct in_addr *addr, struct ha_agent *handle)
{
    struct ha_hb_data *data = calloc (1, sizeof (struct ha_hb_data));
    char ip[16];

    if (data == NULL) {
        return NULL;
    }

    data->addr = *addr;
    data->next_hb_msec = HA_HB_INTERVAL_MS;
    data->hb_sock = open_socket_udp (HA_HEARBEAT_PORT, handle->bind_if_name,
        &handle->bind_if_addr);
    if (data->hb_sock < 0) {
        free (data);
        return NULL;
    }
    update_timer (&data->timedout);

    inet_ntop (AF_INET, addr, ip, sizeof (ip));
    log_message (LOG_INFO, "Prepare to receive HA_MSG_TYPE_HB from %s", ip);

    return data;
}

static enum HA_FAILOVER_TYPE
do_hb_socket_actions (struct ha_hb_data *data)
{
    char recv_buff[HA_MSG_MAX_LEN];
    unsigned long long timeu;
    struct timeval time_diff;
    struct sockaddr_in from;
    struct msg_hb *msg;
    unsigned int len;
    int recv_len;
    char ip[16];

    memset (recv_buff, 0, HA_MSG_MAX_LEN);
    len = sizeof (struct sockaddr_in);
    /* receive heart beat */
    if ((recv_len = recvfrom (data->hb_sock, recv_buff, HA_MSG_MAX_LEN,
                              MSG_DONTWAIT, (struct sockaddr *) &from,
                              &len)) < 0) {
        if (errno != EAGAIN) {
            log_message (LOG_ERR, "%s:%d: recvfrom() failed because %s",
                         __FILE__, __LINE__, strerror (errno));
            return HA_FAILOVER_TYPE_NONE;
        }
    }
    if (recv_len > 0 &&
        addrcmp (&data->addr, (struct in_addr *) &from.sin_addr) == 0 &&
        msg_type_get (recv_buff) == HA_MSG_TYPE_HB) {
        msg = (struct msg_hb *) recv_buff;
        update_timer (&data->timedout);
        data->next_hb_msec = msg->next_hb_msec;

        if (msg->next_hb_msec != 0) {
            return HA_FAILOVER_TYPE_NONE;
        }
        /* Otherwise, this node is stopped normally */
    }

    inet_ntop (AF_INET, &(data->addr), ip, sizeof (ip));

    /* check heart beat timeout */
    if (data->next_hb_msec != 0) {
        timeu = (unsigned long long) data->next_hb_msec * 1000;
        if (check_timeout (data->timedout, timeu, &time_diff)) {
            /* timeout! */
            log_message (LOG_ERR, "%s:%d: heart beat timeout from %s, diff time is %d.%d seconds",
                         __FILE__, __LINE__, ip,
                         time_diff.tv_sec, time_diff.tv_usec);
            update_timer (&data->timedout);
            return HA_FAILOVER_TYPE_FAIL;
        }
    } else {
        /* node stop */
        log_message (LOG_INFO, "HA node %s stop", ip);
        return HA_FAILOVER_TYPE_STOP;
    }

    return HA_FAILOVER_TYPE_NONE;
}

static int
ha_hb_thread_is_hold (struct ha_agent *handle) {
    return (handle->hb_thread_data.interval_msec == 0) ? 1 : 0;
}

static void
ha_hb_thread_hold (struct ha_agent *handle)
{
    struct ha_hb_thread_data *data = &handle->hb_thread_data;
    data->interval_msec = 0;
    memset (&data->target, 0, sizeof (struct in_addr));
    log_message (LOG_INFO, "Heart beat thread hold");
}

static void
ha_hb_thread_resume (struct ha_agent *handle, struct in_addr addr)
{
    struct ha_hb_thread_data *data = &handle->hb_thread_data;
    char ip[16];

    update_timer (&data->l_senttime);
    data->interval_msec = HA_HB_INTERVAL_MS;
    data->target = addr;
    inet_ntop (AF_INET, &addr, ip, sizeof (ip));
    log_message (LOG_INFO, "Heart beat thread resume, the target is %s", ip);
}

static int
action_to_init (struct ha_agent *handle)
{
    struct ha_node *this, *node;
    GList *service_list, *node_list;
    LIBHA_REGISTER *service;

    this = local_ha_node (handle);

    /* hold heart beat thread */
    if (!ha_hb_thread_is_hold (handle)) {
        ha_hb_thread_hold (handle);
    }

    handle->state = HA_STATE_INIT;

    for (service_list = g_list_first (this->service_list);
         service_list;
         service_list = g_list_next (service_list)) {
        service = (LIBHA_REGISTER *) service_list->data;
        if (service == NULL) {
            continue;
        }

        for (node_list = g_list_next (handle->ha_node_list);
             node_list;
             node_list = g_list_next (node_list)) {
            node = (struct ha_node *) node_list->data;
            if (node == NULL) {
                continue;
            }

            if (g_list_find_custom (node->service_list,
                                    service,
                                    ha_agent_service_find_func) == NULL) {
                continue;
            }

            /* This node has the same daemon, so send
               LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE to daemon */
            ha_agent_service_change_send_to_daemon (handle,
                                                    &(node->info.addr),
                                                    node->info.hostname,
                                                    node->info.state,
                                                    LIBHA_SERVICE_OP_DEL,
                                                    service);
        }
    }

    /* clean node list */
    ha_agent_ha_node_list_free (g_list_next (handle->ha_node_list), handle);
    handle->ha_node_list->next = NULL;

    this->info.state = LIBHA_STATE_SLAVE;

    return 1;
}

static int
msg_socket_actions (struct ha_agent *handle)
{
    char recv_buff[HA_MSG_MAX_LEN];
    struct sockaddr_in from;
    unsigned int len;
    int recv_len, ret, type;
    char ip[16];

    ret = 0;
    memset (recv_buff, 0, HA_MSG_MAX_LEN);
    len = sizeof (struct sockaddr_in);
    /* non-block mode */
    if ((recv_len = recvfrom (handle->msg_sock, recv_buff,
                              HA_MSG_MAX_LEN, MSG_DONTWAIT,
                              (struct sockaddr *) &from,
                              &len)) < 0) {
        if (errno == EAGAIN) {
            return 0;
        }
        log_message (LOG_ERR, "%s:%d: recvfrom() failed because %s",
                     __FILE__, __LINE__, strerror (errno));
        return -1;
    }

    inet_ntop (AF_INET, &(from.sin_addr), ip, sizeof (ip));

    if (recv_len > 0) {
        /* msg types */
        type = (int) msg_type_get (recv_buff);
        switch (type) {
        case HA_MSG_TYPE_CHECK:
            ret = ha_agent_alive_send ((struct in_addr *) &from.sin_addr, handle);
            log_message (LOG_INFO,
                         "Received HA_MSG_TYPE_CHECK request from %s and handle it %s",
                         ip, (ret == 0) ? "success" : "failed");
            break;
        case HA_MSG_TYPE_ALIVE:
            ret = ha_set_active ((struct in_addr *) &from.sin_addr,
                                 (struct msg_alive *) recv_buff,
                                 handle);
            log_message (LOG_INFO,
                         "Received HA_MSG_TYPE_ALIVE response from %s and handle it %s",
                         ip, (ret == 0) ? "success" : "failed");
            break;
        case HA_MSG_TYPE_TO_INIT:
            ret = action_to_init (handle);
            log_message (LOG_INFO,
                         "Received HA_MSG_TYPE_TO_INIT request from %s and handle it %s",
                         ip, (ret == 0) ? "success" : "failed");

            /* For debugging */
            ha_agent_ha_nodes_info_dump (handle);
            break;
        case HA_MSG_TYPE_MEMBER_LIST_UPDATE:
            ret = ha_agent_ha_node_list_update ((struct msg_node_list *) recv_buff,
                                                handle);
            log_message(LOG_INFO,
                        "Received HA_MSG_TYPE_MEMBER_LIST_UPDATE request from %s and handle it %s",
                        ip, (ret == 0) ? "success" : "failed");

            /* For debugging */
            ha_agent_ha_nodes_info_dump (handle);
            break;
        case HA_MSG_TYPE_FAILOVER:
            ret = ha_node_list_fail ((struct msg_node_list *) recv_buff,
                                     handle);
            log_message (LOG_INFO,
                         "Received HA_MSG_TYPE_FAILOVER: request from %s and handle it %s",
                         ip, (ret == 0) ? "success" : "failed");

            /* For debugging */
            ha_agent_ha_nodes_info_dump (handle);
            break;
        case HA_MSG_TYPE_NODE_STOP:
            ret = ha_node_list_stop ((struct msg_node_list *) recv_buff,
                                     handle);
            log_message (LOG_INFO,
                         "Received HA_MSG_TYPE_NODE_STOP request from %s and handle it %s",
                         ip, (ret == 0) ? "success" : "failed");

            /* For debugging */
            ha_agent_ha_nodes_info_dump (handle);
            break;
        case HA_MSG_TYPE_SERVICE_UPDATE:
            ret = ha_agent_service_update ((struct in_addr *) &from.sin_addr,
                                           (struct msg_sync_service *) recv_buff,
                                           handle);
            log_message (LOG_INFO,
                         "Received HA_MSG_TYPE_SERVICE_UPDATE request from %s and handle it %s",
                         ip, (ret == 0) ? "success" : "failed");

            /* For debugging */
            ha_agent_ha_nodes_info_dump (handle);
            break;
        default:
            log_message (LOG_ERR, "%s:%d: Received Unknown message from %s",
                         __FILE__, __LINE__, ip);
            ret = -1;
            break;
        }

    }
    return ret;
}

static void
free_hb_data (struct ha_agent *handle)
{
    struct ha_hb_data *data;

    data = handle->hb_data;
    if (data) {
        close (data->hb_sock);
        free (data);
        handle->hb_data = NULL;
    }
}

static int
hb_socket_actions (struct ha_agent *handle)
{
    struct ha_node *hb_sender = get_hb_sender_node (handle);
    struct ha_node *hb_receiver = get_hb_receiver_node (handle);
    struct ha_hb_data *data;
    enum HA_FAILOVER_TYPE ret;
    char ip[16];

    if (hb_receiver) {
        if (addrcmp (&hb_receiver->info.addr, &handle->hb_thread_data.target) != 0) {
            if (!ha_hb_thread_is_hold (handle)) {
                /* hold heart beat thread */
                ha_hb_thread_hold (handle);
            }
            ha_hb_thread_resume (handle, hb_receiver->info.addr);
        }
    } else {
        if (!ha_hb_thread_is_hold (handle)) {
            ha_hb_thread_hold (handle);
        }
    }

    if (hb_sender){
        data = handle->hb_data;
        if (!handle->hb_data) {
            log_message (LOG_DEBUG, "allocate hb data");
            handle->hb_data = new_hb_data (&hb_sender->info.addr, handle);
            if (!handle->hb_data) {
                log_message (LOG_ERR, "%s:%d: cannot malloc memory %s",
                             __FILE__, __LINE__, strerror (errno));
                return -1;
            }
        } else if (addrcmp (&hb_sender->info.addr, &data->addr) != 0){
            /* switch hb_sender */
            data->addr = hb_sender->info.addr;
            update_timer (&data->timedout);
            data->next_hb_msec = HA_HB_INTERVAL_MS;
            inet_ntop (AF_INET, &(data->addr), ip, sizeof (ip));
            log_message (LOG_INFO, "Prepare to receive HA_MSG_TYPE_HB from %s", ip);
        }
    } else {
        if (handle->hb_data) {
            free_hb_data (handle);
        }
        return 0;
    }

    data = handle->hb_data;
    ret = do_hb_socket_actions (data);
    if (ret == HA_FAILOVER_TYPE_FAIL) {
        if (ha_agent_failover_send (handle) == 0) {
            update_timer (&data->failover_timedout);
            return 0;
        }
    } else if (ret == HA_FAILOVER_TYPE_STOP) {
        // sender node stopped
        hb_sender->state = HA_STATE_INACTIVE;
        ha_agent_node_stop_send_to_master (handle);
    }

    return 0;
}

static int
mcast_socket_actions (struct ha_agent *handle)
{
    struct ha_node *this = local_ha_node (handle);
    struct master_data *data;
    int ret;

    if (this->info.state != LIBHA_STATE_MASTER) {
        if (handle->master_data) {
            free (handle->master_data);
            handle->master_data = NULL;
            log_message (LOG_INFO, "Stop to send HA_MSG_TYPE_ANNOUNCE_MASTER");
        }
        return 0;
    }
    if (!handle->master_data) {
        handle->master_data = new_master_data (handle);
        if (!handle->master_data) {
            log_message (LOG_ERR, "%s:%d: cannot malloc memory %s",
                         __FILE__, __LINE__, strerror(errno));
            return -1;
        }

        log_message (LOG_INFO, "Start to send HA_MSG_TYPE_ANNOUNCE_MASTER");
    }

    data = handle->master_data;
    if (check_timeout (data->timedout, HA_ANC_MASTER_INTERVAL, NULL)) {
        ret = ha_agent_multicast_send_by_master (handle);
        if (ret < 0) {
            log_message (LOG_ERR, "%s:%d: ha_agent_multicast_send_by_master failed",
                         __FILE__, __LINE__);
        }
        update_timer (&data->timedout);
    }

    ret = master_multicast_recv (handle);
    if (ret < 0) {
        log_message (LOG_ERR, "%s:%d: master_multicast_recv error",
                     __FILE__, __LINE__);
    }
    return ret;
}

static int
ha_state_action_failover (struct ha_agent *handle)
{
    struct ha_hb_data *data = (struct ha_hb_data *) handle->hb_data;
    int total_ha_node_count;

    if (!data) {
        return -1;
    }
    /* check msg */
    msg_socket_actions (handle);

    /* check timeout */
    if (check_timeout (data->failover_timedout, HA_FAILOVER_TIMEOUT, NULL)) {
        total_ha_node_count =
            ha_agent_ha_node_list_count_get (g_list_first (handle->ha_node_list),
                                             HA_STATE_INACTIVE,
                                             NULL);
        if (total_ha_node_count != 0) {
            /* Some HA node doesn't respond HA_MSG_TYPE_ALIVE */
            ha_agent_failover_send_to_master (handle);
        } else {
            log_message (LOG_INFO, "Received all HA nodes HA_MSG_TYPE_ALIVE, no failover action");
        }
        handle->state = HA_STATE_RUNNING;
    }
    return 0;
}

static int
ha_state_action_split_brain (struct ha_agent *handle)
{
    struct msg_header *msg = NULL;
    int sock = -1, len, ret = -1;
    GList *glist;

    glist = g_list_first (handle->ha_node_list);
    if (glist == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        goto ha_state_action_split_brain_finish;
    }
    glist = g_list_next (glist);
    if (glist == NULL) {
        /* No other HA node, it's normally */
        ret = 0;
        goto ha_state_action_split_brain_finish;
    }

    /* notify & clean node list */
    msg = ha_agent_msg_create (handle, HA_MSG_TYPE_TO_INIT, &len);
    if (!msg) {
        log_message (LOG_ERR, "%s:%d: can not allocate memory",
                     __FILE__, __LINE__);
        return -1;
    }
    while ((sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new sock failed",
                     __FILE__, __LINE__);
        usleep(100000);
    }

    log_message (LOG_INFO, "Send HA_MSG_TYPE_TO_INIT to other HA nodes");
    sendtolist (sock, msg, len, glist);
    ret = 0;

    /* stop sending heart beat */
    if (!ha_hb_thread_is_hold (handle)) {
        ha_hb_thread_hold (handle);
    }

 ha_state_action_split_brain_finish:

    if (sock != -1) {
        close (sock);
    }

    if (msg) {
        free (msg);
    }

    action_to_init (handle);
    return 0;
}

static int
ha_state_action_running (struct ha_agent *handle)
{
    int ret = 0, tmp_ret;

    /* check split brain */
    tmp_ret = mcast_socket_actions (handle);
    if (tmp_ret != 0) {
        ret = -1;
    }
    /* check msg */
    tmp_ret = msg_socket_actions (handle);
    if (tmp_ret != 0) {
        ret = -1;
    }
    /* check heart beat */
    tmp_ret = hb_socket_actions (handle);
    if (tmp_ret != 0) {
        ret = -1;
    }

    return ret;
}

static int
ha_state_action_init (struct ha_agent *handle)
{
    /* mcast for master */
    struct ha_node *this = local_ha_node (handle);
    this->info.state = LIBHA_STATE_SLAVE;
    if (ha_agent_mcast_send (handle) < 0) {
        return -1;
    }
    if (recv_master_reply_timeout (handle, HA_INIT_TIMEOUT) == 0) {
        this->info.state = LIBHA_STATE_MASTER;
        log_message (LOG_INFO, "Local is master.");
    }
    else {
        log_message (LOG_INFO, "Local is slave.");
    }
    return 0;
}

static void
ha_agent_sockets_free (struct ha_agent *handle)
{
    if (handle->msg_sock) {
        close(handle->msg_sock);
        handle->msg_sock = 0;
    }

    if (handle->server_ipc) {
        libsock_ipc_server_free (&handle->server_ipc);
        handle->server_ipc = NULL;
    }
}

static int
ha_agent_sockets_init (struct ha_agent *handle)
{
    enum LIBSOCK_IPC_RESULT ipc_ret;
    ipc_ret = libsock_ipc_server_create (HA_IPC_SERVER_PATH,
                                         &(handle->server_ipc));
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        log_message (LOG_ERR, "libsock_ipc_result_string_get failed, because %s\n",
                     libsock_ipc_result_string_get (ipc_ret));
        return -1;
    }

    /* open message port */
    if (handle->msg_sock == 0) {
#if 1
        handle->msg_sock = open_socket_udp (HA_MESSAGE_PORT,
                                            NULL, &handle->bind_if_addr);
#else
        /* FIXME: Bind netif will cause that UDP packet cannot be
           received from lo */
        handle->msg_sock = open_socket_udp (HA_MESSAGE_PORT,
                                            handle->bind_if_name,
                                            &handle->bind_if_addr);
#endif

        if (handle->msg_sock < 0) {
            handle->msg_sock = 0;
            libsock_ipc_server_free (&handle->server_ipc);
            handle->server_ipc = NULL;
            return -1;
        }
    }

    return 0;
}

static void *
ha_agent_hb_thread_func (void *arg)
{
    struct ha_agent *handle = (struct ha_agent *)arg;
    struct ha_hb_thread_data *data = &handle->hb_thread_data;
    struct msg_hb *msg;
    unsigned long long timeu;
    int hb_sock, len;
    char ip[16];
    struct timeval time_diff;

    while ((msg = ha_agent_msg_create (handle, HA_MSG_TYPE_HB, &len)) == NULL) {
        log_message (LOG_ERR, "%s:%d: ha_agent_hb_msg_create failed",
                     __FILE__, __LINE__);
        usleep (100000);
    }

    while ((hb_sock = open_socket_udp (0, handle->bind_if_name,
        &handle->bind_if_addr)) < 0) {
        log_message (LOG_ERR, "%s:%d: new hb_sock failed",
                     __FILE__, __LINE__);
        usleep (100000);
    }

    log_message (LOG_INFO, "Heart beat thread is started");
    if (ha_hb_thread_is_hold (handle)) {
        log_message (LOG_INFO, "Heart beat thread hold");
    }

    while (data->stop == 0) {
        /* If ha_hb_thread_hold() is called, interval_msec is 0
           (thread safe control) */
        if (data->interval_msec > 0) {
            if (!ADDR_EMPTY (&data->target)) {
                timeu = (unsigned long long) data->interval_msec * 1000; // useconds
                /* Set heart timeout is timeu, but we will send heart
                   beat every timeu/3 usec to avoid false timeout */
                if (check_timeout (data->l_senttime, (timeu / 3), &time_diff)) {
#if 1 /* Enable this line to detect whether the HA_MSG_TYPE_HB is sent on time */
                    {
                        long diff_msec = (time_diff.tv_sec * 1000) + (time_diff.tv_usec / 1000);
                        if (diff_msec > data->interval_msec) {
                            log_message (LOG_WARNING, "%s:%d: Send HA_MSG_TYPE_HB too slow [%ld msec]\n",
                                         __FILE__, __LINE__, diff_msec);
                        }
                    }
#endif
                    msg->next_hb_msec = data->interval_msec;
                    if (sendtoaddr (hb_sock, msg, len, &data->target,
                                    HA_HEARBEAT_PORT) <= 0) {
                        inet_ntop (AF_INET, &(data->target), ip, sizeof (ip));
                        log_message (LOG_ERR, "%s:%d: Send HA_MSG_TYPE_HB to %s failed",
                                     __FILE__, __LINE__, ip);
                    }
                    update_timer (&data->l_senttime);
                }
            }
        }
        usleep(10000); /* EJ sleep 10 ms. Sleep less then 2 ms is busy loop */
    }

#if 1 /* Test case: Remark this line to test HA daemon timeout */
    /* Send the last heart beat message */
    if (data->interval_msec != 0) {
        inet_ntop (AF_INET, &(data->target), ip, sizeof (ip));
        log_message (LOG_INFO, "Send HA_MSG_TYPE_HB stop to %s", ip);
        msg->next_hb_msec = 0;
        if (sendtoaddr (hb_sock, msg, len, &data->target,
                        HA_HEARBEAT_PORT) <= 0) {
            log_message (LOG_ERR, "%s:%d: Send HA_MSG_TYPE_HB to %s failed",
                         __FILE__, __LINE__, ip);
        }
    }
#endif

    free (msg);
    close (hb_sock);

    log_message (LOG_INFO, "Heart beat thread is terminated");

    return NULL;
}

static int
ha_agent_hb_thread_run (struct ha_agent *handle)
{
    if (pthread_create ((pthread_t *) &handle->hb_ptid, 0, ha_agent_hb_thread_func,
                        handle) != 0) {
        return -1;
    }

    return 0;
}

static void
ha_agent_hb_thread_stop (struct ha_agent *handle)
{
    struct ha_hb_thread_data *data;
    data = &handle->hb_thread_data;
    if (data) {
        data->stop = 1;
        pthread_join ((pthread_t) handle->hb_ptid, NULL);
    }
}

static int
ha_agent_service_count_get (HA_AGENT *handle,
                            const char *service_name)
{
    LIBHA_REGISTER *service;
    struct ha_node *node;
    GList *node_list, *service_list;
    int count = 0;

    if (handle == NULL ||
        service_name == NULL || strlen (service_name) == 0) {
        return 0;
    }

    node_list = g_list_first (handle->ha_node_list);
    if (node_list == NULL) {
        /* FIXME: Local node isn't existed? */
        log_message (LOG_ERR, "%s:%d: Local node isn't existed?",
                     __FILE__, __LINE__);
        return 0;
    }

    for (node_list = g_list_next (node_list);
         node_list;
         node_list = g_list_next (node_list)) {
        node = (struct ha_node *) node_list->data;

        for (service_list = g_list_first (node->service_list);
             service_list;
             service_list = g_list_next (service_list)) {
            service = (LIBHA_REGISTER *) service_list->data;
            if (strcmp (service_name, service->s_name) != 0) {
                continue;
            }
            count++;
            break;
        }
    }

    return count;
}

static int
ha_agent_service_register_reply_send (HA_AGENT *handle,
                                      LIBSOCK_IPC_SERVER *server_ipc,
                                      LIBSOCK_IPC_SERVER_SESSION *session,
                                      LIBHA_REGISTER *reg_msg)
{
    struct ha_node *this, *node;
    LIBHA_REGISTER *service;
    LIBHA_REGISTER_REPLY *reg_reply = NULL;
    LIBSOCK_IPC_MESSAGE *msg = NULL;
    GList *node_list, *service_list;
    int i = 0, count, ret = -1;
    struct in_addr *local_addr = NULL;
    enum LIBSOCK_IPC_RESULT ipc_ret;

    this = local_ha_node (handle);
    if (this == NULL) {
        log_message (LOG_ERR, "%s:%d: Local node isn't existed",
                     __FILE__, __LINE__);
        goto ha_agent_service_register_reply_send_finish;
    }

    count = ha_agent_service_count_get (handle, reg_msg->s_name);

    local_addr = get_local_addr (handle);
    if (local_addr == NULL) {
        log_message (LOG_ERR, "%s:%d: Local address not found\n",
                     __FUNCTION__, __LINE__);
        goto ha_agent_service_register_reply_send_finish;
    }

    reg_reply = libha_register_reply_msg_create (count, *local_addr);
    if (reg_reply == NULL) {
        log_message (LOG_ERR, "%s:%d: Out of memory\n",
                     __FUNCTION__, __LINE__);
        goto ha_agent_service_register_reply_send_finish;
    }

    reg_reply->ha_state = this->info.state;
    reg_reply->pid = getpid();

    node_list = g_list_first (handle->ha_node_list);

    /* Don't need to send local service information */
    for (node_list = g_list_next (node_list);
         node_list;
         node_list = g_list_next (node_list)) {
        node = (struct ha_node *) node_list->data;

        for (service_list = g_list_first (node->service_list);
             service_list;
             service_list = g_list_next (service_list)) {
            service = (LIBHA_REGISTER *) service_list->data;
            if (strcmp (reg_msg->s_name, service->s_name) != 0) {
                continue;
            }

            libha_register_reply_msg_set (reg_reply,
                                          i,
                                          &node->info);
            i++;
            break;
        }
    }

    ipc_ret = libsock_ipc_msg_create (LIBHA_MESSAGE_TYPE_REGISTER_REPLY,
                                      (char *) reg_reply,
                                      libha_register_reply_msg_size_get (reg_reply),
                                      &msg);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        log_message (LOG_ERR, "%s:%d: libsock_ipc_msg_create failed, because %s\n",
                     __FUNCTION__, __LINE__,
                     libsock_ipc_result_string_get (ipc_ret));
        goto ha_agent_service_register_reply_send_finish;
    }

    ipc_ret =
        libsock_ipc_server_msg_send_reply_with_timeout (handle->server_ipc,
                                                        session,
                                                        msg,
                                                        LIBHA_SERVER_SEND_REPLY_TIMEOUT);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        log_message (LOG_ERR, "%s:%d: libsock_ipc_server_msg_send_reply_with_timeout, because %s\n",
                     __FUNCTION__, __LINE__,
                     libsock_ipc_result_string_get (ipc_ret));
        libsock_ipc_server_msg_send_reply_cancel (handle->server_ipc);
        goto ha_agent_service_register_reply_send_finish;
    }

    log_message (LOG_INFO, "Send LIBHA_MESSAGE_TYPE_REGISTER_REPLY to service [%s] success\n",
                 reg_msg->s_name);

    ret = 0;

 ha_agent_service_register_reply_send_finish:

    if (msg) {
        libsock_ipc_msg_free (&msg);
    }

    if (reg_reply) {
        free (reg_reply);
    }

    return ret;
}

static int
ha_agent_service_register_handler (HA_AGENT *handle,
                                   LIBSOCK_IPC_SERVER *server_ipc,
                                   LIBSOCK_IPC_SERVER_SESSION *session,
                                   LIBHA_REGISTER *reg_msg)
{
    struct ha_node *this;
    LIBHA_REGISTER *reg_msg_tmp;
    GList *list;

    this = local_ha_node (handle);

    if (session == NULL) {
        log_message (LOG_ERR, "%s:%d: The register IPC shall be reply [%s]",
                     __FILE__, __LINE__, reg_msg->s_name);
        return -1;
    }

    /* Is this node existed? */
    list = g_list_find_custom (this->service_list,
                               reg_msg,
                               ha_agent_service_find_func);

    if (list) {
        reg_msg_tmp = (LIBHA_REGISTER *) list->data;
        reg_msg_tmp->pid = reg_msg->pid;

        /* This service is existed, so just send reply to daemon */
        return ha_agent_service_register_reply_send (handle,
                                                     server_ipc,
                                                     session,
                                                     reg_msg);
    }

    reg_msg_tmp = (LIBHA_REGISTER *) calloc (1, sizeof (LIBHA_REGISTER));
    if (reg_msg_tmp == NULL) {
        log_message (LOG_ERR, "%s:%d: Out of memory",
                     __FILE__, __LINE__);
        goto ha_agent_service_register_handler_error;
    }

    log_message (LOG_INFO, "Received LIBHA_MESSAGE_TYPE_REGISTER from service [%s]",
                 reg_msg->s_name);

    if (ha_agent_service_register_reply_send (handle,
                                              server_ipc,
                                              session,
                                              reg_msg) != 0) {
        goto ha_agent_service_register_handler_error;
    }

    memcpy (reg_msg_tmp, reg_msg, sizeof (LIBHA_REGISTER));
    this->service_list =
        g_list_insert_sorted_with_data (this->service_list,
                                        reg_msg_tmp,
                                        ha_agent_service_compare_func,
                                        NULL);

    /* Send notification message */
    ha_agent_service_update_send (handle);

    /* For debugging */
    ha_agent_ha_nodes_info_dump (handle);

    return 0;

 ha_agent_service_register_handler_error:

    libsock_ipc_server_msg_send_reply_cancel (handle->server_ipc);

    if (reg_msg_tmp) {
        free (reg_msg_tmp);
    }

    return -1;
}

static void
ha_agent_service_ipc_recv (HA_AGENT *handle)
{
    LIBSOCK_IPC_SERVER *server_ipc;
    LIBSOCK_IPC_SERVER_SESSION *session = NULL;
    LIBSOCK_IPC_MESSAGE *recv_msg = NULL;
    long msg_type;
    char *payload;
    size_t len;
    enum LIBSOCK_IPC_RESULT ipc_ret;

    server_ipc = handle->server_ipc;

    /* Receive IPC message until no any message in queue */
    while (1) {
        ipc_ret = libsock_ipc_server_msg_recv (server_ipc, &session, &recv_msg);
        if (ipc_ret == LIBSOCK_IPC_RESULT_RETRY) {
            break;
        }

        if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
            log_message (LOG_ERR, "%s:%d: libsock_ipc_server_msg_recv failed, because %s\n",
                         __FUNCTION__, __LINE__,
                         libsock_ipc_result_string_get (ipc_ret));
            break;
        }

        ipc_ret = libsock_ipc_msg_info_get (recv_msg, &msg_type, NULL);
        if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
            log_message (LOG_ERR, "%s:%d: libsock_ipc_msg_info_get failed, because %s\n",
                         __FUNCTION__, __LINE__,
                         libsock_ipc_result_string_get (ipc_ret));
            break;
        }

        ipc_ret = libsock_ipc_msg_payload_get (recv_msg, &payload, &len);
        if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
            log_message (LOG_ERR, "%s:%d: libsock_ipc_msg_payload_get failed, because %s\n",
                         __FUNCTION__, __LINE__,
                         libsock_ipc_result_string_get (ipc_ret));
            break;
        }

        switch (msg_type) {
        case LIBHA_MESSAGE_TYPE_REGISTER:
            ha_agent_service_register_handler (handle,
                                               server_ipc,
                                               session,
                                               (LIBHA_REGISTER *) payload);
            break;
        default:
            if (session) {
                /* The server session shall be cancel, because we didn't
                   response */
                libsock_ipc_server_msg_send_reply_cancel (handle->server_ipc);
            }
            break;
        }

        if (session) {
            libsock_ipc_server_session_free (&session);
        }

        if (recv_msg) {
            libsock_ipc_msg_free (&recv_msg);
        }
    }

    if (session) {
        libsock_ipc_server_session_free (&session);
    }

    if (recv_msg) {
        libsock_ipc_msg_free (&recv_msg);
    }
}

static void
ha_agent_local_service_is_alive_check (HA_AGENT *handle)
{
    struct ha_node *this = local_ha_node (handle);
    LIBHA_REGISTER *service;
    GList *list, *next;
    gboolean is_deleted = FALSE;

    list = g_list_first (this->service_list);
    while (list) {
        next = g_list_next (list);
        service = (LIBHA_REGISTER *) list->data;

        if (is_daemon_alive (service->pid) != 1) {
            log_message (LOG_INFO, "Found service [%s] isn't existed, pid [%d]",
                         service->s_name,
                         service->pid);
            this->service_list = g_list_delete_link (this->service_list, list);
            free (service);
            is_deleted = TRUE;
        }
        list = next;
    }

    if (!is_deleted) {
        return;
    }

    /* Some service isn't existed, send notification message */
    ha_agent_service_update_send (handle);

    /* For debugging */
    ha_agent_ha_nodes_info_dump (handle);
}

/* ------ public functions ------ */
HA_AGENT *
ha_agent_create (void)
{
    struct ha_agent *handle;

    handle = calloc (1, sizeof (struct ha_agent));
    if (!handle) {
        return NULL;
    }

    if (ha_agent_init (handle)) {
        free (handle);
        return NULL;
    }

    return handle;
}

void
ha_agent_free (HA_AGENT *handle)
{
    if (!handle) {
        return;
    }

    if (handle->state != HA_STATE_EXITING) {
        ha_agent_stop (handle);
    }

    if (handle->bind_if_name) {
        free (handle->bind_if_name);
        handle->bind_if_name = NULL;
    }
    ha_agent_ha_node_list_free (handle->ha_node_list, handle);
    master_data_free ((struct master_data *) handle->master_data);
    hb_data_free ((struct ha_hb_data *) handle->hb_data);
    if (handle->msg_sock) {
        close (handle->msg_sock);
    }

    free (handle);
}

int
ha_agent_run (HA_AGENT *handle)
{
    LIBSOCK_IPC_SERVER *server_ipc;
    LIBSOCK_IPC_SERVER_SESSION *session = NULL;
    LIBSOCK_IPC_MESSAGE *recv_msg = NULL;
    int ret = 0, state;

    while (ha_agent_sockets_init (handle) < 0) {
        if (handle->state == HA_STATE_EXITING) {
            goto ha_agent_run_finish;
        }

        log_message (LOG_ERR, "%s:%d: initial sockets failed",
                     __FILE__, __LINE__);
        sleep (1);
    }

    while (ha_agent_hb_thread_run (handle) < 0) {
        if (handle->state == HA_STATE_EXITING) {
            goto ha_agent_run_finish;
        }

        log_message (LOG_ERR, "%s:%d: heart beat thread initial failed",
                     __FILE__, __LINE__);
        sleep (1);
    }

    /* Flush all message in socket buffer before enter while loop */
    server_ipc = handle->server_ipc;
    while (libsock_ipc_server_msg_recv (server_ipc,
                                        &session,
                                        &recv_msg) == LIBSOCK_IPC_RESULT_OK) {
        if (session) {
            libsock_ipc_server_msg_send_reply_cancel (server_ipc);
            libsock_ipc_server_session_free (&session);
        }

        if (recv_msg) {
            libsock_ipc_msg_free (&recv_msg);
        }
    }

    while (handle->state != HA_STATE_EXITING) {
        state = handle->state;
        switch (state) {
        case HA_STATE_INIT:
            ret = ha_state_action_init (handle);
            if (ret == 0) {
                handle->state = HA_STATE_RUNNING;
                log_message (LOG_INFO, "to running mode.");
            }
            break;
        case HA_STATE_RUNNING:
            ret = ha_state_action_running (handle);
            if (handle->state == HA_STATE_SPLIT_BRAIN) {
                log_message (LOG_INFO, "to split brain mode.");
            } else if (handle->state == HA_STATE_FAILOVER) {
                log_message (LOG_INFO, "to failover mode.");
            }
            break;
        case HA_STATE_SPLIT_BRAIN:
            ret = ha_state_action_split_brain (handle);
            log_message (LOG_INFO, "to init mode.");
            break;
        case HA_STATE_FAILOVER:
            ret = ha_state_action_failover (handle);
            if (handle->state == HA_STATE_RUNNING) {
                log_message (LOG_INFO, "to running mode.");
            }
            break;
        }

        /* All of the state shall to handle the IPC from service */
        ha_agent_service_ipc_recv (handle);

        /* All of the state shall to check daemon's state */
        ha_agent_local_service_is_alive_check (handle);

        // usleep (1000);
        usleep(10000); // EJ sleep 10 ms. Sleep less then 2 ms is busy loop
    }

 ha_agent_run_finish:

    ha_agent_sockets_free (handle);

    /* stop thread */
    ha_agent_hb_thread_stop (handle);
    return ret;
}

void
ha_agent_stop (HA_AGENT *handle)
{
    handle->state = HA_STATE_EXITING;
}

void
ha_agent_if_name_set (char *name, HA_AGENT *handle)
{
    handle->bind_if_name = name;
}

char *
ha_agent_if_name_get (HA_AGENT *handle)
{
    return handle->bind_if_name;
}

void
ha_agent_if_addr_set (struct in_addr *addr, HA_AGENT *handle)
{
    handle->bind_if_addr = *addr;
}

int
ha_agent_node_addr_set (struct in_addr *addr, char *hostname, HA_AGENT *handle)
{
    struct ha_node_info ha_info;
    struct ha_node *node;

    memset (&ha_info, 0, sizeof (struct ha_node_info));
    ha_info.addr = *addr;
    strcpy(ha_info.hostname, hostname);
    node = ha_node_new (handle, &ha_info);

    if (node) {
        handle->ha_node_list = g_list_append (handle->ha_node_list, node);
        return 0;
    }
    return -1;
}

void
ha_agent_key_set (HA_AGENT *handle, void *key, int len)
{
    if (len >= sizeof (handle->group_id)) {
        memcpy (&(handle->group_id), key, sizeof (handle->group_id));
    } else {
        memcpy (&(handle->group_id), key, len);
    }
}
/* ------ end public functions ------ */
