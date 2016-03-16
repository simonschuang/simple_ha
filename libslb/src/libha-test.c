#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib.h>
#include "daemon.h"
#include "libsock-ipc.h"
#include "libslb-netif.h"
#include "libha.h"

static GMainLoop *g_main_loop = NULL;

static void
signal_catch (int sig)
{
    /* Ignore pipe signal */
    if (sig == SIGPIPE) {
        return;
    }

    if (g_main_loop) {
        g_main_loop_quit (g_main_loop);
    }
}

#ifdef __LIBHA_CLIENT__
#define LIBHA_TEST_EVENT_POLL_INTERVAL 100 /* 100ms */

typedef struct LIBHA_TEST_CLIENT {
    LIBHA *ha;
    enum LIBHA_STATE state; /* Local service state */
} LIBHA_TEST_CLIENT;

static void
member_list_dump (LIBHA_TEST_CLIENT *handle, LIBHA_MEMBER_LIST *member_list)
{
    LIBHA_MEMBER_LIST *list;
    LIBHA_MEMBER *info;

    if (handle) {
        printf ("Local, state is %s\n",
                (handle->state == LIBHA_STATE_MASTER) ? "master" : "slave");
    }

    if (member_list == NULL) {
        printf ("member list is empty\n");
        return;
    }

    for (list = member_list; list; list = list->next) {
        info = &(list->info);
        printf ("addr=%s, state is %s\n",
                inet_ntoa (info->addr),
                (info->state == LIBHA_STATE_MASTER) ? "master" : "slave");
    }
}

static gboolean
ha_event_poll (gpointer user_data)
{
    LIBHA_TEST_CLIENT *handle;
    LIBHA *ha;
    int event;
    enum LIBHA_STATE state;
    LIBHA_MEMBER_LIST *member_list;
    enum LIBHA_RESULT ret;

    handle = (LIBHA_TEST_CLIENT *) user_data;
    ha = handle->ha;

    ret = libha_event_poll (ha, &event);
    if (ret != LIBHA_RESULT_OK) {
        printf ("%s:%d: libha_event_poll failed, because %s\n",
                __FUNCTION__, __LINE__,
                libha_result_string_get (ret));
        goto ha_event_poll_finish;
    }

    if (LIBHA_EVENT_IS_SET (event, LIBHA_EVENT_TYPE_HA_DOWN)) {
        printf ("Got event: HA down\n");
    }
    
    if (LIBHA_EVENT_IS_SET (event, LIBHA_EVENT_TYPE_TO_MASTER)) {
        printf ("Got event: to master\n");
        ret = libha_state_get (ha, &state);
        if (ret != LIBHA_RESULT_OK) {
            printf ("%s:%d: libha_state_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libha_result_string_get (ret));
        } else {
            printf ("Current state is %s\n",
                    (state == LIBHA_STATE_MASTER) ? "master" : "slave");
        }
        handle->state = state;
    }

    if (LIBHA_EVENT_IS_SET (event, LIBHA_EVENT_TYPE_TO_SLAVE)) {
        printf ("Got event: to slave\n");
        ret = libha_state_get (ha, &state);
        if (ret != LIBHA_RESULT_OK) {
            printf ("%s:%d: libha_state_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libha_result_string_get (ret));
        } else {
            printf ("Current state is %s\n",
                    (state == LIBHA_STATE_MASTER) ? "master" : "slave");
        }
        handle->state = state;
    }

    if (LIBHA_EVENT_IS_SET (event, LIBHA_EVENT_TYPE_CHANGE_MASTER)) {
        printf ("Got event: change master\n");
        ret = libha_member_list_get (ha, &member_list);
        if (ret != LIBHA_RESULT_OK) {
            printf ("%s:%d: libha_member_list_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libha_result_string_get (ret));
        } else {
            handle->state = LIBHA_STATE_SLAVE;
            member_list_dump (handle, member_list);
            libha_member_list_free (&member_list);
        }
    }

    if (LIBHA_EVENT_IS_SET (event, LIBHA_EVENT_TYPE_CHANGE_REMOTE)) {
        printf ("Got event: change remote\n");
        ret = libha_state_get (ha, &state);
        if (ret != LIBHA_RESULT_OK) {
            printf ("%s:%d: libha_state_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libha_result_string_get (ret));
        }
        handle->state = state;

        ret = libha_member_list_get (ha, &member_list);
        if (ret != LIBHA_RESULT_OK) {
            printf ("%s:%d: libha_member_list_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libha_result_string_get (ret));
        } else {
            member_list_dump (handle, member_list);
            libha_member_list_free (&member_list);
        }
    }

 ha_event_poll_finish:

    g_timeout_add (LIBHA_TEST_EVENT_POLL_INTERVAL,
                   ha_event_poll,
                   handle);

    return FALSE;
}

int
main (int argc, char *argv[])
{
    LIBHA_TEST_CLIENT handle;
    enum LIBHA_STATE state;
    LIBHA_MEMBER_LIST *member_list = NULL;
    struct sigaction act;
    enum LIBHA_RESULT ret;

    if (argc != 2) {
        printf ("%s [service name]\n", argv[0]);
        return -1;
    }

    memset (&handle, 0, sizeof (LIBHA_TEST_CLIENT));
    handle.state = LIBHA_STATE_SLAVE;

    /* Init signal catch */
    act.sa_handler = signal_catch;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction (SIGTERM, &act, NULL);
    sigaction (SIGINT, &act, NULL);
    sigaction (SIGPIPE, &act, NULL);

    /* Init thread system for glib */
    g_thread_init (NULL);

    g_main_loop = g_main_loop_new (NULL, FALSE);

    ret = libha_create (&(handle.ha), argv[1]);
    if (ret != LIBHA_RESULT_OK) {
        printf ("%s:%d: libha_create failed, because %s\n",
                __FUNCTION__, __LINE__,
                libha_result_string_get (ret));
        goto finish;
    }

    ret = libha_run (handle.ha);
    if (ret != LIBHA_RESULT_OK) {
        printf ("%s:%d: libha_run failed, because %s\n",
                __FUNCTION__, __LINE__,
                libha_result_string_get (ret));
        goto finish;
    }

    printf ("Dump HA daemon information...\n");

    ret = libha_state_get (handle.ha, &state);
    if (ret != LIBHA_RESULT_OK) {
        printf ("%s:%d: libha_state_get failed, because %s\n",
                __FUNCTION__, __LINE__,
                libha_result_string_get (ret));
    } else {
        printf ("Current state is %s\n",
                (state == LIBHA_STATE_MASTER) ? "master" : "slave");
    }
    handle.state = state;

    ret = libha_member_list_get (handle.ha, &member_list);
    if (ret != LIBHA_RESULT_OK) {
        printf ("%s:%d: libha_member_list_get failed, because %s\n",
                __FUNCTION__, __LINE__,
                libha_result_string_get (ret));
    } else {
        member_list_dump (&handle, member_list);
        libha_member_list_free (&member_list);
    }
    printf ("Dump HA daemon information ok...\n");

    ha_event_poll (&handle);

    /* Enter main loop */
    g_main_loop_run (g_main_loop);

 finish:

    /* Main loop Terminated */
    if (g_main_loop) {
        g_main_loop_unref (g_main_loop);
        g_main_loop = NULL;
    }

    libha_stop (handle.ha);
    libha_free (&(handle.ha));

    return 0;
}
#endif

#ifdef __LIBHA_SERVER__
#define LIBHA_IPC_RECV_INTERVAL 1
#define LIBHA_SERVER_SEND_REPLY_TIMEOUT 10 /* 10ms */
#define LIBHA_SERVER_MASTER_CHANGE_TIMEOUT 5000 /* 5s */
#define LIBHA_SERVER_REMOTE_CHANGE_TIMEOUT 11000 /* 11s */
#define LIBHA_SERVER_SERVICE_CHECK_INTERVAL 100 /* 100ms */
#define LIBHA_MEMBER_LIST_DEFAULT_COUNT 2
#define LIBHA_SERVICE_CHANGE_RANGE 2

typedef struct LIBHA_TEST_SERVER {
    LIBSOCK_IPC_SERVER *server_ipc;
    GList *register_list; /* LIBHA_REGISTER */
    GList *member_list; /* LIBHA_MEMBER */
    enum LIBHA_STATE state; /* Local service state */

    int remote_modify_count;
    gboolean remote_is_add;
} LIBHA_TEST_SERVER;

static gint
libha_register_find_func (gconstpointer a,
                          gconstpointer b)
{
    LIBHA_REGISTER *reg_msg_a, *reg_msg_b;

    reg_msg_a = (LIBHA_REGISTER *) a;
    reg_msg_b = (LIBHA_REGISTER *) b;

    return strcmp (reg_msg_a->s_name, reg_msg_b->s_name);
}

static gint
libha_register_compare_func (gconstpointer a,
                             gconstpointer b,
                             gpointer user_data)
{
    LIBHA_REGISTER *reg_msg_a, *reg_msg_b;

    reg_msg_a = (LIBHA_REGISTER *) a;
    reg_msg_b = (LIBHA_REGISTER *) b;

    return strcmp (reg_msg_a->s_name, reg_msg_b->s_name);
}

static void
libha_ipc_register_reply_send (LIBHA_TEST_SERVER *handle,
                               LIBSOCK_IPC_SERVER *server_ipc,
                               LIBSOCK_IPC_SERVER_SESSION *session)
{
    LIBHA_REGISTER_REPLY *reg_reply = NULL;
    LIBSOCK_IPC_MESSAGE *msg = NULL;
    char *netif_name = NULL;
    GList *list;
    int i = 0;
    struct in_addr local_addr;
    enum LIBSOCK_IPC_RESULT ret;

    netif_name = libslb_priv_netif_name_get();
    if (netif_name == NULL) {
        printf ("%s:%d: libslb_priv_netif_name_get failed\n",
                __FUNCTION__, __LINE__);
        goto libha_ipc_register_reply_send_finish;
    }

    if (libslb_netif_ip_get_by_name (netif_name, &local_addr) != 0) {
        printf ("%s:%d: libslb_netif_ip_get_by_name failed\n",
                __FUNCTION__, __LINE__);
        goto libha_ipc_register_reply_send_finish;
    }

    reg_reply = libha_register_reply_msg_create (g_list_length (handle->member_list),
                                                 local_addr);
    if (reg_reply == NULL) {
        printf ("%s:%d: Out of memory\n",
                __FUNCTION__, __LINE__);
        goto libha_ipc_register_reply_send_finish;
    }

    for (list = g_list_first (handle->member_list);
         list;
         list = g_list_next (list)) {
        libha_register_reply_msg_set (reg_reply,
                                      i,
                                      (LIBHA_MEMBER *) list->data);
        i++;
    }

    ret = libsock_ipc_msg_create (LIBHA_MESSAGE_TYPE_REGISTER_REPLY,
                                  (char *) reg_reply,
                                  libha_register_reply_msg_size_get (reg_reply),
                                  &msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("%s:%d: libsock_ipc_msg_create failed, because %s\n",
                __FUNCTION__, __LINE__,
                libsock_ipc_result_string_get (ret));
        goto libha_ipc_register_reply_send_finish;
    }

    ret = libsock_ipc_server_msg_send_reply_with_timeout (server_ipc,
                                                          session,
                                                          msg,
                                                          LIBHA_SERVER_SEND_REPLY_TIMEOUT);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("%s:%d: libsock_ipc_server_msg_send_reply_with_timeout, because %s\n",
                __FUNCTION__, __LINE__,
                libsock_ipc_result_string_get (ret));
        libsock_ipc_server_msg_send_reply_cancel (server_ipc);
        goto libha_ipc_register_reply_send_finish;
    }

 libha_ipc_register_reply_send_finish:

    if (netif_name) {
        free (netif_name);
    }

    if (msg) {
        libsock_ipc_msg_free (&msg);
    }

    if (reg_reply) {
        free (reg_reply);
    }
}

static gboolean
libha_ipc_register_recv (LIBHA_TEST_SERVER *handle,
                         LIBSOCK_IPC_SERVER *server_ipc,
                         LIBHA_REGISTER *reg_msg)
{
    LIBHA_REGISTER *reg_msg_tmp;
    GList *list;

    list = g_list_find_custom (handle->register_list,
                               reg_msg,
                               libha_register_find_func);
    if (list) {
        reg_msg_tmp = (LIBHA_REGISTER *) list->data;
        reg_msg_tmp->pid = reg_msg->pid;
        return TRUE;
    }

    reg_msg_tmp = (LIBHA_REGISTER *) calloc (1, sizeof (LIBHA_REGISTER));
    if (reg_msg_tmp == NULL) {
        printf ("%s:%d: Out of memory\n",
                __FUNCTION__, __LINE__);
        return FALSE;
    }

    reg_msg_tmp->pid = reg_msg->pid;
    strcpy (reg_msg_tmp->s_name, reg_msg->s_name);

    handle->register_list =
        g_list_insert_sorted_with_data (handle->register_list,
                                        reg_msg_tmp,
                                        libha_register_compare_func,
                                        NULL);

    return TRUE;
}

static gboolean
libha_server_ipc_recv (gpointer user_data)
{
    LIBHA_TEST_SERVER *handle;
    LIBSOCK_IPC_SERVER *server_ipc;
    LIBSOCK_IPC_SERVER_SESSION *session = NULL;
    LIBSOCK_IPC_MESSAGE *recv_msg = NULL;
    long msg_type;
    char *payload;
    size_t len;
    enum LIBSOCK_IPC_RESULT ret;

    handle = (LIBHA_TEST_SERVER *) user_data;
    server_ipc = handle->server_ipc;

    while (1) {
        ret = libsock_ipc_server_msg_recv (server_ipc, &session, &recv_msg);
        if (ret == LIBSOCK_IPC_RESULT_RETRY) {
            break;
        }

        if (ret != LIBSOCK_IPC_RESULT_OK) {
            printf ("%s:%d: libsock_ipc_server_msg_recv failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libsock_ipc_result_string_get (ret));
            break;
        }

        ret = libsock_ipc_msg_info_get (recv_msg, &msg_type, NULL);
        if (ret != LIBSOCK_IPC_RESULT_OK) {
            printf ("%s:%d: libsock_ipc_msg_info_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libsock_ipc_result_string_get (ret));
            break;
        }

        ret = libsock_ipc_msg_payload_get (recv_msg, &payload, &len);
        if (ret != LIBSOCK_IPC_RESULT_OK) {
            printf ("%s:%d: libsock_ipc_msg_payload_get failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libsock_ipc_result_string_get (ret));
            break;
        }

        if (msg_type == LIBHA_MESSAGE_TYPE_REGISTER) {
            printf ("Receive a register message\n");
            if (libha_ipc_register_recv (handle,
                                         server_ipc,
                                         (LIBHA_REGISTER *) payload)) {
            }

            if (session && msg_type == LIBHA_MESSAGE_TYPE_REGISTER) {
                printf ("Send register reply message\n");
                libha_ipc_register_reply_send (handle, server_ipc, session);
            }
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

    g_timeout_add (LIBHA_IPC_RECV_INTERVAL, libha_server_ipc_recv, handle);

    return FALSE;
}

static void
libha_server_register_list_free (LIBHA_TEST_SERVER *handle)
{
    GList *list;

    if (handle == NULL) {
        return;
    }

    while ((list = g_list_first (handle->register_list))) {
        if (list->data) {
            free (list->data);
        }

        handle->register_list = g_list_delete_link (handle->register_list, list);
    }
}

static void
libha_server_member_list_free (LIBHA_TEST_SERVER *handle)
{
    GList *list;

    if (handle == NULL) {
        return;
    }

    while ((list = g_list_first (handle->member_list))) {
        if (list->data) {
            free (list->data);
        }

        handle->member_list = g_list_delete_link (handle->member_list, list);
    }
}

static void
libha_server_member_list_add (LIBHA_TEST_SERVER *handle)
{
    LIBHA_MEMBER *member;
    char addr[16];
    int i;

    for (i = 0; i < LIBHA_MEMBER_LIST_DEFAULT_COUNT; i++) {
        member = (LIBHA_MEMBER *) calloc (1, sizeof (LIBHA_MEMBER));
        if (member == NULL) {
            return;
        }

        snprintf (addr, sizeof (addr), "10.10.1.%d", i + 1);
        inet_aton (addr, &(member->addr));
        if (i == 0) {
            member->state = LIBHA_STATE_MASTER;
        } else {
            member->state = LIBHA_STATE_SLAVE;
        }

        handle->member_list = g_list_append (handle->member_list, member);
    }
}

static void
libha_server_notify_change_remote_send (LIBHA_TEST_SERVER *handle,
                                        enum LIBHA_SERVICE_OP op_state,
                                        struct in_addr *addr,
                                        enum LIBHA_STATE remote_state,
                                        enum LIBHA_STATE local_state)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *msg = NULL;
    LIBHA_NOTIFY_REMOTE notify_remote;
    LIBHA_REGISTER *reg;
    GList *list;
    enum LIBSOCK_IPC_RESULT ret;

    printf ("libha_server_notify_change_remote_send\n");

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("%s:%d: libsock_ipc_client_create failed, because %s\n",
                __FUNCTION__, __LINE__,
                libsock_ipc_result_string_get (ret));
        return;
    }

    notify_remote.op_state = op_state;
    memcpy (&(notify_remote.addr), addr, sizeof (struct in_addr));
    notify_remote.remote_state = remote_state;
    notify_remote.local_state = local_state;

    ret = libsock_ipc_msg_create (LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE,
                                  (void *) &notify_remote,
                                  sizeof (LIBHA_NOTIFY_REMOTE),
                                  &msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("%s:%d: libsock_ipc_msg_create failed, because %s\n",
                __FUNCTION__, __LINE__,
                libsock_ipc_result_string_get (ret));
        goto libha_server_notify_change_remote_send;
    }

    for (list = g_list_first (handle->register_list);
         list;
         list = g_list_next (list)) {
        reg = (LIBHA_REGISTER *) list->data;

        ret = libsock_ipc_client_msg_send_with_no_reply (client_ipc,
                                                         reg->s_name,
                                                         msg);
        if (ret != LIBSOCK_IPC_RESULT_OK) {
            printf ("%s:%d: libsock_ipc_client_msg_send_with_no_reply failed, because %s\n",
                    __FUNCTION__, __LINE__,
                    libsock_ipc_result_string_get (ret));
            continue;
        }
    }

 libha_server_notify_change_remote_send:

    if (msg) {
        libsock_ipc_msg_free (&msg);
    }

    if (client_ipc) {
        libsock_ipc_client_free (&client_ipc);
    }
}

static gboolean
libha_master_change (gpointer user_data)
{
    LIBHA_TEST_SERVER *handle;
    LIBHA_MEMBER *member;
    unsigned int index, member_count;
    GList *list;
    int i;

    handle = (LIBHA_TEST_SERVER *) user_data;

    member_count = g_list_length (handle->member_list);

 retry:
    while (1) {
        i = 0;
        index = (g_random_int () % (member_count + 1));

        /* Local state change to master */
        if (index == member_count) {
#if 0
// won't happen
            if (handle->state == LIBHA_STATE_MASTER) {
                /* Local is already a master */
                goto retry;
            }
            handle->state = LIBHA_STATE_MASTER;

            /* Change all of the remote state to slave */
            for (list = g_list_first (handle->member_list);
                 list;
                 list = g_list_next (list)) {
                member = (LIBHA_MEMBER *) list->data;
                member->state = LIBHA_STATE_SLAVE;
            }

            libha_server_notify_state_send (handle);

#endif
            return TRUE;
        }

        /* Remote state chanage to master */
        for (list = g_list_first (handle->member_list);
             list;
             list = g_list_next (list)) {
            member = (LIBHA_MEMBER *) list->data;
            if (i == index) {
                if (member->state == LIBHA_STATE_MASTER) {
                    goto retry;
                }
                member->state = LIBHA_STATE_MASTER;
            } else {
                member->state = LIBHA_STATE_SLAVE;
            }

            i++;
        }

        for (list = g_list_first (handle->member_list);
             list;
             list = g_list_next (list)) {
            member = (LIBHA_MEMBER *) list->data;
        }

        /* Local state change to slave */
        handle->state = LIBHA_STATE_SLAVE;

        break;
    }

    return TRUE;
}

static gboolean
libha_remote_change (gpointer user_data)
{
    LIBHA_TEST_SERVER *handle;
    LIBHA_MEMBER *member;
    char addr[16];
    struct in_addr address;
    GList *list;

    handle = (LIBHA_TEST_SERVER *) user_data;

    if (handle->remote_is_add) {
        handle->remote_modify_count++;
        if (handle->remote_modify_count == LIBHA_SERVICE_CHANGE_RANGE + 1) {
            handle->remote_is_add = FALSE;

            libha_remote_change (handle);
            return FALSE;
        }
    } else {
        handle->remote_modify_count--;
        if (handle->remote_modify_count == 0) {
            handle->remote_is_add = TRUE;

            libha_remote_change (handle);
            return FALSE;
        }
    }

    snprintf (addr, sizeof (addr), "10.10.2.%d", handle->remote_modify_count);

    if (handle->remote_is_add) {
        member = (LIBHA_MEMBER *) calloc (1, sizeof (LIBHA_MEMBER));
        if (member == NULL) {
            return TRUE;
        }
        inet_aton (addr, &(member->addr));
        member->state = LIBHA_STATE_SLAVE;

        libha_server_notify_change_remote_send (handle,
                                                LIBHA_SERVICE_OP_ADD,
                                                &(member->addr),
                                                member->state,
                                                handle->state);

        handle->member_list = g_list_append (handle->member_list, member);
    } else {
        inet_aton (addr, &address);
        for (list = g_list_first (handle->member_list);
             list;
             list = g_list_next (list)) {
            member = (LIBHA_MEMBER *) list->data;
            if (memcmp (&address, &(member->addr), sizeof (struct in_addr)) != 0) {
                continue;
            }

            if (member->state == LIBHA_STATE_MASTER) {
                handle->state = LIBHA_STATE_MASTER;
            }

            handle->member_list = g_list_delete_link (handle->member_list, list);
            free (member);
            break;
        }

        /* read from pointer member after free
        libha_server_notify_change_remote_send (handle,
                                                LIBHA_SERVICE_OP_DEL,
                                                &address,
                                                member->state,
                                                handle->state);
        */
    }

    g_timeout_add (LIBHA_SERVER_MASTER_CHANGE_TIMEOUT,
                   libha_remote_change,
                   handle);

    return FALSE;
}

static gboolean
libha_service_check (gpointer user_data)
{
    LIBHA_TEST_SERVER *handle;
    LIBHA_REGISTER *reg;
    GList *list;

    handle = (LIBHA_TEST_SERVER *) user_data;

    for (list = g_list_first (handle->register_list);
         list;
         list = g_list_next (list)) {
        reg = (LIBHA_REGISTER *) list->data;

        if (is_daemon_alive (reg->pid) != 1) {
            printf ("Service %s isn't existed\n", reg->s_name);
            handle->register_list = g_list_delete_link (handle->register_list, list);
            free (reg);

            /* TODO: Then? */
        }
    }

    return TRUE;
}

int
main (int argc, char *argv[])
{
    struct sigaction act;
    LIBHA_TEST_SERVER handle;
    enum LIBSOCK_IPC_RESULT ret;

    memset (&handle, 0, sizeof (LIBHA_TEST_SERVER));
    handle.state = LIBHA_STATE_SLAVE;
    handle.remote_modify_count = 0;
    handle.remote_is_add = TRUE;

    /* Init signal catch */
    act.sa_handler = signal_catch;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction (SIGTERM, &act, NULL);
    sigaction (SIGINT, &act, NULL);
    sigaction (SIGPIPE, &act, NULL);

    g_main_loop = g_main_loop_new (NULL, FALSE);

    ret = libsock_ipc_server_create (HA_IPC_SERVER_PATH, &(handle.server_ipc));
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("%s:%d: libsock_ipc_server_create failed, because %s\n",
                __FUNCTION__, __LINE__,
                libsock_ipc_result_string_get (ret));
        goto finish;
    }

    libha_server_member_list_add (&handle);

    libha_server_ipc_recv (&handle);

    /* Change master timer */
    g_timeout_add (LIBHA_SERVER_MASTER_CHANGE_TIMEOUT,
                   libha_master_change,
                   &handle);

    /* Chagne remote timer */
    g_timeout_add (LIBHA_SERVER_REMOTE_CHANGE_TIMEOUT,
                   libha_remote_change,
                   &handle);

    /* Check service state */
    g_timeout_add (LIBHA_SERVER_SERVICE_CHECK_INTERVAL,
                   libha_service_check,
                   &handle);

    /* Enter main loop */
    g_main_loop_run (g_main_loop);

 finish:

    /* Main loop Terminated */
    if (g_main_loop) {
        g_main_loop_unref (g_main_loop);
        g_main_loop = NULL;
    }

    libha_server_register_list_free (&handle);
    libha_server_member_list_free (&handle);

    if (handle.server_ipc) {
        libsock_ipc_server_free (&(handle.server_ipc));
    }

    return 0;
}
#endif
