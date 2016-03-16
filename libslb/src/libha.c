/*
 *              COPYRIGHT (c) 2009-2015  CCMA
 *                     ALL RIGHTS RESERVED
 *
 * Description: Library for slb ha
 * Filename:    libha.c
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>, Hogan Lee, <s30011w@gmail.com>
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <glib.h>
#include "daemon.h"
#include "libsock-ipc.h"
#include "libha.h"

#define LIBHA_THREAD_WAIT_TIME 100000 /* 100ms */
#define LIBHA_THREAD_CHECK_HA_DAEMON_INTERVAL 1 /* 100ms */
#define LIBHA_IPC_MESSAGE_SEND_TIMEOUT 1000 /* 1sec */

typedef struct libha_thread_cmd {
    gboolean is_quit;
} LIBHA_THREAD_CMD;

typedef struct libha_sync_data {
    pthread_mutex_t mutex;
    enum LIBHA_STATE state;
    struct in_addr local_addr;
    LIBHA_MEMBER_LIST *member_list;

    /*
     * return even_type: 1)local HA down 2)local become master 3)local become slave
     * 4)change master 5)remote up/down
     */
    int event_pool;
} LIBHA_SYNC_DATA;

typedef struct libha_thread_data {
    LIBHA_REGISTER *libha_reg;
    GAsyncQueue *msg_queue;

    LIBHA_SYNC_DATA *sync_data;
    int ha_pid;
} LIBHA_THREAD_DATA;

struct libha {
    LIBHA_REGISTER *libha_reg;
    LIBHA_SYNC_DATA *sync_data;
    GAsyncQueue *msg_queue;
    pthread_t tid;
    int ha_pid;
};

static const char *libha_result_desc[] =
    {
        "ok", /* LIBHA_RESULT_OK */
        "HA not found", /* LIBHA_RESULT_HA_NOT_FOUND */
        "is running", /* LIBHA_RESULT_IS_RUNNING */
        "is stop", /* LIBHA_RESULT_IS_STOP */
        "invalid parameter", /* LIBHA_RESULT_INVALID_PARAM */
        "out of memory", /* LIBHA_RESULT_OUT_OF_MEMORY */
        "internal error", /* LIBHA_RESULT_INTERNAL_ERROR */
        "retry", /* LIBHA_RESULT_RETRY */
        "total", /* LIBHA_RESULT_TOTAL */
    };

static enum LIBHA_RESULT
libha_register_create (LIBHA_REGISTER **libha_reg_p, char *s_name)
{
    LIBHA_REGISTER *libha_reg;

    if (libha_reg_p == NULL || s_name == NULL || strlen (s_name) == 0) {
        return LIBHA_RESULT_INVALID_PARAM;
    }

    libha_reg = (LIBHA_REGISTER *) calloc (1, sizeof (LIBHA_REGISTER));
    if (libha_reg == NULL) {
        return LIBHA_RESULT_OUT_OF_MEMORY;
    }

    libha_reg->pid = getpid();
    snprintf (libha_reg->s_name, SNAME_MAX_LEN, "%s",  s_name);

    *libha_reg_p = libha_reg;

    return LIBHA_RESULT_OK;
}

static void
libha_register_free (LIBHA_REGISTER **libha_reg_p)
{
    LIBHA_REGISTER *libha_reg;

    if (libha_reg_p == NULL) {
        return;
    }

    libha_reg = *libha_reg_p;
    if (libha_reg) {
        free (libha_reg);
    }

    *libha_reg_p = NULL;
}

static LIBHA_REGISTER *
libha_register_clone (LIBHA_REGISTER *libha_reg)
{
    LIBHA_REGISTER *libha_reg_clone;

    if (libha_reg == NULL) {
        return NULL;
    }

    libha_reg_clone = (LIBHA_REGISTER *) calloc (1, sizeof (LIBHA_REGISTER));
    if (libha_reg_clone == NULL) {
        return NULL;
    }

    libha_reg_clone->pid = libha_reg->pid;
    strcpy (libha_reg_clone->s_name, libha_reg->s_name);

    return libha_reg_clone;
}

static gboolean
libha_member_list_copy (LIBHA_MEMBER_LIST **dst_member_list_p,
                        LIBHA_MEMBER_LIST *src_member_list)
{
    if (src_member_list == NULL) {
        return TRUE;
    }

    if (dst_member_list_p == NULL) {
        return FALSE;
    }

    *dst_member_list_p = (LIBHA_MEMBER_LIST *) calloc (1, sizeof (LIBHA_MEMBER_LIST));
    if (*dst_member_list_p == NULL) {
        return FALSE;
    }

    memcpy (&((*dst_member_list_p)->info), &(src_member_list->info), sizeof (LIBHA_MEMBER));
    (*dst_member_list_p)->next = NULL;

    return libha_member_list_copy (&((*dst_member_list_p)->next), src_member_list->next);
}

static LIBHA_MEMBER_LIST *
libha_member_list_clone (LIBHA_MEMBER_LIST *member_list)
{
    LIBHA_MEMBER_LIST *member_list_clone = NULL;

    if (member_list == NULL) {
        return NULL;
    }

    if (libha_member_list_copy (&member_list_clone, member_list) != TRUE) {
        libha_member_list_free (&member_list_clone);
    }

    return member_list_clone;
}

static LIBHA_MEMBER_LIST *
libha_member_list_master_get_by_state (LIBHA_SYNC_DATA *sync_data)
{
    LIBHA_MEMBER_LIST *curr;

    if (sync_data->state == LIBHA_STATE_MASTER) {
        return NULL;
    }

    for (curr = sync_data->member_list; curr; curr = curr->next) {
        if (curr->info.state == LIBHA_STATE_MASTER) {
            return curr;
        }
    }

    return NULL;
}

static LIBHA_MEMBER_LIST *
libha_member_list_master_get_by_addr (LIBHA_SYNC_DATA *sync_data)
{
    LIBHA_MEMBER_LIST *curr = NULL, *ret = NULL;
    struct in_addr addr;

    ret = curr = sync_data->member_list;
    if (curr == NULL) {
        return NULL;
    }

    addr = curr->info.addr;

    for (curr = curr->next; curr; curr = curr->next) {
        if (addr.s_addr > curr->info.addr.s_addr) {
            addr = curr->info.addr;
            ret = curr;
        }
    }

    if (ret->info.addr.s_addr > sync_data->local_addr.s_addr) {
        /* Local address is the smallest */
        return NULL;
    }

    return ret;
}

static void
libha_sync_data_free (LIBHA_SYNC_DATA **sync_data_p)
{
    LIBHA_SYNC_DATA *sync_data;

    if (sync_data_p == NULL) {
        return;
    }

    sync_data = *sync_data_p;

    if (sync_data) {
        libha_member_list_free (&(sync_data->member_list));
        free (sync_data);
    }

    *sync_data_p = NULL;
}

static LIBHA_SYNC_DATA *
libha_sync_data_create (void)
{
    LIBHA_SYNC_DATA *sync_data;

    sync_data = (LIBHA_SYNC_DATA *) calloc (1, sizeof (LIBHA_SYNC_DATA));
    if (sync_data == NULL) {
        return NULL;
    }

    pthread_mutex_init (&(sync_data->mutex), NULL);
    sync_data->state = LIBHA_STATE_SLAVE;

    return sync_data;
}

static void
libha_event_ha_down (LIBHA_SYNC_DATA *sync_data)
{
    pthread_mutex_lock (&(sync_data->mutex));
    LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_HA_DOWN);
    pthread_mutex_unlock (&(sync_data->mutex));
}

static void
libha_state_change (LIBHA_SYNC_DATA *sync_data,
                    enum LIBHA_STATE state)
{
    if (sync_data->state != state) {
        switch (state) {
        case LIBHA_STATE_MASTER:
            LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_TO_MASTER);
            break;
        case LIBHA_STATE_SLAVE:
            LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_TO_SLAVE);
            break;
        default:
            break;
        }

        sync_data->state = state;
    }
}

static void
libha_msg_recv_notify_remote (LIBHA_SYNC_DATA *sync_data,
                              LIBHA_NOTIFY_REMOTE *notify_remote)
{
    LIBHA_MEMBER_LIST *curr, *prev, *member_list, *master_service;

    pthread_mutex_lock (&(sync_data->mutex));

    switch (notify_remote->op_state) {
    case LIBHA_SERVICE_OP_ADD:
        member_list = (LIBHA_MEMBER_LIST *) calloc (1, sizeof (LIBHA_MEMBER_LIST));
        if (member_list == NULL) {
            /* FIXME: How to mark this error */
            goto libha_msg_recv_notify_remote_finish;
        }

        memcpy (&(member_list->info.addr),
                &(notify_remote->addr),
                sizeof (struct in_addr));
        strcpy(member_list->info.hostname, notify_remote->hostname);
        member_list->next = NULL;

        if (sync_data->state == LIBHA_STATE_MASTER) {
            if (sync_data->local_addr.s_addr > notify_remote->addr.s_addr) {
                /* Because remote address is smaller than local, so local
                   state is changed to slave */
                libha_state_change (sync_data, LIBHA_STATE_SLAVE);
                member_list->info.state = LIBHA_STATE_MASTER;
                LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_CHANGE_MASTER);
            } else {
                /* Otherwise, local is still master */
                member_list->info.state = LIBHA_STATE_SLAVE;
            }
        } else { /* Local is slave */
            master_service =
                libha_member_list_master_get_by_state (sync_data);
            if (master_service == NULL) {
                master_service =
                    libha_member_list_master_get_by_addr (sync_data);
            }

            if (master_service == NULL) {
                /* Local shall be master now */
                if (sync_data->local_addr.s_addr > notify_remote->addr.s_addr) {
                    member_list->info.state = LIBHA_STATE_MASTER;
                    LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_CHANGE_MASTER);
                } else {
                    libha_state_change (sync_data, LIBHA_STATE_MASTER);
                    member_list->info.state = LIBHA_STATE_SLAVE;
                }
            } else {
                if (master_service->info.addr.s_addr > notify_remote->addr.s_addr) {
                    /* Because remote address is smaller than master, so master
                       state is changed to slave */
                    master_service->info.state = LIBHA_STATE_SLAVE;
                    member_list->info.state = LIBHA_STATE_MASTER;
                    LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_CHANGE_MASTER);
                } else {
                    /* Otherwise, remote master doesn't changed */
                    member_list->info.state = LIBHA_STATE_SLAVE;
                }
            }
        }

        for (curr = sync_data->member_list; curr; curr = curr->next) {
            if (curr->next == NULL) {
                break;
            }
        }

        if (curr == NULL) {
            sync_data->member_list = member_list;
        } else {
            curr->next = member_list;
        }
        break;
    case LIBHA_SERVICE_OP_DEL:
        if (sync_data->member_list != NULL) {
            prev = sync_data->member_list;
            for (curr = sync_data->member_list; curr; curr = curr->next) {
                if (memcmp (&(curr->info.addr),
                            &(notify_remote->addr),
                            sizeof (struct in_addr)) != 0) {
                    prev = curr;
                    continue;
                }

                if (curr == sync_data->member_list) {
                    sync_data->member_list = curr->next;
                } else {
                    prev->next = curr->next;
                }
                free (curr);

                /* Local HA state was changed too */
                if (sync_data->state != notify_remote->local_state) {
                    libha_state_change (sync_data, notify_remote->local_state);
                }

                break;
            }

            master_service =
                libha_member_list_master_get_by_state (sync_data);
            if (master_service == NULL) {
                /* Master not found, select a new master */
                master_service =
                    libha_member_list_master_get_by_addr (sync_data);

                if (master_service) {
                    master_service->info.state = LIBHA_STATE_MASTER;
                    LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_CHANGE_MASTER);
                } else {
                    /* Only local is existed */
                    libha_state_change (sync_data, LIBHA_STATE_MASTER);
                }
            }
        } else if (sync_data->state != LIBHA_STATE_MASTER) {
            libha_state_change (sync_data, LIBHA_STATE_MASTER);
        }
        break;
    default:
        break;
    }

    LIBHA_EVENT_SET (sync_data->event_pool, LIBHA_EVENT_TYPE_CHANGE_REMOTE);

 libha_msg_recv_notify_remote_finish:

    pthread_mutex_unlock (&(sync_data->mutex));
}

static gboolean
libha_msg_recv_func (LIBHA_THREAD_DATA *thread_data,
                     LIBSOCK_IPC_SERVER *server_ipc)
{
    LIBSOCK_IPC_SERVER_SESSION *session = NULL;
    LIBSOCK_IPC_MESSAGE *recv_msg = NULL;
    struct timeval timestamp;
    long msg_type;
    char *payload;
    size_t len;
    enum LIBSOCK_IPC_RESULT ipc_ret;
    gboolean ret = 0;

    /* Check message available */
    ipc_ret = libsock_ipc_server_msg_recv (server_ipc, &session, &recv_msg);
    if (ipc_ret == LIBSOCK_IPC_RESULT_RETRY) {
        return 1;
    }

    /* Error check */
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        ret = -1;
        goto libha_msg_recv_func_finish;
    }

    ipc_ret = libsock_ipc_msg_info_get (recv_msg, &msg_type, &timestamp);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        ret = -1;
        goto libha_msg_recv_func_finish;
    }

    ipc_ret = libsock_ipc_msg_payload_get (recv_msg, &payload, &len);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        ret = -1;
        goto libha_msg_recv_func_finish;
    }

    switch (msg_type) {
    case LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE:
        libha_msg_recv_notify_remote (thread_data->sync_data,
                                      (LIBHA_NOTIFY_REMOTE *) payload);
        break;
    default:
        /* FIXME: Unknown message type */
        break;
    }

    if (session) {
        /* HA daemon only using "no-reply" message, so ignore it */
        libsock_ipc_server_msg_send_reply_cancel (server_ipc);
        libsock_ipc_server_session_free(&session);
    }

 libha_msg_recv_func_finish:

    if (recv_msg) {
        libsock_ipc_msg_free (&recv_msg);
    }

    return ret;
}

static void *
libha_start_func (void *arg)
{
    LIBHA_THREAD_DATA *thread_data = (LIBHA_THREAD_DATA *) arg;
    LIBHA_THREAD_CMD *cmd;
    LIBHA_REGISTER *libha_reg;
    LIBSOCK_IPC_SERVER *server_ipc = NULL;
    int check_ha_count = LIBHA_THREAD_CHECK_HA_DAEMON_INTERVAL;
    gboolean is_quit = FALSE, is_ha_down = FALSE;
    enum LIBSOCK_IPC_RESULT ret;

    libha_reg = (LIBHA_REGISTER *) thread_data->libha_reg;

    /* Create server path with service name */
    ret = libsock_ipc_server_create (libha_reg->s_name, &server_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        /* FIXME: Error handling */
        goto libha_start_finish;
    }

    while (1) {
        cmd = g_async_queue_try_pop (thread_data->msg_queue);
        if (cmd != NULL) {
            is_quit = cmd->is_quit;
            free (cmd);
        }

        if (is_quit) {
            break;
        }

        if (!is_ha_down) {
            /* Check HA daemon whether is alive */
            check_ha_count--;
            if (check_ha_count == 0) {
                if (is_daemon_alive (thread_data->ha_pid) != 1) {
                    libha_event_ha_down (thread_data->sync_data);
                    is_ha_down = TRUE;
                }

                check_ha_count = LIBHA_THREAD_CHECK_HA_DAEMON_INTERVAL;
            }

            if (!is_ha_down) {
                /* Receive IPC message from HA daemon */
                while (libha_msg_recv_func (thread_data, server_ipc) == 0)
                    ;
            }
        }

        usleep (LIBHA_THREAD_WAIT_TIME);
    }

 libha_start_finish:

    if (server_ipc) {
        libsock_ipc_server_free (&server_ipc);
    }

    if (thread_data) {
        if (thread_data->libha_reg) {
            libha_register_free (&(thread_data->libha_reg));
        }
        free (thread_data);
    }

    pthread_exit (NULL);
}

/* NOTICE: This function isn't thread safe */
static enum LIBHA_RESULT
libha_register_ipc_send (LIBHA *ha)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    LIBHA_REGISTER_REPLY *reply_msg;
    LIBHA_MEMBER *member_array;
    LIBHA_MEMBER_LIST *member_list, *curr, *master_service;
    char *payload;
    size_t i, len, count;
    long msg_type;
    enum LIBSOCK_IPC_RESULT ipc_ret;
    enum LIBHA_RESULT ret = LIBHA_RESULT_OK;

    /* Create IP client socket */
    ipc_ret = libsock_ipc_client_create (&client_ipc);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        return LIBHA_RESULT_INTERNAL_ERROR;
    }

    /* Create IPC message */
    ipc_ret = libsock_ipc_msg_create (LIBHA_MESSAGE_TYPE_REGISTER,
                                      (char *) ha->libha_reg,
                                      sizeof (LIBHA_REGISTER),
                                      &send_msg);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        if (ipc_ret == LIBSOCK_IPC_RESULT_OUT_OF_MEMORY) {
            ret = LIBHA_RESULT_OUT_OF_MEMORY;
        } else {
            ret = LIBHA_RESULT_INTERNAL_ERROR;
        }
        goto libha_register_ipc_send_finish;
    }

    /* Send register IPC message */
    ipc_ret = libsock_ipc_client_msg_send_with_timeout (client_ipc,
                                                        HA_IPC_SERVER_PATH,
                                                        LIBHA_IPC_MESSAGE_SEND_TIMEOUT,
                                                        send_msg,
                                                        &recv_msg);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        if (ipc_ret == LIBSOCK_IPC_RESULT_NOT_READY) {
            ret = LIBHA_RESULT_HA_NOT_FOUND;
        } else {
            ret = LIBHA_RESULT_INTERNAL_ERROR;
        }
        goto libha_register_ipc_send_finish;
    }

    ipc_ret = libsock_ipc_msg_info_get (recv_msg, &msg_type, NULL);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        ret = LIBHA_RESULT_INTERNAL_ERROR;
        goto libha_register_ipc_send_finish;
    }

    /* This reply shall be LIBHA_MESSAGE_TYPE_REGISTER_REPLY */
    if (msg_type != LIBHA_MESSAGE_TYPE_REGISTER_REPLY) {
        ret = LIBHA_RESULT_INTERNAL_ERROR;
        goto libha_register_ipc_send_finish;
    }

    /* Parse feedback payload */
    ipc_ret = libsock_ipc_msg_payload_get (recv_msg, &payload, &len);
    if (ipc_ret != LIBSOCK_IPC_RESULT_OK) {
        ret = LIBHA_RESULT_INTERNAL_ERROR;
        goto libha_register_ipc_send_finish;
    }

    reply_msg = (LIBHA_REGISTER_REPLY *) payload;
    ha->ha_pid = reply_msg->pid;
    ha->sync_data->local_addr = reply_msg->local_addr;
    count = libha_register_reply_msg_count_get (reply_msg);
    if ((reply_msg->payload_len % sizeof (LIBHA_MEMBER)) != 0) {
        /* FIXME: Payload length error? */
        ret = LIBHA_RESULT_INTERNAL_ERROR;
        goto libha_register_ipc_send_finish;
    }
    member_array = (LIBHA_MEMBER *) reply_msg->payload;

    /* FIXME: It shouldn't be empty */
    if (ha->sync_data->member_list) {
        libha_member_list_free (&(ha->sync_data->member_list));
    }

    /* Copy member arary to member list */
    for (i = 0; i < count; i++) {

        member_list = (LIBHA_MEMBER_LIST *) calloc (1, sizeof (LIBHA_MEMBER_LIST));
        if (member_list == NULL) {
            libha_member_list_free (&(ha->sync_data->member_list));
            ret = LIBHA_RESULT_OUT_OF_MEMORY;
            goto libha_register_ipc_send_finish;
        }

        memcpy (&(member_list->info),
                &(member_array[i]),
                sizeof (LIBHA_MEMBER));
        member_list->info.state = LIBHA_STATE_SLAVE;
        member_list->next = NULL;

        if (i == 0) {
            ha->sync_data->member_list = member_list;
        } else {
            curr->next = member_list;
        }
        curr = member_list;
    }

    /* Determine which node shall be master */
    master_service =
        libha_member_list_master_get_by_addr (ha->sync_data);
    if (master_service == NULL) {
        /* Local is master */
        if (ha->sync_data->state != LIBHA_STATE_MASTER) {
            libha_state_change (ha->sync_data, LIBHA_STATE_MASTER);
        }
    } else {
        master_service->info.state = LIBHA_STATE_MASTER;
        LIBHA_EVENT_SET (ha->sync_data->event_pool, LIBHA_EVENT_TYPE_CHANGE_MASTER);
        if (ha->sync_data->state != LIBHA_STATE_SLAVE) {
            libha_state_change (ha->sync_data, LIBHA_STATE_SLAVE);
        }
    }

 libha_register_ipc_send_finish:

    if (send_msg) {
        libsock_ipc_msg_free (&send_msg);
    }

    if (recv_msg) {
        libsock_ipc_msg_free (&recv_msg);
    }

    if (client_ipc) {
        libsock_ipc_client_free (&client_ipc);
    }

    return ret;
}

const char *
libha_result_string_get (enum LIBHA_RESULT ret)
{
    if (ret < LIBHA_RESULT_OK || ret > LIBHA_RESULT_TOTAL) {
        return NULL;
    }

    return libha_result_desc[ret];
}

LIBHA_REGISTER_REPLY *
libha_register_reply_msg_create (int count,
                                 struct in_addr local_addr)
{
    LIBHA_REGISTER_REPLY *reg_reply;
    size_t payload_len;

    if (count < 0) {
        return NULL;
    }

    payload_len = count * sizeof (LIBHA_MEMBER);
    reg_reply =
        (LIBHA_REGISTER_REPLY *) calloc (1, sizeof (LIBHA_REGISTER_REPLY) + payload_len);
    if (reg_reply == NULL) {
        return NULL;
    }

    reg_reply->pid = getpid();
    reg_reply->payload_len = payload_len;
    reg_reply->local_addr = local_addr;
    return reg_reply;
}

void
libha_register_reply_msg_set (LIBHA_REGISTER_REPLY *reg_reply,
                              int pos,
                              LIBHA_MEMBER *member)
{
    LIBHA_MEMBER *member_dst;
    int count;

    if (reg_reply == NULL || member == NULL) {
        return;
    }

    count = libha_register_reply_msg_count_get (reg_reply);
    if (count == 0 || pos < 0 || pos >= count) {
        return;
    }

    member_dst = (LIBHA_MEMBER *) (reg_reply->payload + (pos * sizeof (LIBHA_MEMBER)));
    memcpy (member_dst, member, sizeof (LIBHA_MEMBER));
}

size_t
libha_register_reply_msg_count_get (LIBHA_REGISTER_REPLY *reg_reply)
{
    if (reg_reply == NULL) {
        return 0;
    }

    return (reg_reply->payload_len / sizeof (LIBHA_MEMBER));
}

size_t
libha_register_reply_msg_size_get (LIBHA_REGISTER_REPLY *reg_reply)
{
    if (reg_reply == NULL) {
        return 0;
    }
    return (sizeof (LIBHA_REGISTER_REPLY) + reg_reply->payload_len);
}

enum LIBHA_RESULT
libha_create (LIBHA **ha_p, char *s_name)
{
    LIBHA *ha;
    enum LIBHA_RESULT ret;

    if (ha_p == NULL || s_name == NULL || strlen (s_name) == 0) {
        return LIBHA_RESULT_INVALID_PARAM;
    }

    ha = (LIBHA *) calloc (1, sizeof (LIBHA));
    if (ha == NULL) {
        return LIBHA_RESULT_OUT_OF_MEMORY;
    }

    ha->sync_data = libha_sync_data_create ();
    if (ha->sync_data == NULL) {
        ret = LIBHA_RESULT_OUT_OF_MEMORY;
        goto libha_create_failed;
    }

    ret = libha_register_create (&ha->libha_reg, s_name);
    if (ret != LIBHA_RESULT_OK) {
        goto libha_create_failed;
    }

    *ha_p = ha;

    return LIBHA_RESULT_OK;

 libha_create_failed:

    libha_free (&ha);

    return ret;
}

void
libha_free (LIBHA **ha_p)
{
    LIBHA *ha;

    if (ha_p == NULL) {
        return;
    }

    ha = *ha_p;
    if (ha != NULL) {
        libha_stop (ha);

        if (ha->sync_data) {
            libha_sync_data_free (&(ha->sync_data));
        }
        libha_register_free (&(ha->libha_reg));
        free (ha);
    }

    *ha_p = NULL;
}

/*
 * Notice: a thread was created in libha_run function. libha_stop function
 * will cancel the thread.
 */
enum LIBHA_RESULT
libha_run (LIBHA *ha)
{
    LIBHA_THREAD_DATA *thread_data = NULL;
    enum LIBHA_RESULT ret;

    if (ha == NULL) {
        return LIBHA_RESULT_INVALID_PARAM;
    }

    if (ha->msg_queue != NULL) {
        return LIBHA_RESULT_IS_RUNNING;
    }

    thread_data = (LIBHA_THREAD_DATA *) calloc (1, sizeof (LIBHA_THREAD_DATA));
    if (thread_data == NULL) {
        ret = LIBHA_RESULT_OUT_OF_MEMORY;
        goto libha_run_failed;
    }

    /* Update pid inforatmion */
    ha->libha_reg->pid = getpid();

    thread_data->libha_reg = libha_register_clone (ha->libha_reg);
    if (thread_data->libha_reg == NULL) {
        ret = LIBHA_RESULT_OUT_OF_MEMORY;
        goto libha_run_failed;
    }

    ha->msg_queue = g_async_queue_new ();
    if (ha->msg_queue == NULL) {
        ret = LIBHA_RESULT_OUT_OF_MEMORY;
        goto libha_run_failed;
    }

    thread_data->msg_queue = ha->msg_queue;
    thread_data->sync_data = ha->sync_data;

    ret = libha_register_ipc_send (ha);
    if (ret != LIBHA_RESULT_OK) {
        goto libha_run_failed;
    }

    /* This line shall put after libha_register_ipc_send() */
    thread_data->ha_pid = ha->ha_pid;

    if (pthread_create (&ha->tid, NULL, libha_start_func, thread_data) != 0) {
        ret = LIBHA_RESULT_OUT_OF_MEMORY;
        goto libha_run_failed;
    }

    return LIBHA_RESULT_OK;

 libha_run_failed:

    if (ha->msg_queue) {
        g_async_queue_unref (ha->msg_queue);
        ha->msg_queue = NULL;
    }

    if (thread_data) {
        if (thread_data->libha_reg) {
            libha_register_free (&(thread_data->libha_reg));
        }
        free (thread_data);
    }

    return ret;
}

void
libha_stop (LIBHA *ha)
{
    LIBHA_THREAD_CMD *cmd;

    if (ha == NULL || ha->msg_queue == NULL) {
        return;
    }

    /* Send QUIT command to thread */
    cmd = (LIBHA_THREAD_CMD *) calloc (1, sizeof (LIBHA_THREAD_CMD));
    cmd->is_quit = TRUE;
    g_async_queue_push (ha->msg_queue, cmd);

    /* Wait thread stop */
    pthread_join (ha->tid, NULL);

    memset (&ha->tid, 0, sizeof (pthread_t));

    /* Clear and free the message queue */
    while (1) {
        cmd = g_async_queue_try_pop (ha->msg_queue);
        if (cmd == NULL) {
            break;
        }
        free (cmd);
    }
    g_async_queue_unref (ha->msg_queue);

    ha->msg_queue = NULL;
}

/*
 * Use LIBHA_EVENT_IS_SET marco and enum LIBHA_EVENT_TYPE to get the
 * event type
 */
enum LIBHA_RESULT
libha_event_poll (LIBHA *ha, int *event)
{
    if (ha == NULL || event == NULL) {
        return LIBHA_RESULT_INTERNAL_ERROR;
    }

    if (ha->sync_data == NULL) {
        return LIBHA_RESULT_INTERNAL_ERROR;
    }

    pthread_mutex_lock (&(ha->sync_data->mutex));
    *event = ha->sync_data->event_pool;
    ha->sync_data->event_pool = 0;
    pthread_mutex_unlock (&(ha->sync_data->mutex));

    return LIBHA_RESULT_OK;
}

/*
 * member_list_p shall be freed by upper layer
 */
enum LIBHA_RESULT
libha_member_list_get (LIBHA *ha,
                       LIBHA_MEMBER_LIST **member_list_p)
{
    LIBHA_MEMBER_LIST *member_list;

    if (ha == NULL || member_list_p == NULL) {
        return LIBHA_RESULT_INVALID_PARAM;
    }

    if (ha->sync_data == NULL) {
        return LIBHA_RESULT_INTERNAL_ERROR;
    }

    pthread_mutex_lock (&(ha->sync_data->mutex));
    member_list = libha_member_list_clone (ha->sync_data->member_list);
    pthread_mutex_unlock (&(ha->sync_data->mutex));

    *member_list_p = member_list;

    return LIBHA_RESULT_OK;
}

void
libha_member_list_free (LIBHA_MEMBER_LIST **member_list_p)
{
    LIBHA_MEMBER_LIST *curr, *next;

    if (member_list_p == NULL) {
        return;
    }

    curr = *member_list_p;
    while (curr) {
        next = curr->next;
        free (curr);
        curr = next;
    }

    *member_list_p = NULL;
}

enum LIBHA_RESULT
libha_state_get (LIBHA *ha, enum LIBHA_STATE *state)
{
    if (ha == NULL || state == NULL) {
        return LIBHA_RESULT_INVALID_PARAM;
    }

    if (ha->sync_data == NULL) {
        return LIBHA_RESULT_INTERNAL_ERROR;
    }

    pthread_mutex_lock (&(ha->sync_data->mutex));
    *state = ha->sync_data->state;
    pthread_mutex_unlock (&(ha->sync_data->mutex));

    return LIBHA_RESULT_OK;
}
