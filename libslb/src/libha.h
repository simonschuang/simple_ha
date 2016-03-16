/*
 *              COPYRIGHT (c) 2009-2015  CCMA
 *                     ALL RIGHTS RESERVED
 *
 * Description: HA library header file. A thread is created by 'register_ha'
 * libary and exit when 'unregister_ha' function was called.
 * Filename:    libha.c
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>, Hogan Lee, <s30011w@gmail.com>
 */

#ifndef __LIBHA_H__
#define __LIBHA_H__

#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>

#define HA_IPC_SERVER_PATH "HA_IPC_PATH" /* HA daemon path */
#define SNAME_MAX_LEN 36

#define LIBHA_EVENT_SET(event, event_type) (event |= (0x01 << event_type))
#define LIBHA_EVENT_IS_SET(event, event_type) ((event & (0x01 << event_type)))

/*
 * event: 1)local HA down 2)local become master 3)local become slave
 * 4)change master 5)remote up/down
 */
enum LIBHA_EVENT_TYPE {
    LIBHA_EVENT_TYPE_HA_DOWN = 0,
    LIBHA_EVENT_TYPE_TO_MASTER,
    LIBHA_EVENT_TYPE_TO_SLAVE,
    LIBHA_EVENT_TYPE_CHANGE_MASTER,
    LIBHA_EVENT_TYPE_CHANGE_REMOTE
};

enum LIBHA_RESULT {
    LIBHA_RESULT_OK = 0,
    LIBHA_RESULT_HA_NOT_FOUND,
    LIBHA_RESULT_IS_RUNNING,
    LIBHA_RESULT_IS_STOP,
    LIBHA_RESULT_INVALID_PARAM,
    LIBHA_RESULT_OUT_OF_MEMORY,
    LIBHA_RESULT_INTERNAL_ERROR,
    LIBHA_RESULT_RETRY,
    LIBHA_RESULT_TOTAL
};

enum LIBHA_STATE {
    LIBHA_STATE_MASTER,
    LIBHA_STATE_SLAVE,
};

typedef struct libha LIBHA;

#define LIBHA_HOSTNAME_LEN 50

typedef struct libha_member LIBHA_MEMBER;
struct libha_member {
    struct in_addr addr;
    char hostname[LIBHA_HOSTNAME_LEN];
    enum LIBHA_STATE state;
} __attribute__ ((__packed__));

typedef struct libha_member_list LIBHA_MEMBER_LIST;
struct libha_member_list {
    LIBHA_MEMBER info;
    LIBHA_MEMBER_LIST *next;
};

/* ============== For IPC using ============== */
enum LIBHA_MESSAGE_TYPE {
    LIBHA_MESSAGE_TYPE_REGISTER = 200,
    LIBHA_MESSAGE_TYPE_REGISTER_REPLY,
    LIBHA_MESSAGE_TYPE_NOTIFY_REMOTE
};

enum LIBHA_SERVICE_OP {
    LIBHA_SERVICE_OP_ADD,
    LIBHA_SERVICE_OP_DEL
};

typedef struct libha_register LIBHA_REGISTER;
struct libha_register {
    int pid; /* Upper layer daemon's PID */
    char s_name[SNAME_MAX_LEN];
} __attribute__ ((__packed__));

typedef struct libha_register_reply LIBHA_REGISTER_REPLY;
struct libha_register_reply {
    enum LIBHA_STATE ha_state;
    int pid; /* HA daemon's PID */
    struct in_addr local_addr;
    size_t payload_len;
    char payload[0]; /* LIBHA_MEMBER array */
} __attribute__ ((__packed__));

typedef struct libha_notify_remote LIBHA_NOTIFY_REMOTE;
struct libha_notify_remote {
    enum LIBHA_SERVICE_OP op_state;
    struct in_addr addr;
    char hostname[LIBHA_HOSTNAME_LEN];
    enum LIBHA_STATE remote_state; /* Remote HA state */
    enum LIBHA_STATE local_state; /* Local HA state */
} __attribute__ ((__packed__));
/* =========================================== */

const char *
libha_result_string_get (enum LIBHA_RESULT ret);

LIBHA_REGISTER_REPLY *
libha_register_reply_msg_create (int count,
                                 struct in_addr local_addr);

void
libha_register_reply_msg_set (LIBHA_REGISTER_REPLY *reg_reply,
                              int pos,
                              LIBHA_MEMBER *member);

size_t
libha_register_reply_msg_count_get (LIBHA_REGISTER_REPLY *reg_reply);

size_t
libha_register_reply_msg_size_get (LIBHA_REGISTER_REPLY *reg_reply);

enum LIBHA_RESULT
libha_create (LIBHA **ha_p, char *s_name);

void
libha_free (LIBHA **ha_p);

/*
 * Notice: a thread was created in libha_run function. libha_stop function
 * will cancel the thread.
 */
enum LIBHA_RESULT
libha_run (LIBHA *ha);

void
libha_stop (LIBHA *ha);

/*
 * Use LIBHA_EVENT_IS_SET marco and enum LIBHA_EVENT_TYPE to get the
 * event type
 */
enum LIBHA_RESULT
libha_event_poll (LIBHA *ha, int *event);

/*
 * member_list_p shall be freed by upper layer
 */
enum LIBHA_RESULT
libha_member_list_get (LIBHA *ha,
                       LIBHA_MEMBER_LIST **member_list_p);

void
libha_member_list_free (LIBHA_MEMBER_LIST **member_list_p);

enum LIBHA_RESULT
libha_state_get (LIBHA *ha, enum LIBHA_STATE *state);

#endif
