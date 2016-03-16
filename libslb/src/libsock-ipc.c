#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <assert.h>
#include <glib.h>

#include "libsock-ipc.h"

#define LIBSOCK_MESSAGE_ID "slb-ipc"
#define LIBSOCK_IPC_SOCKET_DIR "/tmp"
#define LIBSOCK_MAX_CONNECTION 128
#define LIBSOCK_SERVER_DEFAULT_TIMEOUT 1000 /* millisecond */
#define LIBSOCK_CLIENT_DEFAULT_TIMEOUT 1000 /* millisecond */
#define LIBSOCK_MIN_WAIT_TIME 100 /* millisecond */
#define LIBSOCK_MSG_CHECKSUM_INTERVAL 16 /* The performace is good enough while using 16 */

struct LIBSOCK_IPC_MESSAGE {
    char id[8];
    unsigned int checksum; /* For checking payload */
    struct timeval timestamp;
    int is_need_reply;
    unsigned int tid; /* transaction_id */
    long msg_type;
    size_t len; /* payload length */
    char payload[0];
} __attribute__ ((__packed__));
#define LIBSOCK_IPC_MESSAGE_LEN(len) (sizeof (LIBSOCK_IPC_MESSAGE) + (len))

struct LIBSOCK_IPC_SERVER_SESSION {
    unsigned int tid; /* transaction_id */
};

struct LIBSOCK_IPC_SERVER {
    char *path;
    struct {
        int sock;
    } server;

    struct {
        int sock;
        unsigned int tid;
    } client;
};

struct LIBSOCK_IPC_CLIENT_SESSION {
    char *path;
    unsigned int tid; /* transaction_id */
    int sock;
};

struct LIBSOCK_IPC_CLIENT {
    unsigned int tid_sn;

    /* All of the sessions shall be maintain by this list */
    GList *session_list; /* LIBSOCK_IPC_CLIENT_SESSION */
};

static const char *libsock_ipc_result_desc[] =
    {
        "none", /* LIBSOCK_IPC_RESULT_NONE */
        "ok", /* LIBSOCK_IPC_RESULT_OK */
        "retry", /* LIBSOCK_IPC_RESULT_RETRY */
        "not ready", /* LIBSOCK_IPC_RESULT_NOT_READY */
        "session not found", /* LIBSOCK_IPC_RESULT_SESSION_NOT_FOUND */
        "session is busy", /* LIBSOCK_IPC_RESULT_SESSION_BUSY */
        "connection lose", /* LIBSOCK_IPC_RESULT_CONNECTION_LOSE */
        "connection timeout", /* LIBSOCK_IPC_RESULT_CONNECTION_TIMEOUT */
        "client session pending", /* LIBSOCK_IPC_RESULT_CLIENT_SESSION_PENDING */
        "unknown message", /* LIBSOCK_IPC_RESULT_UNKNOWN_MSG */
        "out of memory", /* LIBSOCK_IPC_RESULT_OUT_OF_MEMORY */
        "parameter error", /* LIBSOCK_IPC_RESULT_PARAMETER_ERROR */
        "socket create error", /* LIBSOCK_IPC_RESULT_SOCKET_CREATE_ERROR */
        "internal error", /* LIBSOCK_IPC_RESULT_INTERNAL_ERROR */
        "total" /* LIBSOCK_IPC_RESULT_TOTAL */
    };

/* ========================== Private function ========================== */

/* timeout: millisecond */
/* return: TRUE:timeout, FALSE:not timeout */
static gboolean
timeval_timeout_check (const struct timeval *begin,
                       long timeout)
{
    struct timeval now;
    long start, end;

    if (begin == NULL) {
        return FALSE;
    }

    gettimeofday (&now, NULL);
    start = (now.tv_sec * 1000) + (now.tv_usec / 1000);
    end = ((begin->tv_sec * 1000) + (begin->tv_usec / 1000)) + timeout;

    return (end <= start) ? TRUE : FALSE;
}

static int
libsock_ipc_unix_sock_create (const char *path,
                              gboolean is_server,
                              gboolean is_nonblock,
                              struct sockaddr_un *addr_un)
{
    int sock;
    char *real_path = NULL;

    if (path == NULL || strlen (path) == 0 || addr_un == NULL) {
        return -1;
    }

    real_path = g_strdup_printf ("%s/%s", LIBSOCK_IPC_SOCKET_DIR, path);
    if (real_path == NULL) {
        return -1;
    }

    /* Remove the path file and ignore the error */
    if (is_server) {
        unlink (real_path);
    }

    sock = socket (AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        goto libsock_ipc_unix_sock_create_finish;
    }

    if (is_nonblock) {
        /* Non-blocking mode */
        fcntl (sock,
               F_SETFL,
               O_NONBLOCK | fcntl (sock, F_GETFL, 0));
    }

    addr_un->sun_family = AF_UNIX;
    strcpy (addr_un->sun_path, real_path);

 libsock_ipc_unix_sock_create_finish:

    if (real_path) {
        free (real_path);
    }

    return sock;
}

static unsigned int
libsock_ipc_checksum_generate (char *payload, size_t len)
{
    unsigned int checksum = 0, offset = 0;
    char *data_p;

    data_p = payload;
    while (offset <= len - 1) {
        checksum += *data_p;
        data_p += LIBSOCK_MSG_CHECKSUM_INTERVAL;
        offset += LIBSOCK_MSG_CHECKSUM_INTERVAL;
    }

    return checksum;
}

static gboolean
libsock_ipc_msg_header_check (const LIBSOCK_IPC_MESSAGE *msg)
{
    if (msg == NULL) {
        return FALSE;
    }

    /* message id */
    if (strcmp (msg->id, LIBSOCK_MESSAGE_ID) != 0) {
        return FALSE;
    }

    /* transactoin id */
    if (msg->tid == 0) {
        return FALSE;
    }

    return TRUE;
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_header_recv (int sock,
                             LIBSOCK_IPC_MESSAGE **msg_p,
                             struct timeval *start,
                             long timeout)
{
    LIBSOCK_IPC_MESSAGE *msg, *msg_tmp;
    int size = 0, count = 0, len = 0;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_OK;

    if (msg_p == NULL) {
        return LIBSOCK_IPC_RESULT_INTERNAL_ERROR;
    }

    msg = (LIBSOCK_IPC_MESSAGE *) calloc (1, LIBSOCK_IPC_MESSAGE_LEN (0));
    if (msg == NULL) {
        return LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
    }

    while (1) {
        /* Sometimes, the recv will cause process crash because SIGPIPE
           not be handled */
        size = recv (sock,
                     (void *) ((char *) msg + count),
                     LIBSOCK_IPC_MESSAGE_LEN (0) - count,
                     0);
        if (size <= 0) {
            if (errno != EAGAIN) {
                ret = LIBSOCK_IPC_RESULT_CONNECTION_LOSE;
                goto libsock_ipc_msg_header_recv_err;
            }
        } else {
            /* Reset the timer */
            gettimeofday (start, NULL);
            count += size;
        }

        if (count > LIBSOCK_IPC_MESSAGE_LEN (0)) {
            /* FIXME: what happen? */
            assert (count <= LIBSOCK_IPC_MESSAGE_LEN (0));
            break;
        }

        if (count == LIBSOCK_IPC_MESSAGE_LEN (0)) {
            break;
        }

        if (timeval_timeout_check (start, timeout) == TRUE) {
            /* Timeout */
            ret = LIBSOCK_IPC_RESULT_CONNECTION_TIMEOUT;
            goto libsock_ipc_msg_header_recv_err;
        }
        usleep (1);
    }

    if (libsock_ipc_msg_header_check (msg) == FALSE) {
        /* The message header isn't corrected */
        ret = LIBSOCK_IPC_RESULT_UNKNOWN_MSG;
        goto libsock_ipc_msg_header_recv_err;
    } 

    len = msg->len;
    msg_tmp = (LIBSOCK_IPC_MESSAGE *) realloc (msg, LIBSOCK_IPC_MESSAGE_LEN (len));
    if (msg_tmp == NULL) {
        ret = LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
        goto libsock_ipc_msg_header_recv_err;
    }
    memset (msg_tmp->payload, 0, len);

    if (msg != msg_tmp) {
        msg = msg_tmp;
    }
    *msg_p = msg;

    return LIBSOCK_IPC_RESULT_OK;

 libsock_ipc_msg_header_recv_err:

    if (msg) {
        free (msg);
    }

    return ret;
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_payload_recv (int sock,
                              LIBSOCK_IPC_MESSAGE *msg,
                              struct timeval *start,
                              long timeout)
{
    unsigned int checksum;
    int size, count = 0;

    while (1) {
        /* Sometimes, the recv will cause process crash because SIGPIPE
           not be handled */
        size = recv (sock,
                     (void *) (msg->payload + count),
                     msg->len - count,
                     0);
        if (size <= 0) {
            if (errno != EAGAIN) {
                return LIBSOCK_IPC_RESULT_CONNECTION_LOSE;
            }
        } else {
            /* Reset the timer */
            gettimeofday (start, NULL);
            count += size;
        }

        if (count > msg->len) {
            /* FIXME: what happen? */
            assert (count <= msg->len);
            break;
        }

        if (count == msg->len) {
            break;
        }

        if (timeval_timeout_check (start, timeout) == TRUE) {
            /* Timeout */
            return LIBSOCK_IPC_RESULT_CONNECTION_TIMEOUT;
        }
        usleep (1);
    }

    checksum = libsock_ipc_checksum_generate (msg->payload, msg->len);
    if (checksum != msg->checksum) {
        return LIBSOCK_IPC_RESULT_UNKNOWN_MSG;
    }

    return LIBSOCK_IPC_RESULT_OK;
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_recv (int sock,
                      LIBSOCK_IPC_MESSAGE **msg_p,
                      struct timeval *start,
                      long timeout)
{
    enum LIBSOCK_IPC_RESULT ret;

    /* Try to receive message header */
    ret = libsock_ipc_msg_header_recv (sock,
                                       msg_p,
                                       start,
                                       timeout);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        return ret;
    }

    /* Message header is ok, then try to receive message payload */
    ret = libsock_ipc_msg_payload_recv (sock,
                                        *msg_p,
                                        start,
                                        timeout);
    return ret;
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_send_real (int sock,
                           LIBSOCK_IPC_MESSAGE *msg,
                           struct timeval *start,
                           long timeout)
{
    int count = 0, size = 0;

    while (1) {
        /* Sometimes, the send will cause process crash because SIGPIPE
           not be handled */
        size = send (sock,
                     (char *) msg + count,
                     LIBSOCK_IPC_MESSAGE_LEN (msg->len) - count,
                     0);
        if (size <= 0) {
            if (errno == EAGAIN) {
                if (timeout == 0) {
                    return LIBSOCK_IPC_RESULT_RETRY;
                }
            } else {
                return LIBSOCK_IPC_RESULT_CONNECTION_LOSE;
            }
        } else {
            /* Reset the timer */
            gettimeofday (start, NULL);
            count += size;
        }

        if (count > LIBSOCK_IPC_MESSAGE_LEN (msg->len)) {
            /* FIXME: what happen? */
            assert (count <= LIBSOCK_IPC_MESSAGE_LEN (msg->len));
            break;
        }

        if (count == LIBSOCK_IPC_MESSAGE_LEN (msg->len)) {
            break;
        }

        if (timeval_timeout_check (start, timeout) == TRUE) {
            /* Timeout */
            return LIBSOCK_IPC_RESULT_CONNECTION_TIMEOUT;
        }
        usleep (1);
    }

    return LIBSOCK_IPC_RESULT_OK;
}

static void
libsock_ipc_server_socket_server_close (LIBSOCK_IPC_SERVER *server_ipc)
{
    if (server_ipc == NULL) {
        return;
    }

    if (server_ipc->server.sock != -1) {
        close (server_ipc->server.sock);
        server_ipc->server.sock = -1;
    }
}

static void
libsock_ipc_server_socket_client_close (LIBSOCK_IPC_SERVER *server_ipc)
{
    if (server_ipc == NULL) {
        return;
    }

    if (server_ipc->client.sock != -1) {
        close (server_ipc->client.sock);
        server_ipc->client.sock = -1;
    }

    server_ipc->client.tid = 0;
}

static void
libsock_ipc_client_session_free_real (LIBSOCK_IPC_CLIENT_SESSION **session_p,
                                      gboolean is_close_sock)
{
    LIBSOCK_IPC_CLIENT_SESSION *session;

    if (session_p == NULL) {
        return;
    }

    session = *session_p;
    if (session != NULL) {
        if (session->path) {
            free (session->path);
        }

        if (is_close_sock &&
            session->sock != -1) {
            close (session->sock);
        }

        free (session);
    }

    *session_p = NULL;
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_client_session_create (const char *path,
                                   unsigned int tid,
                                   int sock,
                                   LIBSOCK_IPC_CLIENT_SESSION **session_p)
{
    LIBSOCK_IPC_CLIENT_SESSION *session;
    enum LIBSOCK_IPC_RESULT ret;

    if (path == NULL || strlen (path) == 0 || tid == 0 ||
        sock == -1 || session_p == NULL) {
        return LIBSOCK_IPC_RESULT_INTERNAL_ERROR;
    }

    session =
        (LIBSOCK_IPC_CLIENT_SESSION *) calloc (1, sizeof (LIBSOCK_IPC_CLIENT_SESSION));
    if (session == NULL) {
        return LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
    }

    session->path = strdup (path);
    if (session->path == NULL) {
        ret = LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
        goto libsock_ipc_client_session_create_err;
    }

    session->tid = tid;
    session->sock = sock;
    *session_p = session;

    return LIBSOCK_IPC_RESULT_OK;

 libsock_ipc_client_session_create_err:

    libsock_ipc_client_session_free_real (&session, FALSE);

    return ret;
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_client_session_clone (LIBSOCK_IPC_CLIENT_SESSION *from_session,
                                  LIBSOCK_IPC_CLIENT_SESSION **to_session_p)
{
    if (from_session == NULL || to_session_p == NULL) {
        return LIBSOCK_IPC_RESULT_INTERNAL_ERROR;
    }

    return libsock_ipc_client_session_create (from_session->path,
                                              from_session->tid,
                                              from_session->sock,
                                              to_session_p);
}

static unsigned int
libsock_ipc_client_tid_generate (LIBSOCK_IPC_CLIENT *client_ipc)
{
    if (client_ipc == NULL) {
        return 0;
    }

    client_ipc->tid_sn++;
    if (client_ipc->tid_sn == 0) {
        client_ipc->tid_sn++;
    }

    return client_ipc->tid_sn;
}

static gint
libsock_ipc_client_session_compare_func (gconstpointer a, gconstpointer b)
{
    LIBSOCK_IPC_CLIENT_SESSION *session_a, *session_b;

    session_a = (LIBSOCK_IPC_CLIENT_SESSION *) a;
    session_b = (LIBSOCK_IPC_CLIENT_SESSION *) b;

    return strcmp (session_a->path, session_b->path);
}

static gint
libsock_ipc_client_session_find_by_path (gconstpointer a, gconstpointer b)
{
    LIBSOCK_IPC_CLIENT_SESSION *session;
    const char *path;

    session = (LIBSOCK_IPC_CLIENT_SESSION *) a;
    path = (char *) b;

    return strcmp (session->path, path);
}

static enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_real (LIBSOCK_IPC_CLIENT *client_ipc,
                                  gboolean is_need_reply,
                                  const char *to_path,
                                  struct timeval *start,
                                  long timeout,
                                  LIBSOCK_IPC_MESSAGE *send_msg,
                                  LIBSOCK_IPC_CLIENT_SESSION **session_p)
{
    int sock;
    int len;
    struct sockaddr_un addr_un;
    LIBSOCK_IPC_CLIENT_SESSION *session;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_OK;

    if (client_ipc == NULL || to_path == NULL || send_msg == NULL) {
        return LIBSOCK_IPC_RESULT_INTERNAL_ERROR;
    }

    if (is_need_reply && session_p == NULL) {
        return LIBSOCK_IPC_RESULT_INTERNAL_ERROR;
    }

    /* Is last session done */
    if (g_list_find_custom (client_ipc->session_list,
                            to_path,
                            libsock_ipc_client_session_find_by_path) != NULL) {
        return LIBSOCK_IPC_RESULT_SESSION_BUSY;
    }

    sock = libsock_ipc_unix_sock_create (to_path,
                                         FALSE,
                                         TRUE,
                                         &addr_un);
    if (sock == -1) {
        return LIBSOCK_IPC_RESULT_SOCKET_CREATE_ERROR;
    }

    len = strlen (addr_un.sun_path) + sizeof (addr_un.sun_family);

    while (1) {
        if (connect (sock,
                     (struct sockaddr *) &addr_un,
                     len) == -1) {
            if (errno == EAGAIN) {
                if (timeout == 0) {
                    ret = LIBSOCK_IPC_RESULT_RETRY;
                    goto libsock_ipc_client_msg_send_finish;
                }
            } else {
                ret = LIBSOCK_IPC_RESULT_NOT_READY;
                goto libsock_ipc_client_msg_send_finish;
            }
        } else {
            /* Reset the timer */
            gettimeofday (start, NULL);
            break;
        }

        if (timeval_timeout_check (start, timeout) == TRUE) {
            ret = LIBSOCK_IPC_RESULT_NOT_READY;
            goto libsock_ipc_client_msg_send_finish;
        }
        usleep (1);
    }

    gettimeofday (&(send_msg->timestamp), NULL);
    send_msg->is_need_reply = is_need_reply;
    send_msg->tid = libsock_ipc_client_tid_generate (client_ipc);
    send_msg->checksum = libsock_ipc_checksum_generate (send_msg->payload, send_msg->len);

    ret = libsock_ipc_msg_send_real (sock, send_msg, start, timeout);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        goto libsock_ipc_client_msg_send_finish;
    }

    if (is_need_reply) {
        ret = libsock_ipc_client_session_create (to_path,
                                                 send_msg->tid,
                                                 sock,
                                                 session_p);
        if (ret != LIBSOCK_IPC_RESULT_OK) {
            goto libsock_ipc_client_msg_send_finish;
        }

        ret = libsock_ipc_client_session_clone (*session_p, &session);
        if (ret != LIBSOCK_IPC_RESULT_OK) {
            libsock_ipc_client_session_free_real (session_p, FALSE);
            goto libsock_ipc_client_msg_send_finish;
        }

        /* Add to session list */
        client_ipc->session_list =
            g_list_insert_sorted (client_ipc->session_list,
                                  session,
                                  libsock_ipc_client_session_compare_func);

        return LIBSOCK_IPC_RESULT_OK;
    }

 libsock_ipc_client_msg_send_finish:

    if (sock != -1) {
        close (sock);
    }

    return ret;
}

/* ====================== Publice function ============================== */
const char *
libsock_ipc_result_string_get (enum LIBSOCK_IPC_RESULT ret) {
    if (ret < LIBSOCK_IPC_RESULT_NONE || ret > LIBSOCK_IPC_RESULT_TOTAL) {
        return NULL;
    }

    return libsock_ipc_result_desc[ret];
}

/* ================= Publice function - IPC MSG ========================= */
enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_create (long msg_type,
                        const char *payload,
                        size_t len,
                        LIBSOCK_IPC_MESSAGE **msg_p)
{
    LIBSOCK_IPC_MESSAGE *msg;

    if (payload == NULL || len <= 0 || msg_p == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    msg = (LIBSOCK_IPC_MESSAGE *) calloc (1, LIBSOCK_IPC_MESSAGE_LEN (len));
    if (msg == NULL) {
        return LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
    }

    /* Message ID: for checking message header */
    snprintf (msg->id, sizeof (msg->id), "%s", LIBSOCK_MESSAGE_ID);

    msg->msg_type = msg_type;
    msg->len = len;
    memcpy (msg->payload, payload, len);

    *msg_p = msg;

    return LIBSOCK_IPC_RESULT_OK;
}

void
libsock_ipc_msg_free (LIBSOCK_IPC_MESSAGE **msg_p)
{
    LIBSOCK_IPC_MESSAGE *msg;

    if (msg_p == NULL) {
        return;
    }

    msg = *msg_p;
    if (msg != NULL) {
        free (msg);
    }
    *msg_p = NULL;
}

/*
 * Each information pointers could be assigned NULL, it means you don't care
 * this information
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_info_get (LIBSOCK_IPC_MESSAGE *msg,
                          long *msg_type,
                          struct timeval *timestamp)
{
    if (msg == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    if (msg_type) {
        *msg_type = msg->msg_type;
    }

    if (timestamp) {
        *timestamp = msg->timestamp;
    }

    return LIBSOCK_IPC_RESULT_OK;
}

/*
 * payload: DO NOT free pointer
 * len: payload length
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_payload_get (LIBSOCK_IPC_MESSAGE *msg,
                             char **payload,
                             size_t *len)
{
    if (msg == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    if (payload != NULL) {
        *payload = msg->payload;
    }

    if (len != NULL) {
        *len = msg->len;
    }

    return LIBSOCK_IPC_RESULT_OK;
}

/* ================= Publice function - IPC SERVER ====================== */
/*
 * path: This IPC server path
 * server_ipc_p: server handle
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_create (const char *path,
                           LIBSOCK_IPC_SERVER **server_ipc_p)
{
    LIBSOCK_IPC_SERVER *server_ipc;
    struct sockaddr_un addr_un;
    int len;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_OK;

    if (path == NULL || strlen (path) == 0 ||
        server_ipc_p == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    server_ipc = (LIBSOCK_IPC_SERVER *) calloc (1, sizeof (LIBSOCK_IPC_SERVER));
    if (server_ipc == NULL) {
        return LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
    }

    server_ipc->path = strdup (path);
    if (server_ipc->path == NULL) {
        ret = LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
        goto libsock_ipc_server_create_err;
    }

    server_ipc->server.sock =
        libsock_ipc_unix_sock_create (path,
                                      TRUE,
                                      TRUE,
                                      &addr_un);
    if (server_ipc->server.sock == -1) {
        ret = LIBSOCK_IPC_RESULT_SOCKET_CREATE_ERROR;
        goto libsock_ipc_server_create_err;
    }

    len = strlen (addr_un.sun_path) + sizeof (addr_un.sun_family);
    if (bind (server_ipc->server.sock,
              (struct sockaddr *) &addr_un,
              len) == -1) {
        ret = LIBSOCK_IPC_RESULT_SOCKET_CREATE_ERROR;
        goto libsock_ipc_server_create_err;
    }

    if (listen(server_ipc->server.sock, LIBSOCK_MAX_CONNECTION) == -1) {
        ret = LIBSOCK_IPC_RESULT_SOCKET_CREATE_ERROR;
        goto libsock_ipc_server_create_err;
    }

    server_ipc->client.sock = -1;

    *server_ipc_p = server_ipc;

    return LIBSOCK_IPC_RESULT_OK;

 libsock_ipc_server_create_err:

    if (server_ipc) {
        libsock_ipc_server_free (&server_ipc);
    }

    return ret;
}

void
libsock_ipc_server_free (LIBSOCK_IPC_SERVER **server_ipc_p)
{
    LIBSOCK_IPC_SERVER *server_ipc;

    if (server_ipc_p == NULL) {
        return;
    }

    server_ipc = *server_ipc_p;
    if (server_ipc != NULL) {
        libsock_ipc_server_socket_client_close (server_ipc);
        libsock_ipc_server_socket_server_close (server_ipc);

        if (server_ipc->path) {
            free (server_ipc->path);
        }

        free (server_ipc);
    }

    *server_ipc_p = NULL;
}

/*
 * session_p: for sending reply using, if the session pointer isn't NULL,
 * then the reply shall be sent (this pointer shall be freed by upper layer)
 * recv_msg_p: receive message from client, this pointer shall be
 * freed by upper layer
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_msg_recv (LIBSOCK_IPC_SERVER *server_ipc,
                             LIBSOCK_IPC_SERVER_SESSION **session_p,
                             LIBSOCK_IPC_MESSAGE **recv_msg_p)
{
    LIBSOCK_IPC_MESSAGE *msg = NULL;
    LIBSOCK_IPC_SERVER_SESSION *session = NULL;
    struct sockaddr_un client_addr;
    socklen_t client_sock_len;
    struct timeval start;
    enum LIBSOCK_IPC_RESULT ret;

    if (server_ipc == NULL || session_p == NULL || recv_msg_p == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    if (server_ipc->client.sock != -1) {
        return LIBSOCK_IPC_RESULT_CLIENT_SESSION_PENDING;
    }

    client_sock_len = sizeof (client_addr);

    server_ipc->client.sock =
        accept(server_ipc->server.sock,
               (struct sockaddr *) &client_addr,
               &client_sock_len);
    if (server_ipc->client.sock == -1) {
        /* No any connection */
        return LIBSOCK_IPC_RESULT_RETRY;
    }

    gettimeofday (&start, NULL);
    ret = libsock_ipc_msg_recv (server_ipc->client.sock,
                                &msg, /* this pointer maybe modified */
                                &start,
                                LIBSOCK_SERVER_DEFAULT_TIMEOUT);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        goto libsock_ipc_server_msg_recv_err;
    }

    /* Payload is ok */
    if (msg->is_need_reply) {
        session =
            (LIBSOCK_IPC_SERVER_SESSION *) calloc (1, sizeof (LIBSOCK_IPC_SERVER_SESSION));
        if (session == NULL) {
            ret = LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
            goto libsock_ipc_server_msg_recv_err;
        }
        session->tid = msg->tid;
        *session_p = session;

        /* Remember this tid for sending reply */
        server_ipc->client.tid = msg->tid;

        *recv_msg_p = msg;

        return LIBSOCK_IPC_RESULT_OK;
    }
    else {
        *recv_msg_p = msg;

        libsock_ipc_server_socket_client_close (server_ipc);

        return LIBSOCK_IPC_RESULT_OK;
    }

 libsock_ipc_server_msg_recv_err:

    if (msg != NULL) {
        libsock_ipc_msg_free (&msg);
    }

    if (session != NULL) {
        libsock_ipc_server_session_free (&session);
    }

    libsock_ipc_server_socket_client_close (server_ipc);

    return ret;
}

/*
 * session: for sending reply
 * send_msg: send reply to client
 * timeout: millisecond
 * NOTICE: if message shall be replied, then you HAVE TO use this
 * function to send reply
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_msg_send_reply_with_timeout (LIBSOCK_IPC_SERVER *server_ipc,
                                                const LIBSOCK_IPC_SERVER_SESSION *session,
                                                LIBSOCK_IPC_MESSAGE *send_msg,
                                                long timeout)
{
    struct timeval start;
    enum LIBSOCK_IPC_RESULT ret;

    if (server_ipc == NULL || session == NULL || send_msg == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    if (session->tid != server_ipc->client.tid) {
        return LIBSOCK_IPC_RESULT_SESSION_NOT_FOUND;
    }

    send_msg->tid = server_ipc->client.tid;
    send_msg->checksum = libsock_ipc_checksum_generate (send_msg->payload, send_msg->len);

    gettimeofday (&start, NULL);
    ret = libsock_ipc_msg_send_real (server_ipc->client.sock,
                                     send_msg,
                                     &start,
                                     timeout);

    if (ret != LIBSOCK_IPC_RESULT_OK) {
        return ret;
    }

    libsock_ipc_server_socket_client_close (server_ipc);

    return LIBSOCK_IPC_RESULT_OK;
}

/*
 * session: for sending reply
 * send_msg: send reply to client
 * NOTICE: if message shall be replied, then you HAVE TO use this
 * function to send reply
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_msg_send_reply (LIBSOCK_IPC_SERVER *server_ipc,
                                   const LIBSOCK_IPC_SERVER_SESSION *session,
                                   LIBSOCK_IPC_MESSAGE *send_msg)
{
    return libsock_ipc_server_msg_send_reply_with_timeout (server_ipc,
                                                           session,
                                                           send_msg,
                                                           LIBSOCK_MIN_WAIT_TIME);
}

void
libsock_ipc_server_msg_send_reply_cancel (LIBSOCK_IPC_SERVER *server_ipc)
{
    if (server_ipc == NULL) {
        return;
    }

    libsock_ipc_server_socket_client_close (server_ipc);
}

void
libsock_ipc_server_session_free (LIBSOCK_IPC_SERVER_SESSION **session_p)
{
    LIBSOCK_IPC_SERVER_SESSION *session;

    if (session_p == NULL) {
        return;
    }

    session = *session_p;
    if (session) {
        free (session);
    }

    *session_p = NULL;
}

/* ================= Publice function - IPC CLIENT ====================== */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_create (LIBSOCK_IPC_CLIENT **client_ipc_p)
{
    LIBSOCK_IPC_CLIENT *client_ipc;
    GRand *rand;

    if (client_ipc_p == NULL) {
        return LIBSOCK_IPC_RESULT_PARAMETER_ERROR;
    }

    client_ipc = (LIBSOCK_IPC_CLIENT *) calloc (1, sizeof (LIBSOCK_IPC_CLIENT));
    if (client_ipc == NULL) {
        return LIBSOCK_IPC_RESULT_OUT_OF_MEMORY;
    }

    rand = g_rand_new();
    if (rand) {
        client_ipc->tid_sn = g_rand_int (rand);
        g_rand_free (rand);
    } else {
        client_ipc->tid_sn = g_random_int ();
    }
    *client_ipc_p = client_ipc;

    return LIBSOCK_IPC_RESULT_OK;
}

void
libsock_ipc_client_free (LIBSOCK_IPC_CLIENT **client_ipc_p)
{
    LIBSOCK_IPC_CLIENT *client_ipc;
    GList *list;

    if (client_ipc_p == NULL) {
        return;
    }

    client_ipc = *client_ipc_p;
    if (client_ipc != NULL) {
        while ((list = g_list_first (client_ipc->session_list))) {
            if (list->data) {
                libsock_ipc_client_session_free_real ((LIBSOCK_IPC_CLIENT_SESSION **) &(list->data),
                                                      TRUE);
            }
            client_ipc->session_list = g_list_delete_link (client_ipc->session_list, list);
        }

        free (client_ipc);
    }

    *client_ipc_p = NULL;
}

/*
 * Send message and don't wait reply (For notification)
 * to_path: which daemon shall receive this message
 * send_msg: The message will be sent to server
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_with_no_reply (LIBSOCK_IPC_CLIENT *client_ipc,
                                           const char *to_path,
                                           LIBSOCK_IPC_MESSAGE *send_msg)
{
    struct timeval start;
    gettimeofday (&start, NULL);

    return libsock_ipc_client_msg_send_real (client_ipc,
                                             FALSE,
                                             to_path,
                                             &start,
                                             LIBSOCK_MIN_WAIT_TIME,
                                             send_msg,
                                             NULL);
}

/*
 * Send message and wait reply synchronize
 * to_path: which daemon shall receive this message
 * timeout: millisecond.
 * send_msg: The message will be sent to server from client
 * recv_msg_p: receive message from server, this pointer shall be
 * freed by upper layer
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_with_timeout (LIBSOCK_IPC_CLIENT *client_ipc,
                                          const char *to_path,
                                          long timeout,
                                          LIBSOCK_IPC_MESSAGE *send_msg,
                                          LIBSOCK_IPC_MESSAGE **recv_msg_p)
{
    LIBSOCK_IPC_CLIENT_SESSION *session = NULL;
    LIBSOCK_IPC_MESSAGE *recv_msg = NULL;
    struct timeval start;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_OK;

    gettimeofday (&start, NULL);
    ret = libsock_ipc_client_msg_send_real (client_ipc,
                                            TRUE,
                                            to_path,
                                            &start,
                                            timeout,
                                            send_msg,
                                            &session);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        return ret;
    }

    ret = libsock_ipc_msg_recv (session->sock,
                                &recv_msg, /* this pointer maybe modified */
                                &start,
                                timeout);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        goto libsock_ipc_client_msg_send_with_timeout_err;
    }

    if (recv_msg->tid != session->tid) {
        ret = LIBSOCK_IPC_RESULT_UNKNOWN_MSG;
        goto libsock_ipc_client_msg_send_with_timeout_err;
    }

    /* Payload is ok */
    *recv_msg_p = recv_msg;

    libsock_ipc_client_session_free (client_ipc, &session);

    return LIBSOCK_IPC_RESULT_OK;

 libsock_ipc_client_msg_send_with_timeout_err:

    if (session) {
        libsock_ipc_client_session_free (client_ipc, &session);
    }

    if (recv_msg) {
        libsock_ipc_msg_free (&recv_msg);
    }

    return ret;
}

/*
 * Send message asynchronize
 * to_path: which daemon shall receive this message
 * session_p: for receiving reply, if the session pointer isn't NULL,
 * then the reply shall be receiveed (this pointer shall be freed by upper layer)
 * send_msg: The message will be sent to server from client
 * NOTICE: libsock_ipc_client_msg_send_send shall be called
 * after call libsock_ipc_client_msg_send
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send (LIBSOCK_IPC_CLIENT *client_ipc,
                             const char *to_path,
                             LIBSOCK_IPC_CLIENT_SESSION **session_p,
                             LIBSOCK_IPC_MESSAGE *send_msg)
{

    LIBSOCK_IPC_CLIENT_SESSION *session = NULL;
    struct timeval start;

    gettimeofday (&start, NULL);
    return libsock_ipc_client_msg_send_real (client_ipc,
                                             TRUE,
                                             to_path,
                                             &start,
                                             LIBSOCK_CLIENT_DEFAULT_TIMEOUT,
                                             send_msg,
                                             &session);
}

/*
 * Wait response asynchronize
 * session: for receiving reply
 * recv_msg_p: receive message from server, this pointer shall be
 * freed by upper layer
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_end (LIBSOCK_IPC_CLIENT *client_ipc,
                                 LIBSOCK_IPC_CLIENT_SESSION *session,
                                 LIBSOCK_IPC_MESSAGE **recv_msg_p)
{
    struct timeval start;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_OK;

    gettimeofday (&start, NULL);
    ret = libsock_ipc_msg_recv (session->sock,
                                recv_msg_p, /* this pointer maybe modified */
                                &start,
                                LIBSOCK_CLIENT_DEFAULT_TIMEOUT);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        goto libsock_ipc_client_msg_send_end_err;
    }

    if ((*recv_msg_p)->tid != session->tid) {
        ret = LIBSOCK_IPC_RESULT_UNKNOWN_MSG;
        goto libsock_ipc_client_msg_send_end_err;
    }

    /* Payload is ok */
    libsock_ipc_client_session_free (client_ipc, &session);

    return LIBSOCK_IPC_RESULT_OK;

 libsock_ipc_client_msg_send_end_err:

    if (*recv_msg_p) {
        libsock_ipc_msg_free (recv_msg_p);
    }

    return ret;
}

/*
 * Cancel the send message
 * session: for canceling message
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_cancel (LIBSOCK_IPC_CLIENT *client_ipc,
                                    LIBSOCK_IPC_CLIENT_SESSION **session_p)
{
    libsock_ipc_client_session_free (client_ipc, session_p);
    return LIBSOCK_IPC_RESULT_OK;
}

/*
 * Free client session
 */
void
libsock_ipc_client_session_free (LIBSOCK_IPC_CLIENT *client_ipc,
                                 LIBSOCK_IPC_CLIENT_SESSION **session_p)
{
    LIBSOCK_IPC_CLIENT_SESSION *session;
    GList *list;

    if (session_p == NULL) {
        return;
    }

    if (*session_p != NULL) {
        list = g_list_find_custom (client_ipc->session_list,
                                   *session_p,
                                   libsock_ipc_client_session_compare_func);
        if (list != NULL) {
            session = (LIBSOCK_IPC_CLIENT_SESSION *) list->data;

            /* Remove from session list */
            client_ipc->session_list = g_list_delete_link (client_ipc->session_list,
                                                           list);

            /* FALSE: don't close the socket */
            libsock_ipc_client_session_free_real (&session, FALSE);
        }

        /* TRUE: close the socket */
        libsock_ipc_client_session_free_real (session_p, TRUE);
    }

    *session_p = NULL;
}
