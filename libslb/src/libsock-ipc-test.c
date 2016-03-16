#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <glib.h>
#include "libsock-ipc.h"

#define LIBSOCK_IPC_TEST_SERVER_PATH "SERVER_PATH"
#define LIBSOCK_IPC_TEST_SERVER_RECV_INTERVAL 1
#define LIBSOCK_IPC_TEST_SERVER_SEND_WITH_TIMEOUT 1000
#define LIBSOCK_IPC_TEST_CLIENT_SEND_INTERVAL 10
#define LIBSOCK_IPC_TEST_CLIENT_SEND_WITH_TIMEOUT 1000
#define IS_PRINT_MSG 0

#define LIBSOCK_IPC_TEST_SERVER_MSG_TYPE 100

static GMainLoop *g_main_loop = NULL;

enum LIBSOCK_IPC_CLIENT_TEST_CASE {
    LIBSOCK_IPC_CLIENT_TEST_CASE_NONE = 0,

    LIBSOCK_IPC_CLIENT_TEST_CASE_1,
    LIBSOCK_IPC_CLIENT_TEST_CASE_2,
    LIBSOCK_IPC_CLIENT_TEST_CASE_3,
    LIBSOCK_IPC_CLIENT_TEST_CASE_4,
    LIBSOCK_IPC_CLIENT_TEST_CASE_5,
    LIBSOCK_IPC_CLIENT_TEST_CASE_6,

    LIBSOCK_IPC_CLIENT_TEST_CASE_TOTAL
};

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

//===================================server=================================================
#ifdef __LIBSOCK_IPC_SERVER__

typedef struct LIBSOCK_IPC_TEST_SERVER LIBSOCK_IPC_TEST_SERVER;
struct LIBSOCK_IPC_TEST_SERVER {
    LIBSOCK_IPC_SERVER *server_ipc;
    struct timeval start;
    struct timeval end;
    unsigned long long int success_count;
    unsigned long long int failed_count;
};

static gboolean
msg_recv_func (gpointer user_data)
{
    LIBSOCK_IPC_TEST_SERVER *handle;
    LIBSOCK_IPC_SERVER *server_ipc;
    LIBSOCK_IPC_SERVER_SESSION *session = NULL;
    LIBSOCK_IPC_MESSAGE *recv_msg = NULL;
    long msg_type;
    char *payload;
    size_t len;
    struct timeval timestamp;
    enum LIBSOCK_IPC_RESULT ret;

    handle = (LIBSOCK_IPC_TEST_SERVER *) user_data;
    server_ipc = handle->server_ipc;

    ret = libsock_ipc_server_msg_recv (server_ipc,
                                       &session,
                                       &recv_msg);
    if (ret == LIBSOCK_IPC_RESULT_RETRY) {
        return TRUE;
    }

    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_server_msg_recv failed, because %s.\n",
                libsock_ipc_result_string_get (ret));
        handle->failed_count++;
        return TRUE;
    }

    if (IS_PRINT_MSG) {
        printf ("Receive message and ");
        printf ("%s\n", (session != NULL) ? "need reply" : "don't need reply");
    }

    ret = libsock_ipc_msg_info_get (recv_msg, &msg_type, &timestamp);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("Get message information failed, because %s\n",
                libsock_ipc_result_string_get (ret));
        handle->failed_count++;
        goto msg_recv_func_finish;
    }

    if (msg_type != LIBSOCK_IPC_TEST_SERVER_MSG_TYPE) {
        printf ("Unknown message type %lu\n", msg_type);
        handle->failed_count++;
        goto msg_recv_func_finish;
    }

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                       &payload,
                                       &len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("Get message payload failed, because %s\n",
                libsock_ipc_result_string_get (ret));
        handle->failed_count++;
        goto msg_recv_func_finish;
    }

    if (IS_PRINT_MSG) {
        printf ("Payload length:%lu\n", len);
        printf ("Payload message:%s\n", payload);
    }

    if (session) {
        snprintf (payload, len, "Son, I saw you there!");

        ret = 
            libsock_ipc_server_msg_send_reply_with_timeout (server_ipc,
                                                            session,
                                                            recv_msg,
                                                            LIBSOCK_IPC_TEST_SERVER_SEND_WITH_TIMEOUT);
        if (ret != LIBSOCK_IPC_RESULT_OK) {
            printf ("libsock_ipc_server_msg_send_reply failed, because %s\n",
                    libsock_ipc_result_string_get (ret));
            libsock_ipc_server_msg_send_reply_cancel (server_ipc);
        } else {
            if (IS_PRINT_MSG) {
                printf ("Send reply ok\n");
            }
        }
    }

    handle->success_count++;

 msg_recv_func_finish:

    if (session) {
        libsock_ipc_server_session_free (&session);
    }

    if (recv_msg) {
        libsock_ipc_msg_free (&recv_msg);
    }

    return TRUE;
}

int
main (int argc, char *argv[])
{
    LIBSOCK_IPC_TEST_SERVER handle;
    struct sigaction act;
    enum LIBSOCK_IPC_RESULT ret;

    /* Init signal catch */
    act.sa_handler = signal_catch;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction (SIGTERM, &act, NULL);
    sigaction (SIGINT, &act, NULL);
    sigaction (SIGPIPE, &act, NULL);

    g_main_loop = g_main_loop_new (NULL, FALSE);

    memset (&handle, 0, sizeof (LIBSOCK_IPC_TEST_SERVER));
    ret = libsock_ipc_server_create (LIBSOCK_IPC_TEST_SERVER_PATH,
                                     &(handle.server_ipc));

    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_server_create failed, because %s.\n",
                libsock_ipc_result_string_get (ret));
        goto finish;
    }

    g_timeout_add (LIBSOCK_IPC_TEST_SERVER_RECV_INTERVAL,
                   msg_recv_func,
                   &(handle.server_ipc));

    gettimeofday (&(handle.start), NULL);

    /* Enter main loop */
    g_main_loop_run (g_main_loop);

    gettimeofday (&(handle.end), NULL);

 finish:

    /* Main loop Terminated */
    if (g_main_loop) {
        g_main_loop_unref (g_main_loop);
        g_main_loop = NULL;
    }

    libsock_ipc_server_free (&(handle.server_ipc));

    printf ("%lu msec, ",
            ((handle.end.tv_sec * 1000) + (handle.end.tv_usec % 1000)) -
            ((handle.start.tv_sec * 1000) + (handle.start.tv_usec % 1000)));
    printf ("success_count=%llu, failed_count=%llu\n",
            handle.success_count, handle.failed_count);

    return 0;
}
#endif

//===================================client=================================================
#ifdef __LIBSOCK_IPC_CLIENT__

typedef struct LIBSOCK_IPC_TEST_CLIENT LIBSOCK_IPC_TEST_CLIENT;
struct LIBSOCK_IPC_TEST_CLIENT {
    LIBSOCK_IPC_CLIENT *client_ipc;
    time_t start;
    unsigned int test_sec;
    enum LIBSOCK_IPC_CLIENT_TEST_CASE test_case;
    struct {
        unsigned int success_count;
        unsigned int failed_count;
    } result[LIBSOCK_IPC_CLIENT_TEST_CASE_TOTAL - 1];
};

static gboolean
msg_send_with_timeout_func (gpointer user_data)
{
    LIBSOCK_IPC_TEST_CLIENT *handle;
    LIBSOCK_IPC_CLIENT *client_ipc;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    char *test_send_msg = NULL;
    char *payload;
    size_t len, msg_len = 0;
    int i, speed;
    enum LIBSOCK_IPC_RESULT ret;

    handle = (LIBSOCK_IPC_TEST_CLIENT *) user_data;
    client_ipc = handle->client_ipc;

    if (handle->start == 0) {
        handle->test_case++;
        handle->start = time (NULL);
    }

    switch (handle->test_case) {
    case LIBSOCK_IPC_CLIENT_TEST_CASE_1:
        /* Througput: small payload */
        msg_len = 1000;
        handle->test_sec = 10;
        speed = LIBSOCK_IPC_TEST_CLIENT_SEND_INTERVAL;
        break;
    case LIBSOCK_IPC_CLIENT_TEST_CASE_2:
        /* Througput: big payload */
        msg_len = 1000000;
        handle->test_sec = 10;
        speed = LIBSOCK_IPC_TEST_CLIENT_SEND_INTERVAL;
        break;
    case LIBSOCK_IPC_CLIENT_TEST_CASE_3:
        /* Througput: small payload with high speed */
        msg_len = 1000;
        handle->test_sec = 10;
        speed = 0;
        break;
    case LIBSOCK_IPC_CLIENT_TEST_CASE_4:
        /* Througput: big payload with high speed */
        msg_len = 1000000;
        handle->test_sec = 10;
        speed = 0;
        break;
    default:
        for (i = LIBSOCK_IPC_CLIENT_TEST_CASE_1; i <= LIBSOCK_IPC_CLIENT_TEST_CASE_4; i++) {
            printf ("Case %d: success_count=%u, failed_count=%u\n",
                    i,
                    handle->result[i - 1].success_count,
                    handle->result[i - 1].failed_count);
        }
        g_main_loop_quit (g_main_loop);
        return FALSE;
    }

    if ((handle->start + handle->test_sec) == time (NULL)) {
        handle->start = 0;
        return TRUE;
    }

    test_send_msg = (char *) calloc (1, msg_len);
    if (test_send_msg == NULL) {
        printf ("Out of memory\n");
        return FALSE;
    }

    snprintf (test_send_msg,
              msg_len,
              "Mom, I'm here!");
    ret = libsock_ipc_msg_create (LIBSOCK_IPC_TEST_SERVER_MSG_TYPE,
                                  (char *) test_send_msg,
                                  msg_len,
                                  &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_msg_create failed, because %s\n",
                libsock_ipc_result_string_get (ret));
        handle->result[handle->test_case - 1].failed_count++;
        goto msg_send_with_timeout_func;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
                                                  LIBSOCK_IPC_TEST_SERVER_PATH,
                                                  LIBSOCK_IPC_TEST_CLIENT_SEND_WITH_TIMEOUT,
                                                  send_msg,
                                                  &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_client_send_with_timeout failed, because %s.\n",
                libsock_ipc_result_string_get (ret));
        handle->result[handle->test_case - 1].failed_count++;
        goto msg_send_with_timeout_func;
    }

    if (IS_PRINT_MSG) {
        printf ("Send message with timeout\n");
        printf ("Recevie reply message\n");
    }

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                       &payload,
                                       &len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("Get reply message payload failed, because %s\n",
                libsock_ipc_result_string_get (ret));
    } else {
        if (IS_PRINT_MSG) {
            printf ("Payload length:%lu\n", len);
            printf ("Payload content:%s\n", payload);
        }
    }

    handle->result[handle->test_case - 1].success_count++;
    libsock_ipc_msg_free (&recv_msg);

 msg_send_with_timeout_func:

    if (test_send_msg) {
        free (test_send_msg);
    }

    if (send_msg) {
        libsock_ipc_msg_free (&send_msg);
    }

    g_timeout_add (speed,
                   msg_send_with_timeout_func,
                   handle);

    return FALSE;
}

static gboolean
msg_send_with_no_reply_func (gpointer user_data)
{
    LIBSOCK_IPC_TEST_CLIENT *handle;
    LIBSOCK_IPC_CLIENT *client_ipc;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL;
    char *msg = NULL;
    size_t msg_len = 0;
    int i, speed;
    enum LIBSOCK_IPC_RESULT ret;

    handle = (LIBSOCK_IPC_TEST_CLIENT *) user_data;
    client_ipc = handle->client_ipc;

    if (handle->start == 0) {
        handle->test_case++;
        handle->start = time (NULL);
    }

    switch (handle->test_case) {
    case LIBSOCK_IPC_CLIENT_TEST_CASE_1:
        /* Througput: small payload */
        msg_len = 1000;
        handle->test_sec = 10;
        speed = LIBSOCK_IPC_TEST_CLIENT_SEND_INTERVAL;
        break;
    case LIBSOCK_IPC_CLIENT_TEST_CASE_2:
        /* Througput: big payload */
        msg_len = 1000000;
        handle->test_sec = 10;
        speed = LIBSOCK_IPC_TEST_CLIENT_SEND_INTERVAL;
        break;
    case LIBSOCK_IPC_CLIENT_TEST_CASE_3:
        /* Througput: small payload with high speed */
        msg_len = 1000;
        handle->test_sec = 10;
        speed = 0;
        break;
    case LIBSOCK_IPC_CLIENT_TEST_CASE_4:
        /* Througput: big payload with high speed */
        msg_len = 1000000;
        handle->test_sec = 10;
        speed = 0;
        break;
    default:
        for (i = LIBSOCK_IPC_CLIENT_TEST_CASE_1; i <= LIBSOCK_IPC_CLIENT_TEST_CASE_4; i++) {
            printf ("Case %d: success_count=%u, failed_count=%u\n",
                    i,
                    handle->result[i - 1].success_count,
                    handle->result[i - 1].failed_count);
        }
        memset (handle, 0, sizeof (LIBSOCK_IPC_TEST_CLIENT));
        handle->client_ipc = client_ipc;
        msg_send_with_timeout_func (handle);
        return FALSE;
    }

    if ((handle->start + handle->test_sec) == time (NULL)) {
        handle->start = 0;
        return TRUE;
    }

    msg = (char *) calloc (1, msg_len);
    if (msg == NULL) {
        printf ("Out of memory\n");
        return FALSE;
    }

    snprintf (msg, msg_len, "Mom, I'm here!");
    ret = libsock_ipc_msg_create (LIBSOCK_IPC_TEST_SERVER_MSG_TYPE,
                                  (char *) msg,
                                  msg_len,
                                  &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_msg_create failed, because %s\n",
                libsock_ipc_result_string_get (ret));
        handle->result[handle->test_case - 1].failed_count++;
        goto msg_send_with_no_reply_func;
    }

    ret = libsock_ipc_client_msg_send_with_no_reply (client_ipc,
                                                     LIBSOCK_IPC_TEST_SERVER_PATH,
                                                     send_msg);
    if (ret == LIBSOCK_IPC_RESULT_RETRY) {
        printf ("Buffer is fulled\n");
        handle->result[handle->test_case - 1].failed_count++;
        goto msg_send_with_no_reply_func;
    }

    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_client_send_with_no_reply failed, because %s.\n",
                libsock_ipc_result_string_get (ret));
        handle->result[handle->test_case - 1].failed_count++;
        goto msg_send_with_no_reply_func;
    }

    if (IS_PRINT_MSG) {
        printf ("Send message with no reply\n");
    }
    handle->result[handle->test_case - 1].success_count++;

 msg_send_with_no_reply_func:

    if (msg) {
        free (msg);
    }

    if (send_msg) {
        libsock_ipc_msg_free (&send_msg);
    }

    g_timeout_add (speed,
                   msg_send_with_no_reply_func,
                   handle);

    return FALSE;
}

int
main (int argc, char *argv[])
{
    LIBSOCK_IPC_TEST_CLIENT handle;
    struct sigaction act;
    enum LIBSOCK_IPC_RESULT ret;

    /* Init signal catch */
    act.sa_handler = signal_catch;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction (SIGTERM, &act, NULL);
    sigaction (SIGINT, &act, NULL);
    sigaction (SIGPIPE, &act, NULL);

    g_main_loop = g_main_loop_new (NULL, FALSE);

    memset (&handle, 0, sizeof (LIBSOCK_IPC_TEST_CLIENT));
    ret = libsock_ipc_client_create (&(handle.client_ipc));
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        printf ("libsock_ipc_client_create failed, because %s\n",
                libsock_ipc_result_string_get (ret));
        goto finish;
    }

    msg_send_with_no_reply_func (&handle);

    /* Enter main loop */
    g_main_loop_run (g_main_loop);

 finish:

    /* Main loop Terminated */
    if (g_main_loop) {
        g_main_loop_unref (g_main_loop);
        g_main_loop = NULL;
    }

    libsock_ipc_client_free (&(handle.client_ipc));
    
    return 0;
}
#endif
