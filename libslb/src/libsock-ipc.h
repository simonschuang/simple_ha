/*
 * libsock-ipc.h
 *
 *  Created on: 2012/2/23
 *      Author: A00128
 *
 * NOTICE: Please catch the signal - SIGPIPE, it will cause the
 * process terminated when the socket is closed and process still try
 * to read/write data
 */

#ifndef __LIBSOCK_IPC_H__
#define __LIBSOCK_IPC_H__

#include <sys/time.h>

enum LIBSOCK_IPC_RESULT {
    LIBSOCK_IPC_RESULT_NONE = 0,

    LIBSOCK_IPC_RESULT_OK,

    /* send site: buffer is fulled, recv site: buffer is empty */
    LIBSOCK_IPC_RESULT_RETRY,

    /* Daemon client/server isn't existed */
    LIBSOCK_IPC_RESULT_NOT_READY,

    /* The session isn't found */
    LIBSOCK_IPC_RESULT_SESSION_NOT_FOUND,

    /* sent site have never received last message's reply, but upper
       layer'd like to send message agagin */
    /* NOTICE: Use libsock_ipc_client_msg_send_cancel to cancel the last message */
    LIBSOCK_IPC_RESULT_SESSION_BUSY,

    LIBSOCK_IPC_RESULT_CONNECTION_LOSE,

    LIBSOCK_IPC_RESULT_CONNECTION_TIMEOUT,

    /* A client is waitting to receive a reply from recv site,
       but recv site'd like to receive next request */
    LIBSOCK_IPC_RESULT_CLIENT_SESSION_PENDING,

    LIBSOCK_IPC_RESULT_UNKNOWN_MSG,

    LIBSOCK_IPC_RESULT_OUT_OF_MEMORY,
    LIBSOCK_IPC_RESULT_PARAMETER_ERROR,
    LIBSOCK_IPC_RESULT_SOCKET_CREATE_ERROR,

    /* Coding error */
    LIBSOCK_IPC_RESULT_INTERNAL_ERROR,

    LIBSOCK_IPC_RESULT_TOTAL
};

typedef struct LIBSOCK_IPC_MESSAGE LIBSOCK_IPC_MESSAGE;
typedef struct LIBSOCK_IPC_SERVER_SESSION LIBSOCK_IPC_SERVER_SESSION;
typedef struct LIBSOCK_IPC_SERVER LIBSOCK_IPC_SERVER;
typedef struct LIBSOCK_IPC_CLIENT_SESSION LIBSOCK_IPC_CLIENT_SESSION;
typedef struct LIBSOCK_IPC_CLIENT LIBSOCK_IPC_CLIENT;

const char *
libsock_ipc_result_string_get (enum LIBSOCK_IPC_RESULT ret);

enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_create (long msg_type,
                        const char *payload,
                        size_t len,
                        LIBSOCK_IPC_MESSAGE **msg_p);

void
libsock_ipc_msg_free (LIBSOCK_IPC_MESSAGE **msg_p);

/*
 * Each information pointers could be assigned NULL, it means you don't care
 * this information
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_info_get (LIBSOCK_IPC_MESSAGE *msg,
                          long *msg_type,
                          struct timeval *timestamp);

/*
 * payload: DO NOT free pointer
 * len: payload length
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_msg_payload_get (LIBSOCK_IPC_MESSAGE *msg,
                             char **payload,
                             size_t *len);

/*
 * path: This IPC server path
 * server_ipc_p: server handle
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_create (const char *path,
                           LIBSOCK_IPC_SERVER **server_ipc_p);

void
libsock_ipc_server_free (LIBSOCK_IPC_SERVER **server_ipc_p);

/* TODO */
void
libsock_ipc_server_msg_type_filter_add (LIBSOCK_IPC_SERVER *server_ipc,
                                        long msg_type);

/* TODO */
void
libsock_ipc_server_msg_type_filter_del (LIBSOCK_IPC_SERVER *server_ipc,
                                        long msg_type);

/*
 * session_p: for sending reply using, if the session pointer isn't NULL,
 * then the reply shall be sent (this pointer shall be freed by upper layer)
 * recv_msg_p: receive message from client, this pointer shall be
 * freed by upper layer
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_msg_recv (LIBSOCK_IPC_SERVER *server_ipc,
                             LIBSOCK_IPC_SERVER_SESSION **session_p,
                             LIBSOCK_IPC_MESSAGE **recv_msg_p);

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
                                                long timeout);

/*
 * session: for sending reply
 * send_msg: send reply to client
 * NOTICE: if message shall be replied, then you HAVE TO use this
 * function to send reply
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_server_msg_send_reply (LIBSOCK_IPC_SERVER *server_ipc,
                                   const LIBSOCK_IPC_SERVER_SESSION *session,
                                   LIBSOCK_IPC_MESSAGE *send_msg);

void
libsock_ipc_server_msg_send_reply_cancel (LIBSOCK_IPC_SERVER *server_ipc);

void
libsock_ipc_server_session_free (LIBSOCK_IPC_SERVER_SESSION **session_p);

enum LIBSOCK_IPC_RESULT
libsock_ipc_client_create (LIBSOCK_IPC_CLIENT **client_ipc_p);

void
libsock_ipc_client_free (LIBSOCK_IPC_CLIENT **client_ipc_p);

/*
 * Send message and don't wait reply (For notification)
 * to_path: which daemon shall receive this message
 * send_msg: The message will be sent to server
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_with_no_reply (LIBSOCK_IPC_CLIENT *client_ipc,
                                           const char *to_path,
                                           LIBSOCK_IPC_MESSAGE *send_msg);

/*
 * Send message and wait reply synchronize
 * to_path: which daemon shall receive this message
 * timeout: millisecond
 * send_msg: The message will be sent to server from client
 * recv_msg_p: receive message from server, this pointer shall be
 * freed by upper layer
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_with_timeout (LIBSOCK_IPC_CLIENT *client_ipc,
                                          const char *to_path,
                                          long timeout,
                                          LIBSOCK_IPC_MESSAGE *send_msg,
                                          LIBSOCK_IPC_MESSAGE **recv_msg_p);

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
                             LIBSOCK_IPC_MESSAGE *send_msg);

/*
 * Wait response asynchronize
 * session: for receiving reply
 * recv_msg_p: receive message from server, this pointer shall be
 * freed by upper layer
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_end (LIBSOCK_IPC_CLIENT *client_ipc,
                                 LIBSOCK_IPC_CLIENT_SESSION *session,
                                 LIBSOCK_IPC_MESSAGE **recv_msg_p);

/*
 * Cancel the send message
 * session: for canceling message
 */
enum LIBSOCK_IPC_RESULT
libsock_ipc_client_msg_send_cancel (LIBSOCK_IPC_CLIENT *client_ipc,
                                    LIBSOCK_IPC_CLIENT_SESSION **session_p);

/*
 * Free client session
 */
void
libsock_ipc_client_session_free (LIBSOCK_IPC_CLIENT *client_ipc,
                                 LIBSOCK_IPC_CLIENT_SESSION **session_p);

#endif
