/*
 *
 * libslbipc.c
 *
 *  Created on: 2012/4/16
 *      Author: 990430
 */
#include <stdio.h>
#include <stdlib.h>  // free()
#include <string.h>
#include <sys/socket.h>  // inet_ntoa()
#include <netinet/in.h>  // inet_ntoa()
#include <arpa/inet.h>  // inet_ntoa()
#include "logger.h"  // log_message()
#include "libslbipc.h" // libslbipc_XXX
#include "libsock-ipc.h"  // LIBSOCK_IPC_XXX
#include "slb_communicator_message_type.h"  // SLB_COMMUNICATOR_MESSAGE_TYPE_XXX

// _vc_uuid should be freed by caller
// Return 0: success
// Return -1: fail
int libslbipc_getVcUuidByVmUuid(char **_vc_uuid, const char *_vm_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getVcUuidByVmUuid;
    char *query_data = (char*)_vm_uuid;
    size_t query_len = strlen(_vm_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    char **return_data = _vc_uuid;
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || *return_data != NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
        log_message(LOG_DEBUG, "%s(%d), Payload content:%s\n", __FILE__, __LINE__, reply_data);
    }

    // Copy return data
    *return_data = strdup(reply_data);
    if (*return_data == NULL) {
        log_message(LOG_ERR, "%s(%d), Out of memory\n", __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

// Return 0: success
// Return -1: fail
int libslbipc_getCnIpByVmUuid(struct in_addr *_cnIp, const char *_vm_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getCnIpByVmUuid;
    char *query_data = (char*)_vm_uuid;
    size_t query_len = strlen(_vm_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    struct in_addr *return_data = _cnIp;
    size_t return_len = sizeof(struct in_addr);
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
    }

    // Check reply data length
    if (reply_len != return_len) {
        log_message(LOG_ERR, "%s(%d), wrong reply payload length %d, should be %d\n",
            __FILE__, __LINE__, reply_len, return_len);
        return_code = -1;
        goto out;
    }

    // Copy return data
    memcpy(return_data, reply_data, return_len);

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

// Return 0: success
// Return -1: fail
int libslbipc_getSlbIpByVmUuid(struct in_addr *_slbIp, const char *_vm_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getSlbIpByVmUuid;
    char *query_data = (char*)_vm_uuid;
    size_t query_len = strlen(_vm_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    struct in_addr *return_data = _slbIp;
    size_t return_len = sizeof(struct in_addr);
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
    }

    // Check reply data length
    if (reply_len != return_len) {
        log_message(LOG_ERR, "%s(%d), wrong reply payload length %d, should be %d\n",
            __FILE__, __LINE__, reply_len, return_len);
        return_code = -1;
        goto out;
    }

    // Copy return data
    memcpy(return_data, reply_data, return_len);

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

// Return 0: success
// Return -1: fail
int libslbipc_getVmIpByVmUuid(struct in_addr *_vmIp, const char *_vm_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getVmIpByVmUuid;
    char *query_data = (char*)_vm_uuid;
    size_t query_len = strlen(_vm_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    struct in_addr *return_data = _vmIp;
    size_t return_len = sizeof(struct in_addr);
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
    }

    // Check reply data length
    if (reply_len != return_len) {
        log_message(LOG_ERR, "%s(%d), wrong reply payload length %d, should be %d\n",
            __FILE__, __LINE__, reply_len, return_len);
        return_code = -1;
        goto out;
    }

    // Copy return data
    memcpy(return_data, reply_data, return_len);

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

// Return 0: success
// Return -1: fail
int libslbipc_getVcIpByVmUuid(struct in_addr *_vcIp, const char *_vm_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getVcIpByVmUuid;
    char *query_data = (char*)_vm_uuid;
    size_t query_len = strlen(_vm_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    struct in_addr *return_data = _vcIp;
    size_t return_len = sizeof(struct in_addr);
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
    }

    // Check reply data length
    if (reply_len != return_len) {
        log_message(LOG_ERR, "%s(%d), wrong reply payload length %d, should be %d\n",
            __FILE__, __LINE__, reply_len, return_len);
        return_code = -1;
        goto out;
    }

    // Copy return data
    memcpy(return_data, reply_data, return_len);

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

// Return 0: success
// Return -1: fail
int libslbipc_getSlbIpByVcUuid(struct in_addr *_slbIp, const char *_vc_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getSlbIpByVcUuid;
    char *query_data = (char*)_vc_uuid;
    size_t query_len = strlen(_vc_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    struct in_addr *return_data = _slbIp;
    size_t return_len = sizeof(struct in_addr);
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
    }

    // Check reply data length
    if (reply_len != return_len) {
        log_message(LOG_ERR, "%s(%d), wrong reply payload length %d, should be %d\n",
            __FILE__, __LINE__, reply_len, return_len);
        return_code = -1;
        goto out;
    }

    // Copy return data
    memcpy(return_data, reply_data, return_len);

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

// Return 0: success
// Return -1: fail
int libslbipc_getVcIpByVcUuid(struct in_addr *_vcIp, const char *_vc_uuid)
{
    LIBSOCK_IPC_CLIENT *client_ipc = NULL;
    LIBSOCK_IPC_MESSAGE *send_msg = NULL, *recv_msg = NULL;
    enum LIBSOCK_IPC_RESULT ret = LIBSOCK_IPC_RESULT_NONE;
    int query_type = SLB_COMMUNICATOR_MESSAGE_TYPE_getVcIpByVcUuid;
    char *query_data = (char*)_vc_uuid;
    size_t query_len = strlen(_vc_uuid) + 1;
    char *reply_data = NULL;
    size_t reply_len = 0;
    struct in_addr *return_data = _vcIp;
    size_t return_len = sizeof(struct in_addr);
    int return_code = 0;

    // Check parameters
    if (return_data == NULL || query_data == NULL) {
        log_message(LOG_ERR, "%s(%d), NULL parameter\n",
            __FILE__, __LINE__);
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_client_create (&client_ipc);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret = libsock_ipc_msg_create (query_type,
                                 (char *) query_data,
                                 query_len,
                                 &send_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_msg_create failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    ret =
        libsock_ipc_client_msg_send_with_timeout (client_ipc,
            SLB_COMMUNICATOR_PATH,
            SEND_TIMEOUT,
            send_msg,
            &recv_msg);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), libsock_ipc_client_send_with_timeout failed, because %s.\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    }

    log_message(LOG_DEBUG, "%s(%d), Send message with timeout\n", __FILE__, __LINE__);
    log_message(LOG_DEBUG, "%s(%d), Recevie reply message\n", __FILE__, __LINE__);

    ret = libsock_ipc_msg_payload_get (recv_msg,
                                      &reply_data,
                                      &reply_len);
    if (ret != LIBSOCK_IPC_RESULT_OK) {
        log_message(LOG_ERR, "%s(%d), Get reply message payload failed, because %s\n",
            __FILE__, __LINE__, libsock_ipc_result_string_get (ret));
        return_code = -1;
        goto out;
    } else {
        log_message(LOG_DEBUG, "%s(%d), Payload length:%lu\n", __FILE__, __LINE__, reply_len);
    }

    // Check reply data length
    if (reply_len != return_len) {
        log_message(LOG_ERR, "%s(%d), wrong reply payload length %d, should be %d\n",
            __FILE__, __LINE__, reply_len, return_len);
        return_code = -1;
        goto out;
    }

    // Copy return data
    memcpy(return_data, reply_data, return_len);

    return_code = 0;
out:
    if (recv_msg)
        libsock_ipc_msg_free (&recv_msg);

    if (send_msg)
        libsock_ipc_msg_free (&send_msg);

    if (client_ipc)
        libsock_ipc_client_free (&client_ipc);

    return return_code;
}

#ifdef LIBSLBIPC_TEST
int main()
{
    char vm_uuid[] = "i-EA60856E";
    char *vc_uuid = NULL;
    struct in_addr cnIp;
    struct in_addr slbIp;
    struct in_addr vcIp;
    struct in_addr vmIp;

    openlog("TEST", LOG_PID, LOG_USER);

    libslbipc_getVcUuidByVmUuid(&vc_uuid, vm_uuid);
    log_message(LOG_INFO, "%s(%d), vc_uuid = %s\n", __FILE__, __LINE__, vc_uuid);
    if (vc_uuid != NULL) {
        free(vc_uuid);
        vc_uuid = NULL;
    }

    libslbipc_getCnIpByVmUuid(&cnIp, vm_uuid);
    log_message(LOG_INFO, "%s(%d), cnIp = %s\n", __FILE__, __LINE__, inet_ntoa(cnIp));

    libslbipc_getSlbIpByVmUuid(&slbIp, vm_uuid);
    log_message(LOG_INFO, "%s(%d), cnIp = %s\n", __FILE__, __LINE__, inet_ntoa(slbIp));

    libslbipc_getVmIpByVmUuid(&vmIp, vm_uuid);
    log_message(LOG_INFO, "%s(%d), vmIp = %s\n", __FILE__, __LINE__, inet_ntoa(vmIp));

    libslbipc_getVcIpByVmUuid(&vcIp, vm_uuid);
    log_message(LOG_INFO, "%s(%d), vcIp = %s\n", __FILE__, __LINE__, inet_ntoa(vcIp));

    vc_uuid = "dd9ad117-faa0-462a-ae90-d19ccdbdf47e";
    libslbipc_getSlbIpByVcUuid(&slbIp, vc_uuid);
    log_message(LOG_INFO, "%s(%d), slbIp = %s\n", __FILE__, __LINE__, inet_ntoa(slbIp));

    libslbipc_getVcIpByVcUuid(&vcIp, vc_uuid);
    log_message(LOG_INFO, "%s(%d), vcIp = %s\n", __FILE__, __LINE__, inet_ntoa(vcIp));

    return 0;
}
#endif
