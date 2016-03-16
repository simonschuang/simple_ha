/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: socket related functions
 * Filename:    sockets.c
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> //htonl
#include <ctype.h> //isdigit
#include <netdb.h> //gethostbyname
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"
#include "sockets.h"

/* open udp socket */
int open_socket_udp(unsigned short port, char *bind_dev, struct in_addr *addr)
{
    struct sockaddr_in server;
    int sock;

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }

    memset(&server, 0, sizeof(server));
    if ((port > 0) || (addr != NULL)) {
        server.sin_family = AF_INET;
        if (addr) {
            server.sin_addr.s_addr = addr->s_addr;
        } else {
            server.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        if (port > 0) {
            server.sin_port = htons(port);
        } else {
            server.sin_port = 0;
        }

        if (bind(sock, (struct sockaddr *)&server, sizeof(server)) == -1) {
            log_message(LOG_ERR, "bind socket error %s", strerror(errno));
            close(sock);
            return -1;
        }
    }

    /* Use specific NIC to send packets */
    if (bind_dev) {
        setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, bind_dev,
            strlen(bind_dev)+1);
    }
    return sock;
}

int open_socket_mcast_client(unsigned short port, char *bind_dev,
    struct in_addr *addr)
{
    struct sockaddr_in server;
    unsigned char mc_ttl = 1;
    int sock;

    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_message(LOG_ERR, "socket failed because %s\n", strerror(errno));
        return -1;
    }

    /* set the TTL (time to live/hop count) for the send */
    if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*)&mc_ttl,
        sizeof(mc_ttl))) < 0) {
        log_message(LOG_ERR, "setsockopt() failed because %s\n",
                    strerror(errno));
        close(sock);
        return -1;
    }

    memset(&server, 0, sizeof(server));
    if ((port > 0) || (addr != NULL)) {
        server.sin_family = PF_INET;
        if (addr) {
            server.sin_addr.s_addr = addr->s_addr;
        } else {
            server.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        if (port > 0) {
            server.sin_port = htons(port);
        } else {
            server.sin_port = 0;
        }

        if (bind(sock, (struct sockaddr *)&server, sizeof(server)) == -1) {
            log_message(LOG_ERR, "bind socket error %s", strerror(errno));
            close(sock);
            return -1;
        }
    }

    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, bind_dev, strlen(bind_dev)+1);
    return sock;
}

int open_socket_mcast_server(char *mc_addr_str, int mc_port,
                             struct in_addr bind_addr)
{
    struct sockaddr_in mc_addr;
    struct ip_mreq mc_req;
    int sock, flag = 1;

    // set content of struct mc_addr and mc_req to zero
    memset(&mc_addr, 0, sizeof(struct sockaddr_in));
    memset(&mc_req, 0, sizeof(struct ip_mreq));

    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        log_message(LOG_ERR, "socket failed because %s\n", strerror(errno));
        return -1;
    }

    /* set reuse port to on to allow multiple binds per host */
    if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag))) < 0) {
        log_message(LOG_ERR, "setsockopt() failed because %s\n",
            strerror(errno));
        close(sock);
        return -1;
    }

    /* construct a multicast address structure */
    mc_addr.sin_family = AF_INET;
    mc_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    mc_addr.sin_port = htons(mc_port);

    /* bind to multicast address to socket */
    if ((bind(sock, (struct sockaddr *)&mc_addr, sizeof(mc_addr))) < 0) {
        log_message(LOG_ERR, "bind() failed because %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    /* construct an IGMP join request structure */
    mc_req.imr_multiaddr.s_addr = inet_addr(mc_addr_str);
    mc_req.imr_interface = bind_addr;

    /* send an ADD MEMBERSHIP message via setsockopt */
    if ((setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&mc_req,
        sizeof(mc_req))) < 0) {
        log_message(LOG_ERR, "setsockopt() failed because %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

ssize_t sendtomcast(int sock, void *buf, int nbytes, char *host,
                    unsigned short port)
{
    struct sockaddr_in remote;
    int len;

    /* construct a multicast address structure */
    memset(&remote, 0, sizeof(struct sockaddr_in));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(host);
    remote.sin_port = htons(port);

    /* send */
    len = sizeof(struct sockaddr_in);
    return sendto(sock, buf, nbytes, MSG_DONTWAIT, (struct sockaddr *)&remote,
                  len);
}

ssize_t sendtoaddr(int fd, void *buf, int nbytes, struct in_addr *d_addr,
                   unsigned short port) {
    struct sockaddr_in remote;
    int len;

    remote.sin_addr = *d_addr;
    remote.sin_port = htons(port);
    remote.sin_family = AF_INET;

    /* send */
    len = sizeof(struct sockaddr_in);

    return sendto(fd, buf, nbytes, MSG_DONTWAIT, (struct sockaddr *)&remote,
                  len);
}

ssize_t sendtohost(int fd, void *buf, int nbytes, char *hostn,
                   unsigned short port) {
    struct sockaddr_in remote;
    struct hostent *hp;
    int len;

    if (isdigit((int)(*hostn))) {
        remote.sin_addr.s_addr = inet_addr(hostn);
    }else {
        hp = gethostbyname(hostn);
        if (hp == NULL) {
            return -1;
        }
        memcpy(&remote.sin_addr.s_addr, hp->h_addr_list[0], hp->h_length);
    }

    remote.sin_port = htons(port);
    remote.sin_family = AF_INET;

    /* send */
    len = sizeof(struct sockaddr_in);
    return sendto(fd, buf, nbytes, MSG_DONTWAIT, (struct sockaddr *)&remote,
                  len);
}

void add2currenttime(struct timeval *timedone, int seconds)
{
    struct timeval newtime;

    gettimeofday(&newtime, NULL);
    timedone->tv_sec = newtime.tv_sec + (long)seconds;
    timedone->tv_usec = newtime.tv_usec;
}

int gettimeout(struct timeval end, struct timeval *timeoutp) {
    gettimeofday(timeoutp, NULL);
    timeoutp->tv_sec = end.tv_sec - timeoutp->tv_sec;
    timeoutp->tv_usec = end.tv_usec - timeoutp->tv_usec;
    if (timeoutp->tv_usec >= MILLION) {
        timeoutp->tv_sec++;
        timeoutp->tv_usec -= MILLION;
    }
    if (timeoutp->tv_usec < 0) {
        timeoutp->tv_sec--;
        timeoutp->tv_usec += MILLION;
    }
    if ((timeoutp->tv_sec < 0) ||
            ((timeoutp->tv_sec == 0) && (timeoutp->tv_usec == 0))) {
        errno = ETIME;
        return -1;
    }
    return 0;
}

int waitfdtimed(int fd, struct timeval end) {
    fd_set readset;
    int retval;
    struct timeval timeout;

    if ((fd < 0) || (fd >= FD_SETSIZE)) {
        errno = EINVAL;
        return -1;
    }
    FD_ZERO(&readset);
    FD_SET(fd, &readset);
    if (gettimeout(end, &timeout) == -1)
        return 0;
    while ((retval = select(fd+1, &readset, NULL, NULL, &timeout)) == -1) {
        if (gettimeout(end, &timeout) == -1)
            return 0;
        FD_ZERO(&readset);
        FD_SET(fd, &readset);
    }
    if (retval == 0) {
        errno = ETIME;
        return 0;
    }
    if (retval == -1)
        return -1;
    return retval;
}

ssize_t recvfrom_nowait(int fd, void *buf, size_t nbytes,
                        struct sockaddr_in *ubufp)
{
    struct sockaddr *remote;
    unsigned int len;

    len = sizeof (struct sockaddr_in);
    remote = (struct sockaddr *)ubufp;
    return recvfrom(fd, buf, nbytes, MSG_DONTWAIT, remote, &len);
}
/*
 *                  recvfromtimedone
 * Retrieve information from a file descriptor with
 */
int recvfromtimedone(int fd, void *buf, size_t nbytes, struct sockaddr_in *ubufp,
        struct timeval timedone) {
    unsigned int len = sizeof(struct sockaddr_in);
    struct sockaddr *remote = (struct sockaddr *)ubufp;
    int retval;

    if ((retval = waitfdtimed(fd, timedone)) > 0) {
        while ((retval = recvfrom(fd, buf, nbytes, 0, remote, &len)) == -1) ;
    }

    return retval;
}
