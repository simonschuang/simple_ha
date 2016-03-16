/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: socket related functions
 * Filename:    sockets.c
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 *
 */
#ifndef _SOCKETS_H
#define _SOCKETS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#define MILLION 1000000

extern int open_socket_udp(unsigned short port, char *bind_dev,
                           struct in_addr *addr);
extern int open_socket_mcast_client(unsigned short port, char *bind_dev,
                                    struct in_addr *addr);
extern int open_socket_mcast_server(char *mc_addr_str, int mc_port,
                                    struct in_addr addr);
extern ssize_t sendtomcast(int sock, void *buf, int nbytes, char *host,
                           unsigned short port);
extern ssize_t sendtoaddr(int fd, void *buf, int nbytes, struct in_addr *d_addr,
                          unsigned short port);
extern ssize_t sendtohost(int fd, void *buf, int nbytes, char *hostn,
                          unsigned short port);
extern void add2currenttime(struct timeval *timedone, int seconds);
extern ssize_t recvfrom_nowait(int fd, void *buf, size_t nbytes,
                               struct sockaddr_in *ubufp);
extern int recvfromtimedone(int fd, void *buf, size_t nbytes,
                            struct sockaddr_in *ubufp,
                            struct timeval timedone);

#endif
