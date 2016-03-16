/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Copy from 'UNIX Systems Programming'
 *              Name resolution functions
 * Filename:    uiciname.h
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

/* uiciname.h name resolution functions */

#ifndef _UICINAME_H
#define _UICINAME_H 

#include <netinet/in.h>
#define REENTRANT_NONE 0
#define REENTRANT_R 1
#define REENTRANT_MUTEX 2
#define REENTRANT_POSIX 3

extern int name2addr(char *name, in_addr_t *addrp);
extern void addr2name(struct in_addr addr, char *name, int namelen);

#endif
