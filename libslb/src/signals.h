/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Include file for signal.c
 * Filename:    signal.h
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

#ifndef _SIGNALS_H
#define _SIGNALS_H

/* Prototypes */
extern void *signal_set(int signo, void (*func) (void *, int), void *v);
extern void *signal_ignore(int signo);
extern void signal_handler_init(void);
extern void signal_handler_destroy(void);
extern void signal_wait_handlers(void);
extern int signal_rfd(void);


#endif

