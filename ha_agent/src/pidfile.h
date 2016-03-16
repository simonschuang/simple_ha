/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Include file for pidfile.c
 * Filename:    pidfile.h
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

#ifndef _PIDFILE_H
#define _PIDFILE_H

/* system include */
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>

/* lock pidfile */
#define PID_FILE "/var/run/ha-agent.pid"

/* Prototypes */
extern int pidfile_write(char *pid_file, int pid);
extern void pidfile_rm(char *pid_file);
extern int process_running(char *pid_file);

#endif
