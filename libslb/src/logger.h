/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: log_message function for logging
 * Filename:    logger.h
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

#ifndef _LOGGER_H
#define _LOGGER_H
#include <syslog.h>
#include <stdio.h>

#define LOG_FILE 99
#define OUTFILE "/usr/cloudos/slb/output.log"
extern FILE *fp;

void log_message(const int facility, const char *format, ...);
void init_fp(void);
void exit_fp(void);

#define IEL_LOG(facility, args...) do { \
    if((facility) == LOG_FILE) { \
        fprintf(fp, args); \
    } else { \
        log_message(facility, args); \
    } \
} while (0)

#endif
