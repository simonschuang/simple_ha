/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: log_message function for logging
 * Filename:    logger.c
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

#include <sys/syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "logger.h"
FILE *fp = NULL;
#define LOG_MAX_LEN 1024
#define LOG_FACILITY_LEN  8
#define LOG_PREFIX_ERR     "[ERROR] "
#define LOG_PREFIX_WARN    "[WARN ] "
#define LOG_PREFIX_INFO    "[INFO ] "
#define LOG_PREFIX_DEBUG   "[DEBUG] "

void init_fp(void)
{
    fp = fopen(OUTFILE, "w+");
}

void exit_fp(void)
{
    fclose(fp);
    fp = NULL;
}

void log_message(const int facility, const char *format, ...)
{
    char log_buffer[LOG_MAX_LEN + LOG_FACILITY_LEN];
    int msg_len;

    va_list args;
    va_start(args,format);

    msg_len = LOG_MAX_LEN;
    memset(log_buffer, 0, LOG_MAX_LEN);
    unsigned int log_used=0;
    switch (facility) {
        case LOG_ERR:
            strncpy(log_buffer, LOG_PREFIX_ERR, LOG_FACILITY_LEN);
            msg_len -= (LOG_FACILITY_LEN);
            log_used=LOG_FACILITY_LEN;
            break;
        case LOG_WARNING:
            strncpy(log_buffer, LOG_PREFIX_WARN, LOG_FACILITY_LEN);
            msg_len -= (LOG_FACILITY_LEN);
            log_used=LOG_FACILITY_LEN;
            break;
        case LOG_INFO:
            strncpy(log_buffer, LOG_PREFIX_INFO, LOG_FACILITY_LEN);
            msg_len -= (LOG_FACILITY_LEN);
            log_used=LOG_FACILITY_LEN;
            break;
        case LOG_DEBUG:
            strncpy(log_buffer, LOG_PREFIX_DEBUG, LOG_FACILITY_LEN);
            msg_len -= (LOG_FACILITY_LEN);
            log_used=LOG_FACILITY_LEN;
            break;
        default:
            break;
    }
    strncpy(log_buffer + log_used, format, msg_len);

    vsyslog(facility, log_buffer, args);
    va_end(args);
}
