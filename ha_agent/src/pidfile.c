/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: pid file operations
 * Filename:    pidfile.c
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 *
 */

#include "logger.h"
#include "pidfile.h"

/* Create the runnnig daemon pidfile */
int pidfile_write(char *pid_file, int pid)
{
    FILE *pidfile = fopen(pid_file, "w");

    if (!pidfile) {
        log_message(LOG_ERR, "pidfile_write : Can not open %s pidfile",
                pid_file);
        return 0;
    }
    fprintf(pidfile, "%d\n", pid);
    fclose(pidfile);
    return 1;
}

/* Remove the running daemon pidfile */
void pidfile_rm(char *pid_file)
{
    unlink(pid_file);
}

/* return the daemon running state */
int process_running(char *pid_file)
{
    FILE *pidfile = fopen(pid_file, "r");
    pid_t pid;
    int ret;

    /* No pidfile */
    if (!pidfile)
        return 0;

    ret = fscanf(pidfile, "%d", &pid);
    if (ret != 1) {
        fclose(pidfile);
        return 0;
    }

    fclose(pidfile);

    /* If no process is attached to pidfile, remove it */
    if (kill(pid, 0)) {
        log_message(LOG_DEBUG, "[process_running]:Remove a zombie pid file %s", pid_file);
        pidfile_rm(pid_file);
        return 0;
    }

    return 1;
}

