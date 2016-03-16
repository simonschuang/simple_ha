/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Daemonization function coming from zebra source code
 * Filename:    daemon.c
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

#include <sys/types.h>
#include <dirent.h>
#include <glib.h>
#include "daemon.h"
//#include "logger.h"

#define DAEMON_PROC_DIR "/proc/"

/* Daemonization function coming from zebra source code */
pid_t xdaemon(int nochdir, int noclose, int exitflag)
{
    pid_t pid;

    /* In case of fork is error. */
    pid = fork();
    if (pid < 0) {
 //       log_message(LOG_ERR, "xdaemon: fork error");
        return -1;
    }

    /* In case of this is parent process. */
    if (pid != 0) {
        if (!exitflag)
            exit(0);
        else
            return pid;
    }

    /* Become session leader and get pid. */
    pid = setsid();
    if (pid < -1) {
  //      log_message(LOG_ERR, "xdaemon: setsid error");
        return -1;
    }

    /* Change directory to root. */
    if (!nochdir)
        chdir("/");

    /* File descriptor close. */
    if (!noclose) {
        int fd;

        fd = open("/dev/null", O_RDWR, 0);
        if (fd != -1) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
    }

    umask(0);
    return 0;
}

/* return 0: isn't alive, 1: alive, -1: error */
int
is_daemon_alive (pid_t pid)
{
    DIR *dir = NULL;
    char *dir_path = NULL;
    int ret = 0;

    dir_path = g_strdup_printf ("%s%d", DAEMON_PROC_DIR, pid);
    if (dir_path == NULL) {
        return -1;
    }

    dir = opendir (dir_path);
    if (dir) {
        ret = 1;
        closedir (dir);
    }

    free (dir_path);

    return ret;
}
