/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: HA daemon main file
 * Filename:    main.c
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 */

#include <netdb.h> //gethostbyname
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>

/* local include */
#include "config.h"
#include "logger.h"
#include "signals.h"
#include "pidfile.h"
#include "daemon.h"
#include "interface.h"
#include "ha-agent.h"

/* Terminate handler */
static void sigend(void *v, int sig)
{
    HA_AGENT *handle = (HA_AGENT *) v;
    /* register the terminate thread */
    log_message(LOG_INFO, "Terminating ha process on signal");
    ha_agent_stop (handle);
}

/* Initialize signal handler */
static void signal_init(void *arg)
{
    signal_handler_init();
    signal_set(SIGTERM, sigend, arg);
    signal_set(SIGINT, sigend, arg);
    signal_ignore(SIGPIPE);
}

/* Usage functions */
static void usage(const char *prog)
{
    fprintf(stderr, VERSION_STRING);
    fprintf(stderr, "Commands:\n"
        "Either long or short options are allowed.\n"
        " %s --help             -h  Display this short inlined help screen.\n"
        " %s --nodaemon         -d  No daemonized ha-agent.\n"
        " %s --if-name          -f  bind interface name.\n",
        prog, prog, prog);
}

static void parse_network_conf(HA_AGENT *handle)
{
    char line[50];
    FILE *fp;

    fp = popen("cat /usr/cloudos/slb/network.conf |grep 'ha_nic' | cut -d= -f2 | tr -d '\n'", "r");
    if (fp) {
        if (fgets(line, 50, fp)) {
            log_message(LOG_INFO, "parse network.conf ha_nic = %s", line);
            ha_agent_if_name_set(strdup(line), handle);
        }
        pclose(fp);
    }
}

static void parse_cmdline(int argc, char **argv, HA_AGENT *handle,
                          int *daemonize)
{
    struct option longopts[] = { {"help", 0, 0, 'h'},
                                 {"nodaemon", 0, 0, 'd'},
                                 {"if-name", 1, 0, 'f'},
                                 {0, 0, 0, 0} };
    int opt = 0;
    while ((opt = getopt_long(argc, argv, "Lhdf:", longopts, &opt)) != -1) {
        switch (opt) {
            case 0:
                break;
            case 'h':
                usage(argv[0]);
                if (handle) {
                    ha_agent_free(handle);
                }
                closelog();
                exit(0);
                break;
            case 'd':
                *daemonize = 0;
                break;
            case 'f':
                ha_agent_if_name_set (strdup (optarg), handle);
                break;
            default:
                usage(argv[0]);
                if (handle) {
                    ha_agent_free(handle);
                }
                closelog();
                exit(0);
        }
    }
}

static int file_exists(const char *filename)
{
    FILE *file = NULL;
    if ((file = fopen(filename, "r"))) {
        fclose(file);
        return 0;
    }
    return -1;
}

/* Move old log */
static void updateLog(void)
{
    struct tm *tmptime;
    char cmd[1024], buff[24];
    time_t ntime;

    memset(buff, 0, 24);
    sprintf(buff, "/var/log/%s.log", PROG);
    if (file_exists(buff) < 0) {
        return;
    }
    memset (cmd, 0, 1024);
    time(&ntime);
    tmptime = localtime(&ntime);
    if (tmptime == NULL) {
        log_message(LOG_ERR, "Get local time failed");
        return;
    }
    memset(buff, 0, 24);
    if (strftime(buff, 24, "%m%d%H%M%S", tmptime) == 0){
        log_message(LOG_ERR, "convert to string failed");
        return;
    }

    memset(cmd, 0, 100);
    sprintf(cmd, "cp /var/log/%s.log /var/log/%s.log_%s", PROG, PROG, buff);

    if (system(cmd) == -1) {
        log_message(LOG_ERR, "copy file failed");
    }
    system("echo > /var/log/ha-agent.log");
}

/* 
 Entry point.
 1. open log
 2. parse command line
 3. daemonize
 4. change signal handler
 5. start HA
 */
int main(int argc, char **argv)
{
    HA_AGENT *handle = NULL;
    int daemonize, status = 0;

    openlog(PROG, LOG_PID, LOG_LOCAL5);
    updateLog();

    handle = ha_agent_create();
    if (!handle) {
        status = 1;
        goto end;
    }

    daemonize = 1;
    parse_cmdline(argc, argv, handle, &daemonize);
    log_message(LOG_INFO, "Starting " VERSION_STRING);

    parse_network_conf(handle);
    /* Check if process is already running */
    if (process_running((char *)PID_FILE)) {
        log_message(LOG_ERR, "daemon is already running");
        status = 1;
        goto end;
    }
    signal_init(handle);
    if (bind_if_init(handle) < 0) {
        char *bind_if_name = ha_agent_if_name_get (handle);
        log_message(LOG_ERR, "can not find interface %s", bind_if_name);
        status = 1;
        goto end;
    }

    if (daemonize) {
        xdaemon(0, 0, 0);
    }
    /* write the father's pidfile */
    if (!pidfile_write(PID_FILE, getpid())) {
        status = 1;
        goto end;
    }
    /* Start working*/
    status = ha_agent_run (handle);

    signal_handler_destroy();
    pidfile_rm(PID_FILE);
    log_message(LOG_INFO, "Terminating ha-agent process done %d", status);

 end:

    if (handle) {
        ha_agent_free (handle);
    }
    closelog();
    exit(status);
}
