/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Anything about signal handling funtions
 * Filename:    signal.c
 * Author:      Simon Chuang, <snowhigh1211@gmail.com>
 *
 */

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <syslog.h>

#include "signals.h"


/* Local Vars */
void (*signal_SIGTERM_handler) (void *, int sig);
void *signal_SIGTERM_v;
void (*signal_SIGINT_handler) (void *, int sig);
void *signal_SIGINT_v;

static int signal_pipe[2] = { -1, -1 };

/* Signal flag */
void signal_handler(int sig)
{
    write(signal_pipe[1], &sig, sizeof(int));

    switch(sig) {
        case SIGTERM:
            if (signal_SIGTERM_handler)
                signal_SIGTERM_handler(signal_SIGTERM_v, SIGTERM);
            break;
        case SIGINT:
            if (signal_SIGINT_handler)
                signal_SIGINT_handler(signal_SIGINT_v, SIGINT);
            break;
        default:
            break;
    }
}

/* Signal Ignore */
void *signal_ignore(int signo)
{
    return signal_set(signo, NULL, NULL);
}

/* Signal wrapper */
void *signal_set(int signo, void (*func) (void *, int), void *v)
{
    int ret;
    struct sigaction sig;
    struct sigaction osig;

    sig.sa_handler = signal_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    // Return 0 on success, -1 on failed
    ret = sigaction(signo, &sig, &osig);

    switch(signo) {
        case SIGTERM:
            signal_SIGTERM_handler = func;
            signal_SIGTERM_v = v;
            break;
        case SIGINT:
            signal_SIGINT_handler = func;
            signal_SIGINT_v = v;
            break;
    }

    if (ret < 0){
        syslog(LOG_ERR, "signal initial error! %d ", signo);
        return (SIG_ERR);
    }else{
        return (osig.sa_handler);
    }
}

void signal_wait_handlers(void)
{
    struct sigaction sig;

    sig.sa_handler = SIG_DFL;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    /* Ensure no more pending signals */
    sigaction(SIGTERM, &sig, NULL);
    sigaction(SIGINT, &sig, NULL);

    /* reset */
    signal_SIGTERM_v = NULL;
    signal_SIGINT_v = NULL;
}

int signal_rfd(void)
{
    return (signal_pipe[0]);
}

void signal_handler_destroy(void)
{
    signal_wait_handlers();
    close(signal_pipe[1]);
    close(signal_pipe[0]);
    signal_pipe[1] = -1;
    signal_pipe[0] = -1;
}



/* Handlers intialization */
void signal_handler_init(void)
{
    int n = pipe(signal_pipe);
    assert(!n);

    fcntl(signal_pipe[0], F_SETFL, O_NONBLOCK | fcntl(signal_pipe[0], F_GETFL));
    fcntl(signal_pipe[1], F_SETFL, O_NONBLOCK | fcntl(signal_pipe[1], F_GETFL));

    signal_SIGTERM_handler = NULL;
    signal_SIGINT_handler = NULL;
}


