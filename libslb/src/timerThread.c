/*
 * timerThread.c
 *
 *  Created on: 2011/12/2
 *      Author: 990430
 */
#include <errno.h>  // errno, ESRCH
#include <pthread.h>  // pthread_t
#include <signal.h>  // pthread_kill()
#include <string.h>  // memset
#include <unistd.h>  // usleep(), sleep()
#include <sys/time.h>  // struct timeval
#include "timerThread.h"

// Default constructor of TimerThread
void timerThread_constructor(struct TimerThread *_this,
    void (*_fun)(void *parmameter), void *_parameter, const struct timeval *_time, int _flagRun)
{
    // Use parameter to initial properties
    _this->fun = _fun;
    _this->parameter = _parameter;
    _this->flagRun = _flagRun;
    timerThread_setTime(_this, _time);

    // Initial properties with default value
    _this->tid = 0;

    // Create thread and run
    if (_this->flagRun && _this->fun) {
        timerThread_run(_this);
    }
}

// Default destructor of TimerThread
void timerThread_destructor(struct TimerThread *_this)
{
    if (timerThread_isRunning(_this)) {
        _this->flagRun = 0;
        pthread_join(_this->tid, NULL);
    }
    _this->fun = NULL;
    _this->parameter = NULL;
    timerThread_setTime(_this, NULL);
    _this->tid = 0;
}

// Check whether the thread is running
// Return 1: The tread is running
// Return 0: the tread stopped
int timerThread_isRunning(struct TimerThread *_this)
{
    if (_this->flagRun && _this->tid && pthread_kill(_this->tid, 0) != ESRCH)
        return 1;
    return 0;
}

// Get thread ID
pthread_t timerThread_getTid(struct TimerThread *_this)
{
    return _this->tid;
}

// Run thread if it's stopped
int timerThread_run(struct TimerThread *_this)
{
    int ret = 0;

    if (!timerThread_isRunning(_this) && _this->fun != NULL) {
        _this->flagRun = 1;
        if ((ret = pthread_create(&_this->tid, NULL, timerThread_thread, (void*)_this)) != 0) {
            _this->tid = 0;
            _this->flagRun = 0;
            ret = -1;
        }
    }

    return ret;
}

// Set timer
void timerThread_setTime(struct TimerThread *_this, const struct timeval *_time)
{
    if (_time == NULL) {
        _this->time.tv_sec = 0;
        _this->time.tv_usec = 0;
    } else {
        _this->time = *_time;
    }
    if (_this->time.tv_sec < 0)
        _this->time.tv_sec = 0;
    if (_this->time.tv_usec < 0)
        _this->time.tv_usec = 0;
    while (_this->time.tv_usec >= 1000000) {
        ++_this->time.tv_sec;
        _this->time.tv_usec -= 1000000;
    }
}

// Thread to execute function periodically according to the time
void *timerThread_thread(void *_parameter)
{
    struct TimerThread *_this = (struct TimerThread *)_parameter;
    struct timeval timeout = _this->time;
    time_t timeCount = timeout.tv_sec;

    while (_this->flagRun) {
        // Update timeout
        timeout = _this->time;
        if (++timeCount >= timeout.tv_sec) {
            // Execute function
            _this->fun(_this->parameter);
            timeCount = 0;
            if (timeout.tv_usec > 0)
                usleep(timeout.tv_usec);
        }
        if (timeout.tv_sec > 0)
            sleep(1);
    }

    pthread_exit(NULL);
}
