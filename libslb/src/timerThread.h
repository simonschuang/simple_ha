/*
 * timerThread.h
 *
 *  Created on: 2011/12/2
 *      Author: 990430
 */

#ifndef TIMERTHREAD_H_
#define TIMERTHREAD_H_

#include <pthread.h>  // pthread_t
#include <sys/time.h>  // struct timeval

// A thread that regularly execute a specified function with a timer
struct TimerThread {
// Private
    pthread_t tid;  // The ID of thread
    int flagRun;  // Indicate whether to keep running thread, 0: stop thread, 1:run thread
    struct timeval time;  // The time to execute function once
    void (*fun)(void *_parameter);  // A function to execute regularly
    void *parameter;  // A pointer points to the parameter as the input of the function. TimerThread has no responsibility to free parameter.
};

// Public
void timerThread_constructor(struct TimerThread *_this,
    void (*_fun)(void *parmameter), void *_parameter, const struct timeval *_time, int _flagRun);
void timerThread_destructor(struct TimerThread *_this);
int timerThread_isRunning(struct TimerThread *_this);
pthread_t timerThread_getTid(struct TimerThread *_this);
int timerThread_run(struct TimerThread *_this);
void timerThread_setTime(struct TimerThread *_this, const struct timeval *_time);
// Private
void *timerThread_thread(void *_parameter);

#endif /* TIMERTHREAD_H_ */
