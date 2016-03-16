/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: Include file for interface.c
 * Filename:    interface.h
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 *
 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

#include <net/if.h>
#include <libha.h>
#include "ha-agent.h"

#define HWADDR_IS_ZERO(x) \
        ((x[0] == 0) && (x[1] == 0) && \
         (x[2] == 0) && (x[3] == 0) && \
         (x[4] == 0) && (x[5] == 0)) ? 1 : 0 \

int bind_if_init(HA_AGENT *handle);

#endif
