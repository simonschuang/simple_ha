/*
 *              COPYRIGHT (c) 2009-2015  CCMA 
 *                     ALL RIGHTS RESERVED 
 *
 * Description: header file
 * Filename:    ha-agent.h
 * Author:      Simon Chuang, <shangyichuang@itri.org.tw>
 */
#ifndef _HA_AGENT_H
#define _HA_AGENT_H

#include <netinet/in.h>

typedef struct ha_agent HA_AGENT;

HA_AGENT *
ha_agent_create (void);

void
ha_agent_free (HA_AGENT *handle);

int
ha_agent_run (HA_AGENT *handle);

void
ha_agent_stop (HA_AGENT *handle);

void
ha_agent_if_name_set (char *name, HA_AGENT *handle);

char *
ha_agent_if_name_get (HA_AGENT *handle);

void
ha_agent_if_addr_set (struct in_addr *addr, HA_AGENT *handle);

int
ha_agent_node_addr_set (struct in_addr *addr, char *hostname, HA_AGENT *handle);

void
ha_agent_key_set (HA_AGENT *handle, void *key, int len);

#endif
