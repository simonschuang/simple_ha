/*
 * librs_Monitor.h
 *
 *  Created on: 2014/12/3
 *      Author: Hogan
 */

#ifndef LIBRS_MONITOR_H_
#define LIBRS_MONITOR_H_

#include <Monitor.h>
#include "librs_c_session.h"

int
librs_createInstPerfByInstUUID (librs_c_session *session,
                                instPerf *inst_perf);

int
librs_createNodePerfByIP (librs_c_session *session,
                          nodePerf *node_perf);

int
librs_sendHttpLatency2RS (librs_c_session *session,
                          httpLatency *http_latency);

/* to insert bulk of nex-NULL-ENDED list of `instPerf`
 * into RS table `inst_performance`
 * expected to be called periodically, (every 3 sec, maybe)
 * return : 0 means NO Error, else means Error code
 * */
int
librs_createInstPerfList (librs_c_session *session,
                          const instPerf *pFirstInstPerf);

int
librs_createDailyInstPerf (librs_c_session *session,
                           const DailyPerfData *pDailyPerfData,
                           int iInstId,
                           int iVcId);

int
librs_createDailyVcPerf (librs_c_session *session,
                         const int iVcId,
                         const DailyPerfData *pDailyPerfData,
                         int iVdcId);

int
librs_createDailyVdcPerf (librs_c_session *session,
                          const int iVdcId,
                          const DailyPerfData *pDailyPerfData);

/* return 0 means no error existed */
int
librs_getIDsFromInstUuid (librs_c_session *session,
                          const char *szInstUuid,
                          int *piInstId,
                          int *piVcId,
                          int *piVdcId);
/*
IN: pSession, szInstUuid
OUTPUT : return value 0 means NO error, else some error happened.
    If piInstId!= NULL, then corresponding inst_id will be set to it
    If piVcId!= NULL, then corresponding vc_id will be set to it
    If piVdcId!= NULL, then corresponding vdc_id will be set to it

*/

#endif // LIBRS_MONITOR_H_
