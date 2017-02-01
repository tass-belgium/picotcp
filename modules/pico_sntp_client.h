/*********************************************************************
    PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
    See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

    Author: Toon Stegen
 *********************************************************************/
#ifndef INCLUDE_PICO_SNTP_CLIENT
#define INCLUDE_PICO_SNTP_CLIENT

#include "pico_config.h"
#include "pico_protocol.h"

struct pico_timeval
{
    pico_time tv_sec;
    pico_time tv_msec;
};

int pico_sntp_sync(const char *sntp_server, void (*cb_synced)(pico_err_t status));
int pico_sntp_sync_ip(union pico_address *sntp_addr, void (*cb_synced)(pico_err_t status));
int pico_sntp_gettimeofday(struct pico_timeval *tv);

#endif /* _INCLUDE_PICO_SNTP_CLIENT */
