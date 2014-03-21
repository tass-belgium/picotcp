/*********************************************************************
    PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
    See LICENSE and COPYING for usage.

    Author: Toon Stegen
 *********************************************************************/
#ifndef INCLUDE_PICO_NTP_CLIENT
#define INCLUDE_PICO_NTP_CLIENT

#include "pico_config.h"

struct pico_timeval
{
    pico_time tv_sec;
    pico_time tv_msec;
};

int pico_ntp_sync(const char *ntp_server, void (*cb_synced)());
int pico_ntp_gettimeofday(struct pico_timeval *tv);

#endif /* _INCLUDE_PICO_NTP_CLIENT */
