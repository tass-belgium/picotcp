/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   This module handles the equalities between the IGMP and the MLD protocol
   Authors: Roel Postelmans
 *********************************************************************/

#include "pico_stack.h"
#include "pico_ipv6.h"
#include "pico_mld.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#include "pico_mld.h"
#include "pico_igmp.h"
#include "pico_constants.h"

#if ((defined(PICO_SUPPORT_MLD) && defined(PICO_SUPPORT_IPV6)) || (defined(PICO_SUPPORT_IGMP)) && defined(PICO_SUPPORT_MULTICAST)) 

#define multicast_dbg(...) do {} while(0)

#endif
