/*********************************************************************
   PicoTCP. Copyright (c) 2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

  Author: Daniele Lacamera <daniele.lacamera@altran.com>
 *********************************************************************/
#ifndef PICO_AODV_H_
#define PICO_AODV_H_
#include <stdint.h>

#define AODV_TYPE_RREQ 1
#define AODV_TYPE_RREP 2
#define AODV_TYPE_RERR 3
#define AODV_TYPE_RACK 4

PACKED_STRUCT_DEF pico_aodv_rreq
{
    uint8_t type;
    uint16_t req_flags;
    uint8_t hop_count;
    uint32_t rreq_id;
    uint32_t dest;
    uint32_t dseq;
    uint32_t orig;
    uint32_t oseq;
};

#define AODV_RREQ_FLAG_J 0x8000
#define AODV_RREQ_FLAG_R 0x4000
#define AODV_RREQ_FLAG_G 0x2000
#define AODV_RREQ_FLAG_D 0x1000
#define AODV_RREQ_FLAG_U 0x0800
#define AODV_RREQ_FLAG_RESERVED 0x07FF

PACKED_STRUCT_DEF pico_aodv_rrep
{
    uint8_t type;
    uint8_t rep_flags;
    uint8_t prefix_sz;
    uint8_t hop_count;
    uint32_t dest;
    uint32_t dseq;
    uint32_t orig;
    uint32_t lifetime;
};

#define AODV_RREP_MAX_PREFIX 0x1F
#define AODV_RREP_FLAG_R 0x80
#define AODV_RREP_FLAG_A 0x40
#define AODV_RREQ_FLAG_RESERVED 0x3F

PACKED_STRUCT_DEF pico_aodv_node
{
    uint32_t dest;
    uint32_t dseq;  
};

PACKED_STRUCT_DEF pico_aodv_rerr
{
    uint8_t type;
    uint16_t rerr_flags;
    uint8_t dst_count;
    struct pico_aodv_node unreach[1]; /* unrechable nodes: must be at least 1. See dst_count field above */
};

#endif
