/*********************************************************************
 PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
 See LICENSE and COPYING for usage.

 Authors: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_802154.h"
#include "pico_6lowpan.h"
#include "pico_addressing.h"
#include "pico_ipv6_nd.h"
#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_ipv6.h"
#include "pico_udp.h"

#ifdef PICO_SUPPORT_6LOWPAN

/******************************************************************************
 *  Macros
 ******************************************************************************/

#define DEBUG 1
#if DEBUG == 1
    #define SLP_DBG(s, ...)         dbg("[6LoWPAN]$ " s, \
                                        ##__VA_ARGS__)
    #define SLP_ERR(s, ...)         dbg("[6LoWPAN]$ ERROR: %s: %d: " s, \
                                        __FUNCTION__, __LINE__, ##__VA_ARGS__)
    #define SLP_DBG_C               dbg
#else
    #define SLP_DBG(...)            do {} while(0)
    #define SLP_DBG_C(...)          do {} while(0)
    #define SLP_ERR(...)            do {} while(0)
#endif

/******************************************************************************
 *  Preprocessor defines
 ******************************************************************************/

/******************************************************************************
 *  Global Variables
 ******************************************************************************/

/* Queues */
static struct pico_queue pico_6lowpan_in = {
    0
};
static struct pico_queue pico_6lowpan_out = {
    0
};

/******************************************************************************
 *  Forward declarations
 ******************************************************************************/

static int pico_6lowpan_process_out(struct pico_protocol *self,
                                    struct pico_frame *f);
static int pico_6lowpan_process_in(struct pico_protocol *self,
                                   struct pico_frame *f);

/******************************************************************************
 *  Interface: protocol definition
 ******************************************************************************/

struct pico_protocol pico_proto_6lowpan = {
    .name = "6lowpan",
    .layer = PICO_LAYER_DATALINK,
    .process_in = pico_6lowpan_process_in,
    .process_out = pico_6lowpan_process_out,
    .q_in = &pico_6lowpan_in,
    .q_out = &pico_6lowpan_out
};

static int pico_6lowpan_process_out(struct pico_protocol *self,
                                    struct pico_frame *f)
{
    (void *)self;
    (void *)f;

    return 0;
}

static int pico_6lowpan_process_in(struct pico_protocol *self,
                                   struct pico_frame *f)
{
    (void *)self;
    (void *)f;

    return 0;
}

#endif /* PICO_SUPPORT_6LOWPAN */
/******************************************************************************/
/******************************************************************************/
