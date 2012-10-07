/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#ifndef __VDER_QUEUE
#define __VDER_QUEUE
#include <stdint.h>
#include "vde_router.h"
#include "vder_datalink.h"
void enqueue(struct vder_queue *q, struct vde_buff *b);
struct vde_buff *prio_dequeue(struct vder_iface *vif);
struct vde_buff *dequeue(struct vder_queue *q);

void qunlimited_setup(struct vder_queue *q);
void qfifo_setup(struct vder_queue *q, uint32_t limit);
void qred_setup(struct vder_queue *q, uint32_t min, uint32_t max, double P, uint32_t limit);
void qtoken_setup(struct vder_queue *q, uint32_t bitrate, uint32_t limit);


int qunlimited_may_enqueue(struct vder_queue *q, struct vde_buff *b);
int qunlimited_may_dequeue(struct vder_queue *q);

int qfifo_may_enqueue(struct vder_queue *q, struct vde_buff *b);
int qfifo_may_dequeue(struct vder_queue *q);

int qred_may_enqueue(struct vder_queue *q, struct vde_buff *b);
int qred_may_dequeue(struct vder_queue *q);


#endif
