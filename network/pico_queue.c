/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */
#include "pico_queue.h"
#include "pico_headers.h"
#include <stdlib.h>

void enqueue(struct pico_queue *q, struct pico_buff *b)
{
	pthread_mutex_lock(&q->lock);

	if (!q->may_enqueue(q, b)) {
		free(b);
		pthread_mutex_unlock(&q->lock);
		return;
	}

	b->next = NULL;
	if (!q->head) {
		q->head = b;
		q->tail = b;
	} else {
		q->tail->next = b;
		q->tail = b;
	}
	q->size += b->len;
	q->n++;
	pthread_mutex_unlock(&q->lock);
	if (q->policy != QPOLICY_TOKEN) {
		if (q->type != QTYPE_PRIO)
			sem_post(&q->semaphore);
		else
			sem_post(q->prio_semaphore);
	}
}

struct pico_buff *prio_dequeue(struct pico_iface *vif)
{
	struct pico_queue *q;
	int i;
	struct pico_buff *ret = NULL;
	sem_wait(&vif->prio_semaphore);
	for (i = 0; i < PRIO_NUM; i++) {
		q = &(vif->prio_q[i]);
		pthread_mutex_lock(&q->lock);
		if (q->size == 0){
			pthread_mutex_unlock(&q->lock);
			continue;
		}
		if (q->n) {
			ret = q->head;
			q->head = ret->next;
			q->n--;
			q->size -= ret->len;
			if (q->n == 0) {
				q->tail = NULL;
				q->head = NULL;
			}
			pthread_mutex_unlock(&q->lock);
			break;
		}
		pthread_mutex_unlock(&q->lock);
	}
	return ret;
}

struct pico_buff *dequeue(struct pico_queue *q)
{
	struct pico_buff *ret = NULL;
	if (q->type != QTYPE_PRIO)
		sem_wait(&q->semaphore);
	else
		return NULL;
	pthread_mutex_lock(&q->lock);
	if (q->n) {
		ret = q->head;
		q->head = ret->next;
		q->n--;
		q->size -= ret->len;
		if (q->n == 0) {
			q->tail = NULL;
			q->head = NULL;
		}
	}
	pthread_mutex_unlock(&q->lock);
	return ret;
}

/* Unlimited policy */
int qunlimited_may_enqueue(struct pico_queue *q, struct pico_buff *b)
{
	return 1;
}


void qunlimited_setup(struct pico_queue *q)
{
	pthread_mutex_lock(&q->lock);
	if (q->policy == QPOLICY_TOKEN) {
		pico_timed_dequeue_del(q);
	}
	q->policy = QPOLICY_UNLIMITED;
	q->may_enqueue = qunlimited_may_enqueue;
	pthread_mutex_unlock(&q->lock);
}


/* Fifo policy */
int qfifo_may_enqueue(struct pico_queue *q, struct pico_buff *b)
{
	if (q->policy_opt.fifo.limit > q->size)
		return 1;
	else {
		q->policy_opt.fifo.stats_drop++;
		return 0;
	}
}


void qfifo_setup(struct pico_queue *q, uint32_t limit)
{
	pthread_mutex_lock(&q->lock);
	if (q->policy == QPOLICY_TOKEN) {
		pico_timed_dequeue_del(q);
	}
	q->policy = QPOLICY_FIFO;
	q->policy_opt.fifo.limit = limit;
	q->policy_opt.fifo.stats_drop = 0;
	q->may_enqueue = qfifo_may_enqueue;
	pthread_mutex_unlock(&q->lock);
}

/* Random early detection */
int qred_may_enqueue(struct pico_queue *q, struct pico_buff *b)
{
	double red_probability;
	if (q->policy_opt.red.min > q->size) {
		return 1;
	} else if (q->policy_opt.red.max > q->size) {
		red_probability = q->policy_opt.red.P *
				((double)q->size - (double)q->policy_opt.red.min /
				((double)q->policy_opt.red.max - (double)q->policy_opt.red.min));
	} else if (q->policy_opt.red.limit > q->size) {
		red_probability = q->policy_opt.red.P;
	} else {
		q->policy_opt.red.stats_drop++;
		return 0;
	}
	if (drand48() < red_probability) {
		q->policy_opt.red.stats_probability_drop++;
		return 0;
	}
	return 1;
}


void qred_setup(struct pico_queue *q, uint32_t min, uint32_t max, double P, uint32_t limit)
{
	pthread_mutex_lock(&q->lock);
	if (q->policy == QPOLICY_TOKEN) {
		pico_timed_dequeue_del(q);
	}
	q->policy = QPOLICY_RED;
	q->policy_opt.red.min = min;
	q->policy_opt.red.max = max;
	q->policy_opt.red.P = P;
	q->policy_opt.red.limit = limit;
	q->policy_opt.red.stats_drop = 0;
	q->policy_opt.red.stats_probability_drop = 0;
	q->may_enqueue = qred_may_enqueue;
	pthread_mutex_unlock(&q->lock);
}

#define IDEAL_PACKET_SIZE 1500

int qtoken_may_enqueue(struct pico_queue *q, struct pico_buff *b)
{
	if (q->policy_opt.token.limit > q->size)
		return 1;
	else {
		q->policy_opt.token.stats_drop++;
		return 0;
	}
}

void qtoken_setup(struct pico_queue *q, uint32_t bitrate, uint32_t limit)
{
	pthread_mutex_lock(&q->lock);
	q->policy_opt.token.interval = (1000000 * IDEAL_PACKET_SIZE) / ((bitrate >> 3));
	q->policy_opt.token.limit = limit;
	q->policy_opt.token.stats_drop = 0U;
	if (q->policy == QPOLICY_TOKEN) {
		pico_timed_dequeue_del(q);
	}
	q->policy = QPOLICY_TOKEN;
	pico_timed_dequeue_add(q, q->policy_opt.token.interval);
	q->may_enqueue = qtoken_may_enqueue;
	pthread_mutex_unlock(&q->lock);
}

