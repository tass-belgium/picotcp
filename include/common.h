/* VDE_ROUTER (C) 2007:2011 Daniele Lacamera
 *
 * Licensed under the GPLv2
 *
 */

#ifndef _PICOTCP_COMMON
#define _PICOTCP_COMMON
#include <libvdeplug.h>
#include <stdint.h>
#include <pthread.h>
#include "rbtree.h"
#include <semaphore.h>

struct pico_stack;
struct pico_queue;

/* IP address (generic) */
struct pico_ip4address {
	struct pico_ip4address *next;
	uint32_t address;
	uint32_t netmask;
};


/*
 * Filter interface
 */
enum filter_action {
	filter_accept = 0,
	filter_priority,
	filter_reject,
	filter_drop,
	filter_invalid = 255
};

struct pico_filter {
	struct pico_filter *next;
	struct pico_iface *src_iface;
	uint8_t proto;
	struct pico_ip4address saddr;
	struct pico_ip4address daddr;
	uint16_t sport;
	uint16_t dport;
	int tos;
	enum filter_action action;
	uint8_t priority;
	uint32_t stats_packets;
	uint32_t stats_bytes;
};



/* route */
struct pico_route {
	struct pico_route *next;
	uint32_t dest_addr;
	uint32_t netmask;
	uint32_t gateway;
	uint16_t metric;
	struct pico_iface *iface;
};

struct pico_timed_dequeue {
	struct pico_timed_dequeue *next;
	uint64_t last_out;
	uint32_t interval;
	struct pico_queue *q;
};

struct pico_stack {
	struct pico_iface *iflist;
	struct pico_route *routing_table;
	struct pico_filter *filtering_table;
	struct pico_timed_dequeue *timed_dequeue;
	pthread_mutex_t global_config_lock;
	pthread_t timer;
	uint32_t smallest_interval;
};

/* Buffer structure */

struct __attribute__ ((__packed__)) pico_buff 
{
	struct pico_buff *next;
	int len;
	struct pico_iface *src;
	uint8_t priority;
	unsigned char data[0];
};

#define QTYPE_OUT 0
#define QTYPE_PRIO 1

#define PRIO_ARP 1
#define PRIO_BESTEFFORT 15
#define PRIO_NUM 32

enum queue_policy_e {
	QPOLICY_UNLIMITED = 0,
	QPOLICY_FIFO,
	QPOLICY_RED,
	QPOLICY_TOKEN
};

/* Queue */
struct pico_queue {
	uint32_t n; /*< Number of packets */
	uint32_t size; /*< this is in bytes */
	pthread_mutex_t lock;
	sem_t semaphore;
	struct pico_buff *head;
	struct pico_buff *tail;
	uint8_t type;
	sem_t *prio_semaphore;

	enum queue_policy_e policy;
	int (*may_enqueue)(struct pico_queue *q, struct pico_buff *vb);
	int (*may_dequeue)(struct pico_queue *q);
	union policy_opt_e {
		struct {
			uint32_t limit;
			uint32_t stats_drop;
		} fifo;
		struct {
			uint32_t min;
			uint32_t max;
			double P;
			uint32_t limit;
			uint32_t stats_drop;
			uint32_t stats_probability_drop;
		} red;
		struct {
			uint32_t limit;
			uint32_t stats_drop;
			unsigned long long interval;
		} token;
	}policy_opt;
};


struct pico_iface {
	uint8_t interface_id;
	struct pico_iface *next;
	struct pico_ip4address *address_list;
	uint8_t macaddr[6];
	VDECONN *vdec;
	char pico_sock[1024];
	struct rb_root arp_table;
	struct pico_queue out_q;

	struct pico_queue prio_q[256];
	sem_t prio_semaphore;

	struct pico_stack *stack;
	pthread_t sender;
	pthread_t receiver;
	pthread_t queue_manager;
	pthread_t dhcpd;
	pthread_t dhcpclient;
	int dhcpd_started;
	struct {
		uint32_t sent;
		uint32_t recvd;
	} stats;
};

#endif
