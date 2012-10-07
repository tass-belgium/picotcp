#ifndef __VDER_OLSR
#define __VDER_OLSR

#include "vder_arp.h"
#include "vde_router.h"

#define OLSR_PORT (htons(698))

#define OLSRMSG_HELLO 	0xc9
#define OLSRMSG_MID		0x03
#define OLSRMSG_TC		0xca

#define OLSRLINK_SYMMETRIC 0x06
#define OLSRLINK_UNKNOWN 0x08
#define OLSRLINK_MPR	0x0a

struct __attribute__((packed)) olsr_link
{
	uint8_t link_code;
	uint8_t reserved;
	uint16_t link_msg_size;
};

struct __attribute__((packed)) olsr_neighbor
{
	uint32_t addr;
	uint8_t  lq;
	uint8_t  nlq;
	uint16_t reserved;
};

struct __attribute__((packed)) olsr_hmsg_hello
{
	uint16_t reserved;
	uint8_t htime;
	uint8_t willingness;
};

struct __attribute__((packed)) olsr_hmsg_tc
{
	uint16_t ansn;
	uint16_t reserved;
};


struct __attribute__((packed)) olsrmsg
{
	uint8_t type;
	uint8_t vtime;
	uint16_t size;
	uint32_t orig;
	uint8_t ttl;
	uint8_t hop;
	uint16_t seq;
};

struct __attribute__((packed)) olsrhdr
{
	uint16_t len;
	uint16_t seq;
};


struct olsr_setup {
	int n_ifaces;
	struct vder_iface *ifaces[64];
};

void *vder_olsr_loop(void *olsr_setup);

#endif
