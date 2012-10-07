#include "vde_headers.h"
#include "vde_router.h"
#include "pico_queue.h"
#include "pico_datalink.h"
#include "pico_packet.h"
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifndef __PICO_UDP_H
#define __PICO_UDP_H


struct pico_udp_socket {
	struct pico_udp_socket *next;
	uint16_t port;
	struct pico_queue inq;
};

#define UDPSOCK_BUFFER_SIZE 1024 * 16

struct pico_udp_socket *get_by_port(uint16_t port);


/* interface toward the router */
int pico_udp_recv(struct pico_buff *buf);
struct pico_udp_socket *pico_udpsocket_open(uint16_t port);
void pico_udp_close(struct pico_udp_socket *sock);
int pico_udpsocket_sendto(struct pico_udp_socket *sock, void *data, size_t len, uint32_t dst, uint16_t dstport);
int pico_udpsocket_sendto_broadcast(struct pico_udp_socket *sock, void *data, size_t len,
	struct pico_iface *iface, uint32_t dst, uint16_t dstport);
int pico_udpsocket_recvfrom(struct pico_udp_socket *sock, void *data, size_t len, uint32_t *from, uint16_t *fromport, int timeout);

#endif
