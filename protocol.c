#include <stdint.h>
#include "pico_frame.h"
#include "pico_device.h"
#include "pico_protocol.h"
#include "pico_addressing.h"
/* Generic interface for protocols.
 * Specific protocol modules must implement the following:
 * pico_<proto>_process_in()
 * pico_<proto>_process_out()
 * pico_<proto>_overhead()
 *
 *
 */


/** frame alloc/dealloc/copy **/

/* Temporary (POSIX) */
#include <stdlib.h>
#include <string.h>
#define pico_zalloc(x) calloc(x, 1)
#define pico_free(x) free(x)

void pico_frame_discard(struct pico_frame *f)
{
  *f->usage_count--;
  if (*f->usage_count <= 0) {
    pico_free(f->usage_count);
    pico_free(f->buffer);
    pico_free(f);
  }
}


struct pico_frame *pico_frame_copy(struct pico_frame *f)
{
  struct pico_frame *new = pico_zalloc(sizeof(struct pico_frame));
  if (!new)
    return NULL;
  memcpy(new, f, sizeof(struct pico_frame));
  *f->usage_count++;
  return new;
}

struct pico_frame *pico_frame_alloc(int size)
{
  struct pico_frame *p = pico_zalloc(sizeof(struct pico_frame));
  if (!p)
    return NULL;
  p->buffer = pico_zalloc(size);
  if (!p->buffer) {
    pico_free(p);
    return NULL;
  }
  p->usage_count = pico_zalloc(sizeof(uint32_t));
  if (!p->usage_count) {
    pico_free(p->buffer);
    pico_free(p);
    return NULL;
  }
  p->buffer_len = size;
  *p->usage_count = 1;
  return p;
}

/* SOCKET LEVEL: interface towards transport */
int pico_socket_receive(struct pico_frame *f)
{
  /* TODO: recognize the correspondant socket */
  return 0;
}

/* TRANSPORT LEVEL: interface towards network */
int pico_transport_receive(struct pico_frame *f)
{
  /* TODO: identify transport level, deliver packet to the 
   * correct destination (e.g. socket)*/
  return 0;
}

int pico_network_receive(struct pico_frame *f)
{
  /* TODO: dispatch packet to the correspondant ip layer */
  return 0;
}

/* LOWEST LEVEL: interface towards devices. */
int picotcp_stack_recv(struct pico_device *dev, uint8_t *buffer, int len)
{
  struct pico_frame *f;
  if (len <= 0)
    return -1;
  f = pico_frame_alloc(len);
  if (!f)
    return -1;
  memcpy(f->buffer, buffer, len);
  return pico_enqueue(dev->q_in, f);
}

int pico_sendto_dev(struct pico_frame *f)
{
  if (!f->dev) {
    pico_frame_discard(f);
    return -1;
   } else {
    return pico_enqueue(f->dev->q_out, f);
   }
}

void pico_dev_loop(struct pico_device *dev, int loop_score)
{
  struct pico_frame *f;
  while(loop_score > 0) {
    if (dev->q_in->frames + dev->q_out->frames <= 0)
      break;

    /* Device dequeue + send */
    f = pico_dequeue(dev->q_out);
    if (f) {
      dev->send(dev, f->buffer, f->buffer_len);
      pico_frame_discard(f);
      loop_score--;
    }

    /* Receive */
    f = pico_dequeue(dev->q_in);
    if (f) {
      if (dev->eth) {
        pico_ethernet_receive(f);
      } else {
        pico_network_receive(f);
      }
      loop_score--;
    }
  }
}


void pico_proto_loop(struct pico_protocol *proto, int loop_score)
{
  struct pico_frame *f;
  while(loop_score >0) {
    if (proto->q_in->frames + proto->q_out->frames <= 0)
      break;

    f = pico_dequeue(proto->q_out);
    if ((f) &&(proto->process_out(proto, f) > 0)) {
      loop_score--;
    }

    f = pico_dequeue(proto->q_in);
    if ((f) &&(proto->process_in(proto, f) > 0)) {
      loop_score--;
    }
  }
}
