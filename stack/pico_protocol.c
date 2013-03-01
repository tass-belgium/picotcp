/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Daniele Lacamera
*********************************************************************/


#include "pico_protocol.h"
#include "rb.h"

RB_HEAD(pico_protocol_tree, pico_protocol);
RB_PROTOTYPE_STATIC(pico_protocol_tree, pico_protocol, node, pico_proto_cmp);

static struct pico_protocol_tree Datalink_proto_tree;
static struct pico_protocol_tree Network_proto_tree;
static struct pico_protocol_tree Transport_proto_tree;
static struct pico_protocol_tree Socket_proto_tree;


static int pico_proto_cmp(struct pico_protocol *a, struct pico_protocol *b)
{
  if (a->hash < b->hash)
    return -1;
  if (a->hash > b->hash)
    return 1;
  return 0;
}

RB_GENERATE_STATIC(pico_protocol_tree, pico_protocol, node, pico_proto_cmp);


static int proto_loop(struct pico_protocol *proto, int loop_score, int direction)
{
  struct pico_frame *f;

  if (direction == PICO_LOOP_DIR_IN) {

    while(loop_score >0) {
      if (proto->q_in->frames <= 0)
        break;

      f = pico_dequeue(proto->q_in);
      if ((f) &&(proto->process_in(proto, f) > 0)) {
        loop_score--;
      }
    }

  } else if (direction == PICO_LOOP_DIR_OUT) {

    while(loop_score >0) {
      if (proto->q_out->frames <= 0)
        break;

      f = pico_dequeue(proto->q_out);
      if ((f) &&(proto->process_out(proto, f) > 0)) {
        loop_score--;
      }
    }
  }

  return loop_score;
}

#define DL_LOOP_MIN 1

int pico_protocol_datalink_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;

  if (next_in == NULL) {
    next_in = RB_MIN(pico_protocol_tree, &Datalink_proto_tree);
  }
  if (next_out == NULL) {
    next_out = RB_MIN(pico_protocol_tree, &Datalink_proto_tree);
  }
  
  if (direction == PICO_LOOP_DIR_IN)
    next = next_in;
  else if (direction == PICO_LOOP_DIR_OUT)
    next = next_out;

  /* init start node */
  start = next;

  /* round-robin all datalink protocols, break if traversed all protocols */
  while (loop_score > DL_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score, direction);

    next = RB_NEXT(pico_protocol_tree, &Datalink_proto_tree, next);
    if (next == NULL)
      next = RB_MIN(pico_protocol_tree, &Datalink_proto_tree);
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
    next_in = next;
  else if (direction == PICO_LOOP_DIR_OUT)
    next_out = next;

  return loop_score;
}


#define NW_LOOP_MIN 1

int pico_protocol_network_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;

  if (next_in == NULL) {
    next_in = RB_MIN(pico_protocol_tree, &Network_proto_tree);
  }
  if (next_out == NULL) {
    next_out = RB_MIN(pico_protocol_tree, &Network_proto_tree);
  }
  
  if (direction == PICO_LOOP_DIR_IN)
    next = next_in;
  else if (direction == PICO_LOOP_DIR_OUT)
    next = next_out;

  /* init start node */
  start = next;

  /* round-robin all network protocols, break if traversed all protocols */
  while (loop_score > NW_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score, direction);

    next = RB_NEXT(pico_protocol_tree, &Network_proto_tree, next);
    if (next == NULL)
      next = RB_MIN(pico_protocol_tree, &Network_proto_tree);
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
    next_in = next;
  else if (direction == PICO_LOOP_DIR_OUT)
    next_out = next;

  return loop_score;
}

#define TP_LOOP_MIN 1

int pico_protocol_transport_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;

  if (next_in == NULL) {
    next_in = RB_MIN(pico_protocol_tree, &Transport_proto_tree);
  }
  if (next_out == NULL) {
    next_out = RB_MIN(pico_protocol_tree, &Transport_proto_tree);
  }
  
  if (direction == PICO_LOOP_DIR_IN)
    next = next_in;
  else if (direction == PICO_LOOP_DIR_OUT)
    next = next_out;

  /* init start node */
  start = next;

  /* round-robin all transport protocols, break if traversed all protocols */
  while (loop_score > DL_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score, direction);

    next = RB_NEXT(pico_protocol_tree, &Transport_proto_tree, next);
    if (next == NULL)
      next = RB_MIN(pico_protocol_tree, &Transport_proto_tree);
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
    next_in = next;
  else if (direction == PICO_LOOP_DIR_OUT)
    next_out = next;

  return loop_score;
}


#define SOCK_LOOP_MIN 1

int pico_protocol_socket_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;

  if (next_in == NULL) {
    next_in = RB_MIN(pico_protocol_tree, &Socket_proto_tree);
  }
  if (next_out == NULL) {
    next_out = RB_MIN(pico_protocol_tree, &Socket_proto_tree);
  }
  
  if (direction == PICO_LOOP_DIR_IN)
    next = next_in;
  else if (direction == PICO_LOOP_DIR_OUT)
    next = next_out;

  /* init start node */
  start = next;

  /* round-robin all transport protocols, break if traversed all protocols */
  while (loop_score > SOCK_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score,direction);

    next = RB_NEXT(pico_protocol_tree, &Socket_proto_tree, next);
    if (next == NULL)
      next = RB_MIN(pico_protocol_tree, &Socket_proto_tree);
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
    next_in = next;
  else if (direction == PICO_LOOP_DIR_OUT)
    next_out = next;

  return loop_score;
}

int pico_protocols_loop(int loop_score)
{
/*
  loop_score = pico_protocol_datalink_loop(loop_score);
  loop_score = pico_protocol_network_loop(loop_score);
  loop_score = pico_protocol_transport_loop(loop_score);
  loop_score = pico_protocol_socket_loop(loop_score);
*/
  return loop_score;
}

void pico_protocol_init(struct pico_protocol *p)
{
  if (!p)
    return;

  p->hash = pico_hash(p->name);
  switch (p->layer) {
    case PICO_LAYER_DATALINK:
      RB_INSERT(pico_protocol_tree, &Datalink_proto_tree, p);
      break;
    case PICO_LAYER_NETWORK:
      RB_INSERT(pico_protocol_tree, &Network_proto_tree, p);
      break;
    case PICO_LAYER_TRANSPORT:
      RB_INSERT(pico_protocol_tree, &Transport_proto_tree, p);
      break;
    case PICO_LAYER_SOCKET:
      RB_INSERT(pico_protocol_tree, &Socket_proto_tree, p);
      break;
  }
  dbg("Protocol %s registered (layer: %d).\n", p->name, p->layer);

}

