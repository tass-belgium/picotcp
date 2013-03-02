/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Daniele Lacamera
*********************************************************************/


#include "pico_protocol.h"
#include "pico_tree.h"

static int pico_proto_cmp(void *ka, void *kb)
{
	struct pico_protocol *a = ka, *b=kb;
  if (a->hash < b->hash)
    return -1;
  if (a->hash > b->hash)
    return 1;
  return 0;
}

PICO_TREE_DECLARE(Datalink_proto_tree,pico_proto_cmp);
PICO_TREE_DECLARE(Network_proto_tree,pico_proto_cmp);
PICO_TREE_DECLARE(Transport_proto_tree,pico_proto_cmp);
PICO_TREE_DECLARE(Socket_proto_tree,pico_proto_cmp);

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
  static struct pico_tree_node * next_node, * in_node, * out_node;

  if (next_in == NULL) {
  	in_node = pico_tree_firstNode(Datalink_proto_tree.root);
    next_in = in_node->keyValue;
  }
  if (next_out == NULL) {
    out_node = pico_tree_firstNode(Datalink_proto_tree.root);
    next_out = out_node->keyValue;
  }
  
  if (direction == PICO_LOOP_DIR_IN)
  {
  	next_node = in_node;
    next = next_in;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	next_node = out_node;
    next = next_out;
  }

  /* init start node */
  start = next;

  /* round-robin all datalink protocols, break if traversed all protocols */
  while (loop_score > DL_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score, direction);

    //next = RB_NEXT(pico_protocol_tree, &Datalink_proto_tree, next);
    next_node = pico_tree_next(next_node);
    next = next_node->keyValue;

    if (next == NULL)
    {
    	next_node = pico_tree_firstNode(Datalink_proto_tree.root);
    	next = next_node->keyValue;
    }
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
  {
  	in_node = next_node;
    next_in = next;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	out_node = next_node;
    next_out = next;
  }

  return loop_score;
}


#define NW_LOOP_MIN 1

int pico_protocol_network_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;
  static struct pico_tree_node * next_node, * in_node, * out_node;

  if (next_in == NULL) {
    in_node = pico_tree_firstNode(Network_proto_tree.root);
    if (in_node)
      next_in = in_node->keyValue;
  }
  if (next_out == NULL) {
  	out_node = pico_tree_firstNode(Network_proto_tree.root);
    if (out_node)
  	  next_out = out_node->keyValue;
  }
  if (direction == PICO_LOOP_DIR_IN)
  {
  	next_node = in_node;
    next = next_in;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	next_node = out_node;
    next = next_out;
  }

  /* init start node */
  start = next;

  /* round-robin all network protocols, break if traversed all protocols */
  while (loop_score > NW_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score, direction);

    next_node = pico_tree_next(next_node);
    next = next_node->keyValue;

    if (next == NULL)
    {
    	next_node = pico_tree_firstNode(Network_proto_tree.root);
    	next = next_node->keyValue;
    }
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
  {
  	in_node = next_node;
    next_in = next;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	out_node = next_node;
    next_out = next;
  }

  return loop_score;
}

#define TP_LOOP_MIN 1

int pico_protocol_transport_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;
  static struct pico_tree_node * next_node, * in_node, * out_node;

  if (next_in == NULL) {
  	in_node = pico_tree_firstNode(Transport_proto_tree.root);
  	next_in = in_node->keyValue;
  }
  if (next_out == NULL) {
  	out_node = pico_tree_firstNode(Transport_proto_tree.root);
  	next_out = out_node->keyValue;
  }
  
  if (direction == PICO_LOOP_DIR_IN)
  {
  	next_node = in_node;
    next = next_in;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	next_node = out_node;
    next = next_out;
  }

  /* init start node */
  start = next;

  /* round-robin all transport protocols, break if traversed all protocols */
  while (loop_score > DL_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score, direction);

    //next = RB_NEXT(pico_protocol_tree, &Transport_proto_tree, next);
    next_node = pico_tree_next(next_node);
    next = next_node->keyValue;

    if (next == NULL)
    {
    	next_node = pico_tree_firstNode(Transport_proto_tree.root);
    	next = next_node->keyValue;
    }
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
  {
  	in_node = next_node;
    next_in = next;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	out_node = next_node;
    next_out = next;
  }

  return loop_score;
}


#define SOCK_LOOP_MIN 1

int pico_protocol_socket_loop(int loop_score, int direction)
{
  struct pico_protocol *start;
  static struct pico_protocol *next = NULL, *next_in = NULL, *next_out = NULL;
  static struct pico_tree_node * next_node, * in_node, * out_node;

  if (next_in == NULL) {
  	in_node = pico_tree_firstNode(Socket_proto_tree.root);
  	next_in = in_node->keyValue;
  }
  if (next_out == NULL) {
  	out_node = pico_tree_firstNode(Socket_proto_tree.root);
    next_out = out_node->keyValue;
  }
  
  if (direction == PICO_LOOP_DIR_IN)
  {
  	next_node = in_node;
    next = next_in;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
	 	next_node = out_node;
  	next = next_out;
  }

  /* init start node */
  start = next;

  /* round-robin all transport protocols, break if traversed all protocols */
  while (loop_score > SOCK_LOOP_MIN && next != NULL) {
    loop_score = proto_loop(next, loop_score,direction);

    next_node = pico_tree_next(next_node);
    next = next_node->keyValue;

    if (next == NULL)
    {
      next_node = pico_tree_firstNode(next_node);
    	next = next_node->keyValue;
    }
    if (next == start)
      break;
  }

  if (direction == PICO_LOOP_DIR_IN)
  {
  	in_node = next_node;
    next_in = next;
  }
  else if (direction == PICO_LOOP_DIR_OUT)
  {
  	out_node = next_node;
    next_out = next;
  }

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
      pico_tree_insert(&Datalink_proto_tree, p);
      break;
    case PICO_LAYER_NETWORK:
      pico_tree_insert(&Network_proto_tree,p);
      break;
    case PICO_LAYER_TRANSPORT:
      pico_tree_insert(&Transport_proto_tree,p);
      break;
    case PICO_LAYER_SOCKET:
      pico_tree_insert(&Socket_proto_tree,p);
      break;
  }
  dbg("Protocol %s registered (layer: %d).\n", p->name, p->layer);

}

