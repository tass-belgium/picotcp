/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

Authors: Daniele Lacamera
*********************************************************************/


#include "pico_config.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_protocol.h"
#include "pico_tree.h"


static int pico_dev_cmp(void *ka, void *kb)
{
	struct pico_device *a = ka, *b = kb;
  if (a->hash < b->hash)
    return -1;
  if (a->hash > b->hash)
    return 1;
  return 0;
}

PICO_TREE_DECLARE(Device_tree,pico_dev_cmp);

int pico_device_init(struct pico_device *dev, const char *name, uint8_t *mac)
{
	int len = strlen(name);
	if(len>MAX_DEVICE_NAME)
		len = MAX_DEVICE_NAME;
  memcpy(dev->name, name, len);
  dev->hash = pico_hash(dev->name);

  pico_tree_insert(&Device_tree,dev);
  dev->q_in = pico_zalloc(sizeof(struct pico_queue));
  dev->q_out = pico_zalloc(sizeof(struct pico_queue));

  if (mac) {
    dev->eth = pico_zalloc(sizeof(struct pico_ethdev));
    memcpy(dev->eth->mac.addr, mac, PICO_SIZE_ETH);
  } else {
    dev->eth = NULL;
  }

  if (!dev->q_in || !dev->q_out || (mac && !dev->eth))
    return -1;
  return 0;
}

void pico_device_destroy(struct pico_device *dev)
{
  if (dev->destroy)
    dev->destroy(dev);

  if (dev->q_in) {
    pico_queue_empty(dev->q_in);
    pico_free(dev->q_in);
  }
  if (dev->q_out) {
    pico_queue_empty(dev->q_out);
    pico_free(dev->q_out);
  }

  if (dev->eth)
    pico_free(dev->eth);

  pico_tree_delete(&Device_tree,dev);
  pico_free(dev);
}

static int devloop(struct pico_device *dev, int loop_score, int direction)
{
  struct pico_frame *f;

  /* If device supports interrupts, read the value of the condition and trigger the dsr */
  if ((dev->__serving_interrupt) && (dev->dsr)) {
    /* call dsr routine */
    loop_score = dev->dsr(dev, loop_score);
  }

  /* If device supports polling, give control. Loop score is managed internally, 
   * remaining loop points are returned. */
  if (dev->poll) {
    loop_score = dev->poll(dev, loop_score);
  }

  if (direction == PICO_LOOP_DIR_OUT) {

    while(loop_score > 0) {
      if (dev->q_out->frames <= 0)
        break;

      /* Device dequeue + send */
      f = pico_dequeue(dev->q_out);
      if (f) {
        if (dev->eth) {
          int ret = pico_ethernet_send(f);
          if (0 == ret) {
            loop_score--;
            continue;
          } if (ret < 0) {
            if (!pico_source_is_local(f)) { 
              dbg("Destination unreachable -------> SEND ICMP\n");
              pico_notify_dest_unreachable(f);
            } else {
              dbg("Destination unreachable -------> LOCAL\n");
            }
            pico_frame_discard(f);
            continue;
          }
        } else {
          dev->send(dev, f->start, f->len);
        }
        pico_frame_discard(f);
        loop_score--;
      }
    }

  } else if (direction == PICO_LOOP_DIR_IN) {

    while(loop_score > 0) {
      if (dev->q_in->frames <= 0)
        break;

      /* Receive */
      f = pico_dequeue(dev->q_in);
      if (f) {
        if (dev->eth) {
          f->datalink_hdr = f->buffer;
          pico_ethernet_receive(f);
        } else {
          f->net_hdr = f->buffer;
          pico_network_receive(f);
        }
        loop_score--;
      }
    }
  }

  return loop_score;
}


#define DEV_LOOP_MIN  16

int pico_devices_loop(int loop_score, int direction)
{
  struct pico_device *start;
  static struct pico_device *next = NULL, *next_in = NULL, *next_out = NULL;
  static struct pico_tree_node * next_node, * in_node, * out_node;

  if (next_in == NULL) {
    in_node = pico_tree_firstNode(Device_tree.root);
    next_in = in_node->keyValue;
  }
  if (next_out == NULL) {
  	out_node = pico_tree_firstNode(Device_tree.root);
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

  /* round-robin all devices, break if traversed all devices */
  while (loop_score > DEV_LOOP_MIN && next != NULL) {
    loop_score = devloop(next, loop_score, direction);

    next_node = pico_tree_next(next_node);
    next = next_node->keyValue;

    if (next == NULL)
    {
    	next_node = pico_tree_firstNode(Device_tree.root);
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

struct pico_device* pico_get_device(const char* name)
{
  struct pico_device *dev;
  struct pico_tree_node * index;
  pico_tree_foreach(index, &Device_tree){
  	dev = index->keyValue;
    if(strcmp(name, dev->name) == 0)
      return dev;
  }
  return NULL;
}

int pico_device_broadcast(struct pico_frame * f)
{
	struct pico_tree_node * index;
	int ret = -1;

	pico_tree_foreach(index,&Device_tree)
	{
		struct pico_device * dev = index->keyValue;
		if(dev != f->dev)
		{
			struct pico_frame * copy = pico_frame_copy(f);

			if(!copy)
				return -1;
			copy->dev = dev;
			copy->dev->send(copy->dev, copy->start, copy->len);
			pico_frame_discard(copy);
		}
		else
		{
			ret = f->dev->send(f->dev, f->start, f->len);
		}
	}

	return ret;
}
