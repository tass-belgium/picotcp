#ifndef _INCLUDE_PICO_DEVICE 
#define _INCLUDE_PICO_DEVICE 
#include "pico_queue.h"
#include "pico_frame.h"
#include "pico_addressing.h"

//RB_HEAD(pico_device_tree, pico_device);
//RB_PROTOTYPE(pico_device_tree, pico_device, node, pico_dev_cmp);
#define MAX_DEVICE_NAME 16

struct pico_ethdev {
  struct pico_eth mac;
};

struct pico_device {
  char name[MAX_DEVICE_NAME];
//  RB_ENTRY(pico_device) node;
  uint32_t hash;
  uint32_t overhead;
  struct pico_ethdev *eth; /* Null if non-ethernet */
  struct pico_queue *q_in;
  struct pico_queue *q_out;
  int (*send)(struct pico_device *self, void *buf, int len); /* Send function. Return 0 if busy */
};

#endif
