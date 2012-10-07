#ifndef PICO_COMMON_H
#define PICO_COMMON_H
#include "pico_setup.h"
#include "rb.h"

struct pico_frame;
struct connect_up {
  int (*recv_ready)(struct pico_frame *p);
  int (*recv)(struct pico_frame *p);
  struct connect_up *next;
};


struct connect_down {
  struct pico_frame* (*alloc)(int payload_size);
  int (*send)(struct pico_frame *p);
  struct connect_down *next;
};


struct stack_app { /* E.g. ARP, ICMP, ... */
  /* Layer 5 APP only */
  uint16_t port; 
  uint16_t protocol;

  struct stack_app *next;
};

RB_HEAD(pico_module_tree, pico_module);
RB_PROTOTYPE(pico_module_tree, pico_module, node, pico_mod_cmp);

#define MAX_MODULE_NAME 128
struct pico_module {
  RB_ENTRY(pico_module) node;

  /* Init/shutdown functions */
  struct pico_module * (*init)(void *arg);
  void (*shutdown)(struct pico_module *mod);

  /* module identifier */
  int                       layer;
  char                    name[MAX_MODULE_NAME];
  uint32_t                hash;

  /* module queues */
  struct pico_queue *qin;
  struct pico_queue *qout;

  /* exported connectors for communication with other layers */
  struct connect_down to_upper;
  struct connect_up   to_lower;

  /* Module inner structure */
  void *priv;

  /* Run function for packet-flow independant control handling (e.g. deferred operations) */
  void (*run)(void);

};

RB_HEAD(pico_device_tree, pico_device);
RB_PROTOTYPE(pico_device_tree, pico_device, node, pico_dev_cmp);
#define MAX_DEVICE_NAME 16

struct pico_device {
  RB_ENTRY(pico_device) node;
  char name[MAX_DEVICE_NAME];
  uint32_t hash;
  uint32_t overhead;
  struct pico_ethdev *eth; /* Null if non-ethernet */
  struct pico_module *mod;  /* Associated module */
  struct pico_queue *qin;
  struct pico_queue *qout;
  int (*send)(struct pico_device *self, struct pico_frame *p); /* Send function. Return 0 if busy */
};


/* Packet. */

enum routing_stage {
  PICO_ROUTING_INCOMING = 0,
  PICO_ROUTING_OUTGOING = 1
};

struct pico_frame {

  /* Connector for queues */
  struct pico_frame *next;

  /* Start of the whole buffer, total frame length. */
  unsigned char *buffer;
  uint32_t      buffer_len;

  /* Module ownership stuff, usage counter */
  struct pico_module *origin;
  struct pico_module *owner;
  uint32_t           usage_count; /* To handling frame copies and destruction */
  struct pico_module *dest; /* For delivery action towards next module */

  /* Routing stage. */
  enum routing_stage stage;

  /* Pointer to protocol headers */
  void *data_hdr;
  int  data_len;
  void *net_hdr;
  int net_len;
  void *transport_hdr;
  int transport_len;
  void *app_hdr;
  int app_len;


  /* Pointer to the phisical device this packet belongs to.
   * Should be valid in both routing directions
   */
  struct pico_device *dev;

  /* Pointer to network protocol module associated with the packet. */
  struct pico_module *net;

  /* quick reference to identifiers */
  uint16_t id_eth; /* IP or ARP */
  uint16_t id_net; /* version 4 or 6 */
  uint16_t id_trans; /* Transport layer protocol */
  uint16_t id_sock; /* Transport layer port */

  /* Pointer to payload */
  unsigned char *payload;
  int payload_len;
};

#define PICO_LAYER_DATALINK 2
#define PICO_LAYER_NETWORK 3
#define PICO_LAYER_TRANSPORT 4
#define PICO_LAYER_APP      5

#define PICO_UNREACHABLE 1
#define PICO_IDETH_IP 0x0800


/* Interface of delivery.c */
int pico_frame_deliver(struct pico_frame *pkt);
int pico_frame_deliver_cpy(struct pico_frame *pkt);
struct pico_frame *pico_frame_alloc(struct pico_module *owner, int size);
void pico_frame_discard(struct pico_frame *p);

/* Interface of mod_table.c */
int pico_mod_insert(struct pico_module *mod);
void pico_mod_delete(char *name);
uint32_t pico_mod_hash(char *name);
struct pico_module *pico_mod_get(char *name);
int pico_mod_cmp(struct pico_module *m0, struct pico_module *m1);
int pico_dev_cmp(struct pico_device *m0, struct pico_device *m1);



#endif
