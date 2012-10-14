#include "pico_config.h"
#include "pico_device.h"
#include "pico_stack.h"


RB_HEAD(pico_device_tree, pico_device);
RB_PROTOTYPE_STATIC(pico_device_tree, pico_device, node, pico_dev_cmp);

static struct pico_device_tree Device_tree;

static int pico_dev_cmp(struct pico_device *a, struct pico_device *b)
{
  if (a->hash < b->hash)
    return -1;
  if (a->hash > b->hash)
    return 1;
  return 0;
}

RB_GENERATE_STATIC(pico_device_tree, pico_device, node, pico_dev_cmp);

int pico_device_init(struct pico_device *dev, char *name, uint8_t *mac)
{
  memcpy(dev->name, name, MAX_DEVICE_NAME);
  dev->hash = pico_hash(dev->name);

  RB_INSERT(pico_device_tree, &Device_tree, dev);

  dev->q_in = pico_zalloc(sizeof(struct pico_queue));
  dev->q_out = pico_zalloc(sizeof(struct pico_queue));

  if (mac) {
    dev->eth = pico_zalloc(sizeof(struct pico_ethdev));
    memcpy(dev->eth->mac.addr, mac, PICO_SIZE_ETH);
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

  RB_REMOVE(pico_device_tree, &Device_tree, dev);
  pico_free(dev);
}

static void devloop(struct pico_device *dev, int loop_score)
{
  struct pico_frame *f;

  /* If device supports polling, give control. Loop score is managed internally, 
   * remaining loop points are returned. */
  if (dev->poll) {
    loop_score = dev->poll(dev, loop_score);
  }

  while(loop_score > 0) {
    if (dev->q_in->frames + dev->q_out->frames <= 0)
      break;


    /* Device dequeue + send */
    f = pico_dequeue(dev->q_out);
    if (f) {
      if (dev->eth) {
        int ret = pico_ethernet_send(f);
        if (0 == ret) {
          pico_enqueue(dev->q_out, f);
          loop_score--;
          continue;
        } if (ret < 0) {
  /*
          if (pico_ipv4_link_find(&hdr->src)) {
            dbg("Local originated packet: destination unreachable.\n");
          } else {
            dbg("Routed packet: destination unreachable, notify sender.\n");
            pico_notify_dest_unreachable(f);
          }
   */
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

void pico_devices_loop(int loop_score)
{
  struct pico_device *dev;
  RB_FOREACH(dev, pico_device_tree, &Device_tree) {
    devloop(dev, loop_score);
  }
}
