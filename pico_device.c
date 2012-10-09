#include "pico_config.h"
#include "pico_device.h"
RB_HEAD(pico_device_tree, pico_device);
RB_PROTOTYPE_STATIC(pico_device_tree, pico_device, node, pico_dev_cmp);

static struct pico_device_tree Device_tree;
static int pico_dev_cmp(struct pico_device *a, struct pico_device *b)
{
  return 0;
}

RB_GENERATE_STATIC(pico_device_tree, pico_device, node, pico_dev_cmp);



int pico_device_init(struct pico_device *dev, char *name, uint8_t *mac)
{
  memcpy(dev->name, name, MAX_DEVICE_NAME);
  dev->hash = 0;


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

int pico_device_destroy(struct pico_device *dev)
{



}
