/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Frederik Van Slycken
 *********************************************************************/
#include "pico_protocol.h"
#include "pico_hotplug_detection.h"
#include "pico_tree.h"
#include "pico_device.h"

struct pico_hotplug_device{
  struct pico_device *dev;
  int prev_state;
  struct pico_tree callbacks;
};

uint32_t timer_id = 0;

static int pico_hotplug_dev_cmp(void *ka, void *kb)
{
    struct pico_hotplug_device *a = ka, *b = kb;
    if (a->dev->hash < b->dev->hash)
        return -1;

    if (a->dev->hash > b->dev->hash)
        return 1;

    return 0;
}

static int callback_compare(void *ka, void *kb)
{
    if (ka < kb)
        return -1;
    if (ka > kb)
        return 1;
    return 0;
}

PICO_TREE_DECLARE(Hotplug_device_tree, pico_hotplug_dev_cmp);

static void timer_cb(__attribute__((unused)) pico_time t, __attribute__((unused)) void* v)
{
    struct pico_tree_node *node = NULL, *safe = NULL, *cb_node = NULL, *cb_safe = NULL;
    int new_state, event;
    struct pico_hotplug_device *hpdev = NULL;
    void (*cb)(struct pico_device *dev, int event);

    //we don't know if one of the callbacks might deregister, so be safe
    pico_tree_foreach_safe(node, &Hotplug_device_tree, safe)
    {
        hpdev = node->keyValue;
        new_state = hpdev->dev->link_state(hpdev->dev);
        if (new_state != hpdev->prev_state)
        {
            if (new_state == 1){
                event = PICO_HOTPLUG_EVENT_UP;
            } else {
                event = PICO_HOTPLUG_EVENT_DOWN;
            }
            //we don't know if one of the callbacks might deregister, so be safe
            pico_tree_foreach_safe(cb_node, &(hpdev->callbacks), cb_safe)
            {
                cb = cb_node->keyValue;
                cb(hpdev->dev, event);
            }
            hpdev->prev_state = new_state;
        }
    }

    timer_id = pico_timer_add(PICO_HOTPLUG_INTERVAL, &timer_cb, NULL);
}


int pico_hotplug_register(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event))
{
    struct pico_hotplug_device *hotplug_dev;
    struct pico_hotplug_device search = {.dev = dev};

    if (dev->link_state == NULL){
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }

    hotplug_dev = (struct pico_hotplug_device*)pico_tree_findKey(&Hotplug_device_tree, &search);
    if (! hotplug_dev )
    {
      hotplug_dev = PICO_ZALLOC(sizeof(struct pico_hotplug_device));
      if (!hotplug_dev)
      {
          pico_err = PICO_ERR_ENOMEM;
          return -1;
      }
      hotplug_dev->dev = dev;
      hotplug_dev->prev_state = dev->link_state(hotplug_dev->dev);
      hotplug_dev->callbacks.root = &LEAF;
      hotplug_dev->callbacks.compare = &callback_compare;
      pico_tree_insert(&Hotplug_device_tree, hotplug_dev);
    }
    pico_tree_insert(&(hotplug_dev->callbacks), cb);

    if (timer_id == 0)
    {
        timer_id = pico_timer_add(PICO_HOTPLUG_INTERVAL, &timer_cb, NULL);
    }

    return 0;
}

int pico_hotplug_deregister(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event))
{
    struct pico_hotplug_device* hotplug_dev;
    struct pico_hotplug_device search = {.dev = dev};

    hotplug_dev = (struct pico_hotplug_device*)pico_tree_findKey(&Hotplug_device_tree, &search);
    if (!hotplug_dev)
        //wasn't registered
        return 0;
    pico_tree_delete(&hotplug_dev->callbacks, cb);
    if (pico_tree_empty(&hotplug_dev->callbacks))
    {
        pico_tree_delete(&Hotplug_device_tree, hotplug_dev);
        PICO_FREE(hotplug_dev);
    }

    if (pico_tree_empty(&Hotplug_device_tree) && timer_id != 0)
    {
        pico_timer_cancel(timer_id);
        timer_id = 0;
    }
    return 0;
}

