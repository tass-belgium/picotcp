/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Frederik Van Slycken
 *********************************************************************/
#include "pico_protocol.h"
#include "pico_hotplug_detection.h"
#include "pico_tree.h"
#include "pico_device.h"

struct pico_hotplug_device {
    struct pico_device *dev;
    int prev_state;
    struct pico_tree callbacks;
    struct pico_tree init_callbacks; /* functions we still need to call for initialization */
};

static uint32_t timer_id = 0;

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

static PICO_TREE_DECLARE(Hotplug_device_tree, pico_hotplug_dev_cmp);

static void initial_callbacks(struct pico_hotplug_device *hpdev, int event)
{
    struct pico_tree_node *cb_node = NULL, *cb_safe = NULL;
    void (*cb)(struct pico_device *dev, int event);
    pico_tree_foreach_safe(cb_node, &(hpdev->init_callbacks), cb_safe)
    {
        cb = cb_node->keyValue;
        cb(hpdev->dev, event);
        pico_tree_delete(&hpdev->init_callbacks, cb);
    }
}

static void execute_callbacks(struct pico_hotplug_device *hpdev, int new_state, int event)
{
    struct pico_tree_node *cb_node = NULL, *cb_safe = NULL;
    void (*cb)(struct pico_device *dev, int event);
    if (new_state != hpdev->prev_state)
    {
        /* we don't know if one of the callbacks might deregister, so be safe */
        pico_tree_foreach_safe(cb_node, &(hpdev->callbacks), cb_safe)
        {
            cb = cb_node->keyValue;
            cb(hpdev->dev, event);
        }
        hpdev->prev_state = new_state;
    }
}

static void timer_cb(__attribute__((unused)) pico_time t, __attribute__((unused)) void*v)
{
    struct pico_tree_node *node = NULL, *safe = NULL;
    int new_state, event;
    struct pico_hotplug_device *hpdev = NULL;

    /* we don't know if one of the callbacks might deregister, so be safe */
    pico_tree_foreach_safe(node, &Hotplug_device_tree, safe)
    {
        hpdev = node->keyValue;
        new_state = hpdev->dev->link_state(hpdev->dev);

        if (new_state == 1) {
            event = PICO_HOTPLUG_EVENT_UP;
        } else {
            event = PICO_HOTPLUG_EVENT_DOWN;
        }

        initial_callbacks(hpdev, event);
        execute_callbacks(hpdev, new_state, event);
    }

    timer_id = pico_timer_add(PICO_HOTPLUG_INTERVAL, &timer_cb, NULL);
    if (timer_id == 0) {
        dbg("HOTPLUG: Failed to start timer\n");
    }
}

static int ensure_hotplug_timer(void)
{
    if (timer_id == 0)
    {
        timer_id = pico_timer_add(PICO_HOTPLUG_INTERVAL, &timer_cb, NULL);
        if (timer_id == 0) {
            dbg("HOTPLUG: Failed to start timer\n");
            return -1;
        }
    }

    return 0;
}

static void disable_hotplug_timer(void)
{
    if (timer_id != 0)
    {
        pico_timer_cancel(timer_id);
        timer_id = 0;
    }
}

int pico_hotplug_register(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event))
{
    struct pico_hotplug_device *hotplug_dev;
    struct pico_hotplug_device search = {
        .dev = dev
    };

    /* If it does not have a link_state, */
    /* the device does not support hotplug detection */
    if (dev->link_state == NULL) {
        pico_err = PICO_ERR_EPROTONOSUPPORT;
        return -1;
    }

    hotplug_dev = (struct pico_hotplug_device*)pico_tree_findKey(&Hotplug_device_tree, &search);
    if (!hotplug_dev )
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
        hotplug_dev->init_callbacks.root = &LEAF;
        hotplug_dev->init_callbacks.compare = &callback_compare;
        if (pico_tree_insert(&Hotplug_device_tree, hotplug_dev)) {
            PICO_FREE(hotplug_dev);
        	return -1;
		}
    }

    if (pico_tree_insert(&(hotplug_dev->callbacks), cb) == &LEAF) {
        PICO_FREE(hotplug_dev);
        return -1;
	}

    if (pico_tree_insert(&(hotplug_dev->init_callbacks), cb) == &LEAF) {
        pico_tree_delete(&(hotplug_dev->callbacks), cb);
        PICO_FREE(hotplug_dev);
		return -1;
	}

    if (ensure_hotplug_timer() < 0) {
        pico_hotplug_deregister((struct pico_device *)hotplug_dev, cb);
        return -1;
    }

    return 0;
}

int pico_hotplug_deregister(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event))
{
    struct pico_hotplug_device*hotplug_dev;
    struct pico_hotplug_device search = {
        .dev = dev
    };

    hotplug_dev = (struct pico_hotplug_device*)pico_tree_findKey(&Hotplug_device_tree, &search);
    if (!hotplug_dev)
        /* wasn't registered */
        return 0;

    pico_tree_delete(&hotplug_dev->callbacks, cb);
    pico_tree_delete(&hotplug_dev->init_callbacks, cb);
    if (pico_tree_empty(&hotplug_dev->callbacks))
    {
        pico_tree_delete(&Hotplug_device_tree, hotplug_dev);
        PICO_FREE(hotplug_dev);
    }

    if (pico_tree_empty(&Hotplug_device_tree))
    {
        disable_hotplug_timer();
    }

    return 0;
}

