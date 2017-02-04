/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Frederik Van Slycken
 *********************************************************************/
#ifndef INCLUDE_PICO_SUPPORT_HOTPLUG
#define INCLUDE_PICO_SUPPORT_HOTPLUG
#include "pico_stack.h"

#define PICO_HOTPLUG_EVENT_UP  1  /* link went up */
#define PICO_HOTPLUG_EVENT_DOWN  2  /* link went down */

#define PICO_HOTPLUG_INTERVAL 100

/* register your callback to be notified of hotplug events on a certain device.
 * Note that each callback will be called at least once, shortly after adding, for initialization.
 */
int pico_hotplug_register(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event));
int pico_hotplug_deregister(struct pico_device *dev, void (*cb)(struct pico_device *dev, int event));

#endif /* _INCLUDE_PICO_SUPPORT_HOTPLUG */

