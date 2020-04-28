/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights
 reserved. See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Daniele Lacamera
 *********************************************************************/

#include "pico_dev_tun.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/timerfd.h>

#include "pico_device.h"
#include "pico_stack.h"

struct pico_device_tun {
  struct pico_device dev;
  int fd;
};

extern int SHOULD_SNAPSHOT;

#define TUN_MTU 2048

static int pico_tun_send(struct pico_device *dev, void *buf, int len) {
  struct pico_device_tun *tun = (struct pico_device_tun *)dev;
  return (int)write(tun->fd, buf, (uint32_t)len);
}

static int pico_tun_poll(struct pico_device *dev, int loop_score) {
  struct pico_device_tun *tun = (struct pico_device_tun *)dev;
  unsigned char *buf = (unsigned char *)PICO_ZALLOC(TUN_MTU);
  int len;
  /*int flags = fcntl(tun->fd, F_GETFL, 0);*/
  /*fcntl(tun->fd, F_SETFL, flags | O_NONBLOCK);*/
  uint32_t num_timers = pico_timers_size();
  int timer_fds[num_timers];
  uint64_t num_inserted = pico_timers_populate_timer_fds(timer_fds);
  // number of timers + 1 for the TUN fd
  uint64_t num_fds = num_inserted + 1;
  struct pollfd pfds[num_fds];
  pfds[0].fd = tun->fd;
  pfds[0].events = POLLIN;
  for (uint64_t i = 0; i < num_inserted; i++) {
    pfds[i + 1].fd = timer_fds[i];
    pfds[i + 1].events = POLLIN;
  }
  // -1 Timeout means block indefinitely.
  int timeout = -1;
  for (;;) {
    if (poll(pfds, num_fds, timeout) <= 0) {
      fprintf(stderr, "TUN poll error: %s\n", strerror(errno));
      // This will happen when snapshotted.
      return -1;
    }

    // First, check the TUN.
    if (pfds[0].revents & POLLIN) {
      len = (int)read(tun->fd, buf, TUN_MTU);
      if (len > 0) {
        pico_stack_recv_zerocopy(dev, buf, (uint32_t)len);
        return loop_score;
      } else {
        fprintf(stderr, "TUN read error: %s\n", strerror(errno));
        exit(1);
      }
    }

    // Then, check the timers.
    int should_check_timers = 0;
    for (uint64_t i = 1; i < num_fds; i++) {
      if (pfds[i].revents & POLLIN) {
        unsigned long long missed;
        int ret = (int)read(pfds[i].fd, &missed, sizeof(missed));
        if (ret < 0) {
          fprintf(stderr, "Timer read error %s\n", strerror(errno));
          exit(1);
        }
        if (missed > 3) {
          fprintf(stderr, "We've missed a timer more than 3 times.\n");
          exit(1);
        }
        should_check_timers = 1;
      }
    }
    if (should_check_timers) {
      pico_check_timers();
    }
    // We may have new timers, so we need to restart in order
    // to populate our pollfds again.
    if (num_timers < pico_timers_size()) {
      return pico_tun_poll(dev, loop_score);
    }
    if (SHOULD_SNAPSHOT == 1) {
      return -1;
    }
  }
  return 0;
}

/* Public interface: create/destroy. */

void pico_tun_destroy(struct pico_device *dev) {
  struct pico_device_tun *tun = (struct pico_device_tun *)dev;
  if (tun->fd > 0) close(tun->fd);
}

static int tun_open(char *name) {
  struct ifreq ifr;
  int tun_fd;
  if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
    return (-1);
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, name, IFNAMSIZ);
  if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
    return (-1);
  }

  return tun_fd;
}

struct pico_device *pico_tun_create(char *name) {
  struct pico_device_tun *tun = PICO_ZALLOC(sizeof(struct pico_device_tun));

  if (!tun) return NULL;

  if (0 != pico_device_init((struct pico_device *)tun, name, NULL)) {
    dbg("Tun init failed.\n");
    pico_tun_destroy((struct pico_device *)tun);
    return NULL;
  }

  tun->dev.overhead = 0;
  tun->fd = tun_open(name);
  if (tun->fd < 0) {
    dbg("Tun creation failed.\n");
    pico_tun_destroy((struct pico_device *)tun);
    return NULL;
  }

  tun->dev.send = pico_tun_send;
  tun->dev.poll = pico_tun_poll;
  tun->dev.destroy = pico_tun_destroy;
  dbg("Device %s created.\n", tun->dev.name);
  return (struct pico_device *)tun;
}

