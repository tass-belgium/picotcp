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

#define TUN_MTU 2048

static int pico_tun_send(struct pico_device *dev, void *buf, int len) {
  struct pico_device_tun *tun = (struct pico_device_tun *)dev;
  return (int)write(tun->fd, buf, (uint32_t)len);
}

static int pico_tun_poll(struct pico_device *dev, int loop_score) {
  struct pico_device_tun *tun = (struct pico_device_tun *)dev;
  unsigned char *buf = (unsigned char *)PICO_ZALLOC(TUN_MTU);
  int len;
  int flags = fcntl(tun->fd, F_GETFL, 0);
  /*fcntl(tun->fd, F_SETFL, flags | O_NONBLOCK);*/
  uint32_t num_timers = pico_timers_size();
  uint32_t id_expiry_fd[num_timers][3];
  uint32_t num_inserted = pico_timers_populate_id_to_expiry(id_expiry_fd);
  // number of timers + 1 for the TUN fd
  uint32_t num_fds = num_inserted + 1;
  struct pollfd pfds[num_fds];
  pfds[0].fd = tun->fd;
  pfds[0].events = POLLIN;
  for (int i = 0; i < num_inserted; i++) {
    uint32_t id = id_expiry_fd[i][0];
    uint32_t expiry_relative_to_epoch_ms = id_expiry_fd[i][1];
    // PICO_TIME_MS() is the current time relative to epoch.
    uint32_t expiry_wait_ms = expiry_relative_to_epoch_ms - PICO_TIME_MS();
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    /*
     * The itimerspec/timerfd APIs expect the `it_value` to
     * be the amount of time to wait before firing,
     * rather than the time at which to fire.
     */
    struct itimerspec ts;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = expiry_wait_ms / 1000.0;
    ts.it_value.tv_nsec = (expiry_wait_ms % 1000) * 1000000;
    timerfd_settime(timer_fd, 0, &ts, NULL);
    pfds[i + 1].fd = timer_fd;
    pfds[i + 1].events = POLLIN;
    id_expiry_fd[i][2] = timer_fd;
  }
  // -1 Timeout means block indefinitely.
  int timeout = -1;
  int should_return = 0;
  do {
    if (poll(pfds, num_fds, timeout) <= 0) {
      fprintf(stderr, "TUN poll error %s\n", strerror(errno));
      return -1;
    }

    // First, check the TUN.
    if (pfds[0].revents & POLLIN) {
      for (;;) {
        len = (int)read(tun->fd, buf, TUN_MTU);
        if (len > 0) {
          pico_stack_recv_zerocopy(dev, buf, (uint32_t)len);
          return loop_score;
        } else {
          fprintf(stderr, "TUN read error %s\n", strerror(errno));
          return -1;
        }
      }
    }

    // Then, check the timers.
    uint64_t res;
    for (int i = 1; i < num_fds; i++) {
      if (pfds[i].revents & POLLIN) {
        printf("timer fired\n");
        int result = read(pfds[i].fd, &res, sizeof(res));
        if (result <= 0) {
          fprintf(stderr, "Timer read error %s\n", strerror(errno));
          return -1;
        }
        for (uint32_t j = 0; j < num_timers; j++) {
          if (id_expiry_fd[j][2] == pfds[i].fd) {
            pico_timer_trigger_callback(id_expiry_fd[j][0]);
          }
        }
      }
    }

  } while (loop_score > 0 && !should_return);
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

