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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <unistd.h>

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
  /*int flags = fcntl(tun->fd, F_GETFL, 0);*/
  /*fcntl(tun->fd, F_SETFL, flags | O_NONBLOCK);*/
  uint32_t num_timers = pico_timers_size();
  int timer_fds[num_timers];
  int num_inserted = pico_timers_populate_timer_fds(timer_fds);
  // number of timers + 1 for the TUN fd
  int num_fds = num_inserted + 1;
  // -1 Timeout means block indefinitely.
  int timeout = -1;
  int max_events = num_fds * 10;
  struct epoll_event ready_events[max_events];
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    fprintf(stderr, "Failed to create epoll file descriptor\n");
    exit(1);
  }
  struct epoll_event new_event;
  new_event.events = EPOLLIN;
  new_event.data.fd = tun->fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun->fd, &new_event)) {
    fprintf(stderr, "Failed to add TUN file descriptor to epoll\n");
    close(epoll_fd);
    exit(1);
  }
  for (int i = 0; i < num_inserted; i++) {
    new_event.events = EPOLLIN;
    new_event.data.fd = timer_fds[i];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fds[i], &new_event)) {
      fprintf(stderr, "Failed to add file descriptor %d to epoll\n", i);
      close(epoll_fd);
      exit(1);
    }
  }
  int event_count;
  for (;;) {
    int should_check_timers = 0;
    event_count = epoll_wait(epoll_fd, ready_events, max_events, timeout);
    if (event_count <= 0) {
      fprintf(stderr, "epoll_wait error %s\n", strerror(errno));
      return -1;
    }
    for (int i = 0; i < event_count; i++) {
      if ((ready_events[i].events & EPOLLERR) ||
          (ready_events[i].events & EPOLLHUP) ||
          (!(ready_events[i].events & EPOLLIN))) {
        fprintf(stderr, "Timer poll error %s\n", strerror(errno));
        exit(1);
      }
      if (ready_events[i].data.fd == tun->fd) {
        len = (int)read(tun->fd, buf, TUN_MTU);
        if (len > 0) {
          return pico_stack_recv_zerocopy(dev, buf, (uint32_t)len);
        } else {
          fprintf(stderr, "TUN read error: %s\n", strerror(errno));
          exit(1);
        }
        if (close(epoll_fd)) {
          fprintf(stderr, "Failed to close epoll file descriptor\n");
          exit(1);
        }
      } else {  // timer
        unsigned long long missed;
        int ret = (int)read(ready_events[i].data.fd, &missed, sizeof(missed));
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
      pico_check_timers(epoll_fd);
    }
  }
  if (close(epoll_fd)) {
    fprintf(stderr, "Failed to close epoll file descriptor\n");
    exit(1);
  }
  return loop_score;
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

