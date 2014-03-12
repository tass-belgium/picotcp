/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera
 *********************************************************************/

#ifndef UNIT_TEST
#include <libvdeplug.h>
#endif
#include "pico_device.h"
#include "pico_dev_vde.h"
#include "pico_stack.h"

#include <sys/poll.h>

struct pico_device_vde {
    struct pico_device dev;
    char *sock;
    VDECONN *conn;
};

#define VDE_MTU 65536

static int pico_vde_send(struct pico_device *dev, void *buf, int len)
{
    struct pico_device_vde *vde = (struct pico_device_vde *) dev;
    /* dbg("[%s] send %d bytes.\n", dev->name, len); */
    return vde_send(vde->conn, buf, len, 0);
}

static int pico_vde_poll(struct pico_device *dev, int loop_score)
{
    struct pico_device_vde *vde = (struct pico_device_vde *) dev;
    struct pollfd pfd;
    unsigned char buf[VDE_MTU];
    int len;
    pfd.fd = vde_datafd(vde->conn);
    pfd.events = POLLIN;
    do  {
        if (poll(&pfd, 1, 0) <= 0)
            return loop_score;

        len = vde_recv(vde->conn, buf, VDE_MTU, 0);
        if (len > 0) {
            /* dbg("Received pkt.\n"); */
            loop_score--;
            pico_stack_recv(dev, buf, len);
        }
    } while(loop_score > 0);
    return 0;
}

/* Public interface: create/destroy. */

void pico_vde_destroy(struct pico_device *dev)
{
    struct pico_device_vde *vde = (struct pico_device_vde *) dev;
    vde_close(vde->conn);
}



struct pico_device *pico_vde_create(char *sock, char *name, uint8_t *mac)
{
    struct pico_device_vde *vde = PICO_ZALLOC(sizeof(struct pico_device_vde));
    struct vde_open_args open_args = {
        .mode = 0700
    };
    char vdename[] = "picotcp";

    if (!vde)
        return NULL;

    if( 0 != pico_device_init((struct pico_device *)vde, name, mac)) {
        dbg ("Vde init failed.\n");
        pico_vde_destroy((struct pico_device *)vde);
        return NULL;
    }

    vde->dev.overhead = 0;
    vde->sock = PICO_ZALLOC(strlen(sock) + 1);
    memcpy(vde->sock, sock, strlen(sock));
    vde->conn = vde_open(sock, vdename, &open_args);
    if (!vde->conn) {
        pico_vde_destroy((struct pico_device *)vde);
        return NULL;
    }

    vde->dev.send = pico_vde_send;
    vde->dev.poll = pico_vde_poll;
    vde->dev.destroy = pico_vde_destroy;
    dbg("Device %s created.\n", vde->dev.name);
    return (struct pico_device *)vde;
}

