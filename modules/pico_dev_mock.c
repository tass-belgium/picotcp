/*********************************************************************
   PicoTCP. Copyright (c) 2012-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.

   Authors: Frederik Van Slycken
 *********************************************************************/


#include "pico_device.h"
#include "pico_dev_mock.h"
#include "pico_stack.h"
#include "pico_tree.h"

#define MOCK_MTU 1500



/* Tree for finding mock_device based on pico_device* */


static int mock_dev_cmp(void *ka, void *kb)
{
    struct mock_device *a = ka, *b = kb;
    if (a->dev < b->dev)
        return -1;

    if (a->dev > b->dev)
        return 1;

    return 0;
}

static PICO_TREE_DECLARE(mock_device_tree, mock_dev_cmp);

static int pico_mock_send(struct pico_device *dev, void *buf, int len)
{
    struct mock_device search = {
        .dev = dev
    };
    struct mock_device*mock = pico_tree_findKey(&mock_device_tree, &search);
    struct mock_frame*frame;

    if(!mock)
        return 0;

    if (len > MOCK_MTU)
        return 0;

    frame = PICO_ZALLOC(sizeof(struct mock_frame));
    if(!frame) {
        return 0;
    }

    if(mock->out_head == NULL)
        mock->out_head = frame;
    else
        mock->out_tail->next = frame;

    mock->out_tail = frame;

    mock->out_tail->buffer = PICO_ZALLOC((uint32_t)len);
    if(!mock->out_tail->buffer)
        return 0;

    memcpy(mock->out_tail->buffer, buf, (uint32_t)len);
    mock->out_tail->len = len;

    return len;

}

static int pico_mock_poll(struct pico_device *dev, int loop_score)
{
    struct mock_device search = {
        .dev = dev
    };
    struct mock_device*mock = pico_tree_findKey(&mock_device_tree, &search);
    struct mock_frame*nxt;

    if(!mock)
        return 0;

    if (loop_score <= 0)
        return 0;

    while(mock->in_head != NULL && loop_score > 0)
    {
        pico_stack_recv(dev, mock->in_head->buffer, (uint32_t)mock->in_head->len);
        loop_score--;

        PICO_FREE(mock->in_head->buffer);

        if(mock->in_tail == mock->in_head) {
            PICO_FREE(mock->in_head);
            mock->in_tail = mock->in_head = NULL;
            return loop_score;
        }

        nxt = mock->in_head->next;
        PICO_FREE(mock->in_head);
        mock->in_head = nxt;
    }
    return loop_score;
}

int pico_mock_network_read(struct mock_device*mock, void *buf, int len)
{
    struct mock_frame*nxt;
    if(mock->out_head == NULL)
        return 0;

    if(len > mock->out_head->len - mock->out_head->read)
        len = mock->out_head->len - mock->out_head->read;

    memcpy(buf, mock->out_head->buffer, (uint32_t)len);

    if(len + mock->out_head->read != mock->out_head->len) {
        mock->out_head->read += len;
        return len;
    }

    PICO_FREE(mock->out_head->buffer);

    if(mock->out_tail == mock->out_head) {
        PICO_FREE(mock->out_head);
        mock->out_tail = mock->out_head = NULL;
        return len;
    }

    nxt = mock->out_head->next;
    PICO_FREE(mock->out_head);
    mock->out_head = nxt;

    return len;
}

int pico_mock_network_write(struct mock_device*mock, const void *buf, int len)
{
    struct mock_frame*frame;
    if (len > MOCK_MTU)
        return 0;

    frame = PICO_ZALLOC(sizeof(struct mock_frame));
    if(!frame) {
        return 0;
    }

    if(mock->in_head == NULL)
        mock->in_head = frame;
    else
        mock->in_tail->next = frame;

    mock->in_tail = frame;

    mock->in_tail->buffer = PICO_ZALLOC((uint32_t)len);
    if(!mock->in_tail->buffer)
        return 0;

    memcpy(mock->in_tail->buffer, buf, (uint32_t)len);
    mock->in_tail->len = len;

    return len;

}

/* Public interface: create/destroy. */

void pico_mock_destroy(struct pico_device *dev)
{
    struct mock_device search = {
        .dev = dev
    };
    struct mock_device*mock = pico_tree_findKey(&mock_device_tree, &search);
    struct mock_frame*nxt;

    if(!mock)
        return;

    nxt = mock->in_head;
    while(nxt != NULL) {
        mock->in_head = mock->in_head->next;
        PICO_FREE(nxt);
        nxt = mock->in_head;
    }
    nxt = mock->out_head;
    while(nxt != NULL) {
        mock->out_head = mock->out_head->next;
        PICO_FREE(nxt);
        nxt = mock->out_head;
    }
    pico_tree_delete(&mock_device_tree, mock);
}

struct mock_device *pico_mock_create(uint8_t*mac)
{

    struct mock_device*mock = PICO_ZALLOC(sizeof(struct mock_device));
    if(!mock)
        return NULL;

    mock->dev = PICO_ZALLOC(sizeof(struct pico_device));
    if (!mock->dev) {
        PICO_FREE(mock);
        return NULL;
    }

    if(mac != NULL) {
        mock->mac = PICO_ZALLOC(6 * sizeof(uint8_t));
        if(!mock->mac) {
            PICO_FREE(mock->dev);
            PICO_FREE(mock);
            return NULL;
        }

        memcpy(mock->mac, mac, 6);
    }

    if( 0 != pico_device_init((struct pico_device *)mock->dev, "mock", mac)) {
        dbg ("Loop init failed.\n");
        pico_device_destroy(mock->dev);
        if(mock->mac != NULL)
            PICO_FREE(mock->mac);

        PICO_FREE(mock);
        return NULL;
    }

    mock->dev->send = pico_mock_send;
    mock->dev->poll = pico_mock_poll;
    mock->dev->destroy = pico_mock_destroy;
    dbg("Device %s created.\n", mock->dev->name);

    if (pico_tree_insert(&mock_device_tree, mock)) {
        if (mock->mac != NULL)
            PICO_FREE(mock->mac);

        pico_device_destroy(mock->dev);

        PICO_FREE(mock);
        return NULL;
    }

    return mock;
}

/*
 * a few utility functions that check certain fields
 */

uint32_t mock_get_sender_ip4(struct mock_device*mock, void*buf, int len)
{
    uint32_t ret;
    int start = mock->mac ? 14 : 0;
    if(start + 16 > len) {
        dbg("out of range!\n");
        return 0;
    }

    memcpy(&ret, buf + start + 12, 4);
    return ret;
}

/*
 * TODO
 * find a way to create ARP replies
 *
 * create the other utility functions, e.g.
 *  -is_arp_request
 *  -create_arp_reply
 *  -get_destination_ip4
 *  -get_ip4_total_length
 *  -is_ip4_checksum_valid
 *  -is_tcp_syn
 *  -create_tcp_synack
 *  -is_tcp_checksum_valid
 *  etc.
 *
 */

int mock_ip_protocol(struct mock_device*mock, void*buf, int len)
{
    uint8_t type;
    int start = mock->mac ? 14 : 0;
    if(start + 10 > len) {
        return 0;
    }

    memcpy(&type, buf + start + 9, 1);
    return type;
}

/* note : this function doesn't check if the IP header has any options */
int mock_icmp_type(struct mock_device*mock, void*buf, int len)
{
    uint8_t type;
    int start = mock->mac ? 14 : 0;
    if(start + 21 > len) {
        return 0;
    }

    memcpy(&type, buf + start + 20, 1);
    return type;
}

/* note : this function doesn't check if the IP header has any options */
int mock_icmp_code(struct mock_device*mock, void*buf, int len)
{
    uint8_t type;
    int start = mock->mac ? 14 : 0;
    if(start + 22 > len) {
        return 0;
    }

    memcpy(&type, buf + start + 21, 1);
    return type;
}
