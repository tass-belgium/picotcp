/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

Authors: Frederik Van Slycken
*********************************************************************/


#include "pico_device.h"
#include "pico_dev_mock.h"
#include "pico_stack.h"


#define MOCK_MTU 1500

struct mock_frame{
	uint8_t* buffer;
	int len;
	int read;

	struct mock_frame* next;
};

//TODO perhaps we should put the lists in the mock-device, so we can make multiple mock-devices with their own queues
struct mock_frame *in_head, *in_tail, *out_head, *out_tail;

static int pico_mock_send(struct pico_device *dev, void *buf, int len)
{
	struct mock_frame* frame;
  if (len > MOCK_MTU)
    return 0;

	frame = pico_zalloc(sizeof(struct mock_frame));
	if(!frame){
		return 0;
	}

	if(out_head == NULL)
		out_head = frame;
	else
		out_tail->next = frame;
	out_tail = frame;

	out_tail->buffer = pico_zalloc(len);
	if(!out_tail->buffer)
		return 0;

	memcpy(out_tail->buffer, buf, len);
	out_tail->len = len;

	return len;

}

static int pico_mock_poll(struct pico_device *dev, int loop_score)
{
	struct mock_frame* nxt;
  if (loop_score <= 0)
    return 0;

	while(in_head != NULL && loop_score >0)
	{
		pico_stack_recv(dev, in_head->buffer, in_head->len);
		loop_score--;

		pico_free(in_head->buffer);

		if(in_tail == in_head){
			free(in_head);
			in_tail = in_head = NULL;
			return loop_score;
		}

		nxt = in_head->next;
		free(in_head);
		in_head = nxt;
	}
  return loop_score;
}

int pico_mock_network_read(struct pico_device* mock, void *buf, int len)
{
	struct mock_frame* nxt;
	if(out_head == NULL)
		return 0;

	if(len > out_head->len-out_head->read)
		len = out_head->len - out_head->read;

	memcpy(buf, out_head->buffer, len);

	if(len+out_head->read != out_head->len){
		out_head->read += len;
		return len;
	}

	pico_free(out_head->buffer);

	if(out_tail == out_head){
		free(out_head);
		out_tail = out_head = NULL;
		return len;
	}

	nxt = out_head->next;
	free(out_head);
	out_head = nxt;

	return len;
}

int pico_mock_network_write(struct pico_device* mock, const void *buf, int len)
{
	struct mock_frame* frame;
  if (len > MOCK_MTU)
    return 0;

	frame = pico_zalloc(sizeof(struct mock_frame));
	if(!frame){
		return 0;
	}

	if(in_head == NULL)
		in_head = frame;
	else
		in_tail->next = frame;
	in_tail = frame;

	in_tail->buffer = pico_zalloc(len);
	if(!in_tail->buffer)
		return 0;

	memcpy(in_tail->buffer, buf, len);
	in_tail->len = len;

	return len;

}

/* Public interface: create/destroy. */

void pico_mock_destroy(struct pico_device *dev)
{
	//TODO delete the remaining buffers...
}

struct pico_device *pico_mock_create(uint8_t* mac)
{
  struct pico_device *mock = pico_zalloc(sizeof(struct pico_device));
  if (!mock)
    return NULL;

  if( 0 != pico_device_init((struct pico_device *)mock, "mock", mac)) {
    dbg ("Loop init failed.\n");
    pico_mock_destroy((struct pico_device *)mock);
    return NULL;
  }
  mock->send = pico_mock_send;
  mock->poll = pico_mock_poll;
  mock->destroy = pico_mock_destroy;
  dbg("Device %s created.\n", mock->name);
  return (struct pico_device *)mock;
}
