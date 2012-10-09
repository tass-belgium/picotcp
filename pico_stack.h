#ifndef _INCLUDE_PICO_STACK
#define _INCLUDE_PICO_STACK

/* LOWEST LEVEL: interface towards devices. */
/* Device driver will call this function which returns immediately.
 * Incoming packet will be processed later on in the dev loop.
 */
int pico_stack_recv(struct pico_device *dev, uint8_t *buffer, int len);



#endif
