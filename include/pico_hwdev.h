#ifndef _PICO_HWDEV_H
#define _PICO_HWDEV_H

struct pico_hwdev {

  /* Implements: pico object */
  struct pico_object _obj;

  /* Hw address. Must be unique, of course. */
  pico_MACaddr HWADDR;

  /* Initialization routine. Called once by the stack.
   * Can be NULL if not needed.
   */
  void (*init)(void);

  /* polling function. Must return immediately if no data,
   * or call pico_dev_recv() when valid data is received.
   */
  void (*poll)(void);

  /* Send routine. Must not block. The driver should be able to provide
   * some buffering if the device is not ready.
   */
  void (*send)(void *data, uint32_t len);
};


/* HW driver calls this to push packets towards the stack */
void pico_hwdev_recv(void *data, uint32_t len);

#endif
