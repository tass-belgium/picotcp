#include "pico_device.h"

START_TEST(test_pico_device)
{
  /*
   * There is no real test performed here
   * This test just inits a device and destroys it again
   * This is just to check there are no asan errors, mem leaks, ...
   */
  struct pico_device *dummy_device = NULL;
  const uint8_t mac[PICO_SIZE_ETH] = {
    0x09, 0x00, 0x27, 0x39, 0xd0, 0xc6
  };
  const char *name = "device_test";

  dummy_device = PICO_ZALLOC(sizeof(struct pico_device));
  pico_device_init(dummy_device, name, mac);
  pico_device_destroy(dummy_device);
}
END_TEST
