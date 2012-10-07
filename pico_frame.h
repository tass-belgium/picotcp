#ifndef _INCLUDE_PICO_FRAME
#define _INCLUDE_PICO_FRAME


struct pico_frame {

  /* Connector for queues */
  struct pico_frame *next;

  /* Start of the whole buffer, total frame length. */
  unsigned char *buffer;
  uint32_t      buffer_len;

  /* Pointer to usage counter */
  uint32_t *usage_count;

  /* Pointer to protocol headers */
  void *data_hdr;
  int  data_len;
  void *net_hdr;
  int net_len;
  void *transport_hdr;
  int transport_len;
  void *app_hdr;
  int app_len;

  /* Pointer to the phisical device this packet belongs to.
   * Should be valid in both routing directions
   */
  struct pico_device *dev;

  /* quick reference to identifiers */
  uint16_t id_eth; /* IP or ARP */
  uint16_t id_net; /* version 4 or 6 */
  uint16_t id_trans; /* Transport layer protocol */
  uint16_t id_sock; /* Transport layer port */

  /* Pointer to payload */
  unsigned char *payload;
  int payload_len;
};

#endif
