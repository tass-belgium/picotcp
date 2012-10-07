#ifndef _PICO_BUFF
#define _PICO_BUFF
#include "pico_object.h"
#include "pico_headers.h"

struct pico_buff {
  /* Implements: pico_object */
  struct pico_object _obj;

  /* beginning of data buffer */
  uint32_t size;
  uint8_t *rawdata; /* Pointer to the first byte of the allocated buffer */

  /* device driver private fields */
  void          *hw_priv;
  void          *start;

  /* L2 */
  pico_ethhdr   *eth;
  pico_arphdr   *arp;

  /* L3 */
  pico_ip4hdr   *ip4;
  pico_ip6hdr   *ip6;
  pico_icmphdr  *icmp;

  /* L4 */
  pico_udphdr   *udp;
  pico_tcphdr   *tcp;
  void          *sock_info;

  /*
   * This field has a dual meaning.
   * xmit: Incoming data from application, not yet copied into the buffer.
   * recv: pointer to a local area inside rawdata containing the application data.
   */
  struct {
    uint8_t *data;
    uint32_t len;
  } payload;

  uint16_t      priority;
};


#endif
