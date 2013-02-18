/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.

.

*********************************************************************/

struct igmp2_packet_params {
  struct pico_ip4 group_address;
  struct pico_ip4 src_interface;
  struct pico_frame *f;
  uint8_t event;
  uint8_t max_resp_time;
  unsigned long timer_starttime;
};


int test_pico_igmp2_set_membershipState(struct pico_ip4 *mgroup_addr ,uint8_t state);
uint8_t test_pico_igmp2_get_membershipState(struct pico_ip4 *mgroup_addr);

int test_pico_igmp2_process_event(struct igmp2_packet_params *params);
int test_pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params);
int test_pico_igmp2_process_in(struct pico_protocol *self, struct pico_frame *f);
