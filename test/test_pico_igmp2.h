/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

*********************************************************************/

struct igmp2_packet_params {
  uint8_t event;
  struct igmp2_action_data *data_pointer ;
};

struct igmp2_action_data {
  uint8_t max_resp_time;
  uint32_t Group_address;
  struct pico_frame *f;
};

int test_pico_igmp2_set_membershipState(struct pico_ip4 *mgroup_addr ,uint8_t state);
uint8_t test_pico_igmp2_get_membershipState(struct pico_ip4 *mgroup_addr);

int test_pico_igmp2_process_event(struct igmp2_packet_params *params);
int test_pico_igmp2_analyse_packet(struct pico_frame *f, struct igmp2_packet_params *params);

