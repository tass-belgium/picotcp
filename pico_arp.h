#ifndef _INCLUDE_PICO_ARP
#define _INCLUDE_PICO_ARP

int pico_arp_receive(struct pico_frame *);

struct pico_arp4 *pico_arp4_get(struct pico_frame *);
struct pico_arp6 *pico_arp6_get(struct pico_frame *);

int pico_arp4_query(struct pico_frame *);
int pico_arp6_query(struct pico_frame *);



#endif
