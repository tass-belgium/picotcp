#ifndef PICO_SOCKET_MULTICAST_H
#define PICO_SOCKET_MULTICAST_H
int pico_socket_mcast_filter(struct pico_socket *s, struct pico_ip4 *mcast_group, struct pico_ip4 *src);
void pico_multicast_delete(struct pico_socket *s);
int pico_setsockopt_mcast(struct pico_socket *s, int option, void *value);

#endif
