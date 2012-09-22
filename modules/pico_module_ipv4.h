#ifndef _PICO_MODULE_IPV4_H
#define _PICO_MODULE_IPV4_H


/* object: Address */
struct ipv4 {
  uint32_t s_addr;
  uint32_t s_netmask;
  struct ipv4 *next;
};

/* object: socket */
struct sock_ipv4 {
  struct ipv4 *address_list;
  int (*address_add)(struct ipv4 *address);
  int (*address_del)(struct ipv4 *address);
  struct pico_dev *dev;
  struct sock_ipv4 *next;
};

#ifndef IS_MODULE_IPV4
# define _mod extern
#else
# define _mod
#endif
_mod struct pico_module pico_module_ipv4;
#undef _mod

#endif
