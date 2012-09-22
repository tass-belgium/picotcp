#include "pico_setup.h"
#include "pico_common.h"
#include "rb.h"

#define IS_MODULE_VDE
#include "pico_module_vde.h"
#undef IS_MODULE_VDE

/* Macro to convert priv field */
#define DEV_VDE(x) ((struct dev_vde *)((x)->priv))

#include <libvdeplug.h>


struct dev_vde {
  VDECONN vdeconn;
  pico_ethdev *eth;
};

/* TODO: make a nonblocking version that add packets to the out queue if needed */
int mod_vde_send(struct pico_frame *pkt)
{
  struct dev_vde *vde = DEV_VDE(pkt->owner);
  if (!vde->vdeconn)
    return -1;
  else
    return vde_send(vde->conn, pkt->data_hdr, pkt->data_len, 0);
}

int mod_vde_recv(struct pico_frame *pkt)
{
  return 0;
}

void mod_vde_run(void)
{

}

struct pico_frame* mod_vde_alloc(int payload_size)
{
  return pico_frame_alloc(&pico_module_vde, payload_size); // No overhead added.
}

struct pico_module *mod_vde_init(void *arg)
{
  struct pico_module *vde = pico_zalloc(sizeof(struct pico_module));
  if (!vde)
    return NULL;
  vde->priv = pico_zalloc(sizeof(struct proto_vde));
  vde->to_lower.recv = mod_vde_recv;
  vde->to_upper.send = mod_vde_send;
  vde->run = mod_vde_run;
  return vde;
}

void mod_vde_shutdown(struct pico_module *vde)
{
  /* TODO */
}

struct pico_module  pico_module_vde = {
  .init = mod_vde_init,
  .shutdown = mod_vde_shutdown,
  .name = "vde"
};



#ifdef UNIT_IPV4_MAIN
int main(void) {
  struct pico_module vde;
  mod_vde_init(&vde);
}

#endif
