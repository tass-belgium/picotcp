#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_nat.h"

#include <signal.h>
#include <unistd.h>

static struct pico_socket *client = NULL;
static struct pico_socket *send;

void wakeup(uint16_t ev, struct pico_socket *s)
{
  char buf[30];
  int r;
  uint32_t peer;
  uint16_t port;

  printf("Called wakeup\n");
  if (ev == PICO_SOCK_EV_RD) { 
    do {
      r = pico_socket_recvfrom(s, buf, 30, &peer, &port);
      printf("------------------------------------- Receive: %d\n", r);
      if (r > 0) {
        pico_socket_write(s, buf, r);
      } else if (r < 0) {
        printf("error recvfrom - %d\n",pico_err);
      }
    } while(r>0);
  }
  if (ev == PICO_SOCK_EV_CONN) { 
    if (client) {
      printf("Socket busy: try again later.\n");
    } else {
      client = pico_socket_accept(s, &peer, &port);
      send = client;
      if (client)
        printf("Connection established.\n");
      else
        printf("accept: Error.\n");
    }
  }
  if (ev == PICO_SOCK_EV_CLOSE) {
    printf("Socket received event close\n");
    
    /* test read on shut socket */
    r = pico_socket_recvfrom(s, buf, 30, &peer, &port);
    if (r >= 0)
      printf("messed up reading from closed socket\n"); //DELME
    else if (r < 0)
      printf("pico_err - socket_recvfrom - %s - good?\n",strerror(pico_err));
    
    //pico_socket_shutdown(send, PICO_SHUT_WR);
    kill(getpid(),SIGUSR1);
  }
  if (ev == PICO_SOCK_EV_FIN) {
    printf("Socket is going to be closed!\n");
    /* test read on shut socket */
    r = pico_socket_recvfrom(s, buf, 30, &peer, &port);
    if (r >= 0)
      printf("messed up reading from closed socket\n"); //DELME
    else if (r < 0)
      printf("pico_err - socket_recvfrom - %s - good?\n",strerror(pico_err));
  }
}


void callback_exit(int signum)
{
  if (signum == SIGUSR1) {
    printf("SERVER > EXIT WRITE ISSUED\n");
    pico_socket_shutdown(client, PICO_SHUT_WR);
  }
}



int main(void)
{
  unsigned char macaddr1[6] = {0xb1,0,0,0xa,0xb,0xf};
  unsigned char macaddr2[6] = {0xb2,0,0,0xa,0xb,0xe};
  struct pico_device *vde1, *vde2;
  struct pico_ip4 address2, netmask2, address1, netmask1;
  struct pico_ipv4_link *nat_link = NULL;
  pico_stack_init();

  address1.addr = 0xFE00280a;   // 10.40.0.254
  netmask1.addr = 0x00FFFFFF;

  address2.addr = 0xFE00320a;   // 10.50.0.254
  netmask2.addr = 0x00FFFFFF;

  vde1 = pico_vde_create("/tmp/pic0.ctl", "vde1", macaddr1);
  if (!vde1)
    return 1;

  vde2 = pico_vde_create("/tmp/pic1.ctl", "vde2", macaddr2);
  if (!vde2)
    return 1;

  /* add local devices vde1, vde2 */
  pico_ipv4_link_add(vde1, address1, netmask1);
  pico_ipv4_link_add(vde2, address2, netmask2);

  nat_link = pico_ipv4_link_get(&address2);
  pico_ipv4_nat_enable(nat_link);  

  while(1) {
    pico_stack_tick();
    usleep(2000);
  }

  return 0;
}
