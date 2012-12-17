#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"

#include <signal.h>
#include <unistd.h>

#define SUCCESS 0

#define TEST_FAILED 9

struct pico_socket *client = NULL;
static struct pico_socket *send;
static int shutdown = 0;
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
      printf("error recvfrom - %d - good\n",pico_err);
    
    //pico_socket_shutdown(send, PICO_SHUT_WR);
    kill(getpid(),SIGUSR1);
  }

  if (ev == PICO_SOCK_EV_FIN) {
    printf("Socket closed \n");
    shutdown = 1;
  }


}


void callback_exit(int signum)
{
  if (signum == SIGUSR1) {
    printf("SERVER > EXIT WRITE ISSUED\n");
    pico_socket_shutdown(send, PICO_SHUT_WR);
  }
}



int main(int argc, char **argv)
{
  unsigned char macaddr0[6] = {0,0,0,0xa,0xb,0xc};
  struct pico_device *vde0;
  struct pico_ip4 address0, netmask0, address1, netmask1;

  struct pico_socket *sk_udp, *sk_tcp;
  uint16_t port = short_be(5555);

  pico_stack_init();

  int TestNumber = atoi(argv[1]);

  address0.addr = 0x0300280a; //  10.40.0.3
  netmask0.addr = 0x00FFFFFF;

  address1.addr = 0x0300290a; //  10.41.0.3
  netmask1.addr = 0x00FFFFFF;

  vde0 = pico_vde_create("/tmp/pic0.ctl", "vde0", macaddr0);
  if (!vde0){
    printf("vde NOT created");
    return 1;
    exit(1);
  }else if(TestNumber==1){
    printf("vde created");
    return SUCCESS;
    exit(1);
  }

  //vde1 = pico_vde_create("/tmp/pic1.ctl", "vde1", macaddr1);
  //if (!vde1)
  //  return 1;

  pico_ipv4_link_add(vde0, address0, netmask0);
  //pico_ipv4_link_add(vde1, address1, netmask1);

  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
  if (!sk_udp){
    printf("UDP socket not open\n");
    return 2;
    exit(1);
  }else if(TestNumber==2){
    printf("UDP socket open\n");
    return SUCCESS;
    exit(1);
  }

  sk_tcp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &wakeup);
  if (!sk_tcp){
      printf("TCP socket not open\n");
    return 3;
    exit(1);
  }else if(TestNumber==3){
    printf("TCP socket open\n");
    return SUCCESS;
    exit(1);
  }
  
  if (pico_socket_bind(sk_udp, &address0, &port)!= 0){
    printf("UDP socket bind failed\n");
    return 4;
    exit(1);
  }else if(TestNumber==4){
    printf("UDP socket bind\n");
    return SUCCESS;
    exit(1);
  }
 
  if (pico_socket_bind(sk_tcp, &address0, &port)!= 0){
    printf("TCP socket bind failed\n");
    return 5;
    exit(1);
  }else if(TestNumber==5){
    printf("TCP socket bind succes\n");
    return SUCCESS;
    exit(1);
  }

  if (pico_socket_listen(sk_tcp, 3)!=0){
    printf("TCP socket listen failed\n");
    return 7;
    exit(1);
  }else if(TestNumber==7){
    printf("TCP socket listen\n");
    return SUCCESS;
    exit(1);
  }
  send = sk_tcp;

  signal(SIGUSR1, callback_exit);

  while(1) {
    
    if(shutdown){
      printf("Shutting down\n");
      return SUCCESS;     
      exit(1);
    }
    pico_stack_tick();
    usleep(2000);
  }

  return 0;

}


