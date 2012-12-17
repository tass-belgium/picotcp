#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"

#include <poll.h>
#include <unistd.h>
#include <signal.h>

#define TEST_SUCCESS 10
#define TEST_FAILED 9

static int connected = 0, shutdown=0;
static int msgLength=0;
static int cmpTestCorrect = 0;
static char sendbuf[100];
static struct pico_socket *send;

void wakeup(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[30];
  int r=0, ret=0;
  uint32_t peer;
  uint16_t port;

  printf("Called wakeup\n");
  if (ev == PICO_SOCK_EV_RD) { 
    do {
      r = pico_socket_recvfrom(s, recvbuf, 30, &peer, &port);
      printf("------------------------------------- Receive: %d\n", r);
      if (r > 0) {
        printf("---tester------------> Message = %s------------------------------------- \n",recvbuf);
        if(memcmp(recvbuf,sendbuf,msgLength)==0){
          printf("compare ECHO correct!\n");
          cmpTestCorrect = 1;
          pico_socket_shutdown(send, PICO_SHUT_WR);
       }else{
          printf("Compare failed\n");
          return TEST_FAILED;
          exit(1);
        }
      }
    } while(r>0);
  }
  if (ev & PICO_SOCK_EV_CONN) { 
    if (connected) {
      printf("Error: already connected.\n");
    } else {
      printf("Connection established.\n");
      connected = 1;
    }
  }

  if (ev == PICO_SOCK_EV_FIN) {
    printf("Socket closed \n");
    shutdown = 1;
  }


  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(0);
  }
  if (ev == PICO_SOCK_EV_CLOSE) {
    printf("Socket received close\n");
  }
}


void send_callback(int signum)
{
  if (signum == SIGALRM) {
    int ret;
    sprintf(sendbuf,"TEST CALLBACK");
    msgLength = pico_socket_write(send, sendbuf, sizeof("TEST CALLBACK"));
    if (ret < 0)
      printf("pico_err - socket_write : %d\n",pico_err);
    alarm(1);
  }
}


void callback_exit(int signum)
{
  if (signum == SIGUSR1) {
    pico_socket_shutdown(send, PICO_SHUT_WR);
  }
}

int main(int argc, char **argv)
{
  unsigned char macaddr0[6] = {0,0,0,0xa,0xb,0xd};
  struct pico_device *vde0;
  struct pico_ip4 address0, netmask0, address1;

  struct pico_socket *sk_udp, *sk_tcp;
  uint16_t port = short_be(5555);

  struct pollfd fds;
  char buffer[100];
  int ret;
  int TestNumber = atoi(argv[1]);

  signal(SIGUSR1, callback_exit);
  signal(SIGALRM, send_callback);

  pico_stack_init();

  address1.addr = 0x0300280a; //  10.40.0.3 server
  netmask0.addr = 0x00FFFFFF;
  address0.addr = 0x0200280a; //  10.40.0.2 client (this)

  vde0 = pico_vde_create("/tmp/pic0.ctl", "vde0", macaddr0);
  if (!vde0){
    return 1;
    printf("failed to create vde(pic0)\n:");
  }else{
    printf("VDE created\n");
  }
  
  pico_ipv4_link_add(vde0, address0, netmask0);
  /*
  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
  if (!sk_udp)
    return 2;

  if (pico_socket_bind(sk_udp, &address0, &port)!= 0)
    return 1;
  */
  
  sk_tcp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &wakeup);
  if (!sk_tcp)
    return 2;

  if (pico_socket_bind(sk_tcp, &address0, &port)!= 0)
    return 1;
  
  printf("sleep\n");
  //sleep(2);
  printf("end sleep\n");

  if (pico_socket_connect(sk_tcp, &address1, port)!=0)
    return 3;

  fds.fd = STDIN_FILENO;
  fds.events = POLLIN;
  
  send = sk_tcp;
  alarm(1);
  
  while(1) {
    pico_stack_tick();
    usleep(2000);

    if (connected && poll(&fds,1,0)) {
      printf("read POLLIN\n");
      msgLength = read(STDIN_FILENO,buffer,100);
      if (msgLength){
        printf("write on socket\n");
        pico_socket_write(sk_tcp, buffer, msgLength);
      }
    }

    if(shutdown && cmpTestCorrect){
       if(TestNumber==9){
         printf("Shutdown with compare SUCCESS\n"); 
         return 0;
         pico_socket_shutdown(send, PICO_SHUT_WR);
         exit(1);
        }
    }else if(shutdown && (cmpTestCorrect==0)){
      printf("Shutdown with compare FAILED\n");
      pico_socket_shutdown(send, PICO_SHUT_WR);
      return 8;
      exit(1);
    }
  }
  return 0;
}


