/* PicoTCP Test application */

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"

#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
//struct pico_ip4 inaddr_any = {0x0400280a};
struct pico_ip4 inaddr_any = { };
static char *cpy_arg(char **dst, char *str);

/*** APPLICATIONS API: ***/
/* To create a new application, define your initialization
 * function and your callback here */


/**** UDP ECHO ****/
void cb_udpecho(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[1400];
  int r=0;
  uint32_t peer;
  uint16_t port;

  //printf("udpecho> wakeup\n");
  if (ev == PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port);
      if (r > 0)
        pico_socket_sendto(s, recvbuf, r, &peer, port);
    } while(r>0);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(7);
  }
}

void app_udpecho(char *arg)
{
  struct pico_socket *s;
  char *sport;
  int port = 0;
  uint16_t port_be = 0;
  printf("sport: %s\n", arg);
  cpy_arg(&sport, arg);
  if (sport) {
    port = atoi(sport);
    if (port > 0)
      port_be = short_be(port);
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpecho);
  if (!s)
    exit(1);

  if (pico_socket_bind(s, &inaddr_any, &port_be)!= 0)
    exit(1);

}
/*** END UDP ECHO ***/

/*** TCP ECHO ***/
void cb_tcpecho(uint16_t ev, struct pico_socket *s)
{
  #define BSIZE 1400
  char recvbuf[BSIZE];
  int r=0, w = 0;
  int pos = 0, len = 0;
  

  //printf("tcpecho> wakeup\n");
  switch (ev) {
    case PICO_SOCK_EV_RD:
    do {
      r = pico_socket_read(s, recvbuf + len, BSIZE - len);
      if (r > 0)
        len += r;
    } while(r>0);
    /* Fall through */
    case PICO_SOCK_EV_WR:
    do {
      w = pico_socket_write(s, recvbuf + pos, len - pos);
      if (w > 0) {
        pos += w;
        if (pos >= len) {
          pos = 0;
          len = 0;
        }
      }
    } while(w > 0);
    break;
  }
  if (ev & PICO_SOCK_EV_CONN) { 
    struct pico_socket *sock_a;
    struct pico_ip4 orig;
    uint16_t port;
    char peer[30];
    sock_a = pico_socket_accept(s, &orig, &port);
    pico_ipv4_to_string(peer, orig.addr);
    printf("Connection established with %s:%d.\n", peer, short_be(port));
  }

  if (ev == PICO_SOCK_EV_FIN) {
    printf("Socket closed. Exit normally. \n");
    exit(0);
  }


  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(1);
  }
  if (ev == PICO_SOCK_EV_CLOSE) {
    printf("Socket received close from peer.\n");
    pico_socket_close(s);
  }
}
void app_tcpecho(char *arg)
{
  struct pico_socket *s;
  char *sport = arg;
  int port = 0;
  uint16_t port_be = 0;
  cpy_arg(&sport, arg);
  if (sport) {
    port = atoi(sport);
    port_be = short_be((uint16_t)port);
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpecho);
  if (!s)
    exit(1);

  if (pico_socket_bind(s, &inaddr_any, &port_be)!= 0)
    exit(1);

  if (pico_socket_listen(s, 40) != 0)
    exit(1);

}
/*** END TCP ECHO ***/

/*** UDP CLIENT ***/
void app_udpclient(char *arg)
{

}
/*** END UDP CLIENT ***/

/*** TCP CLIENT ***/
void app_tcpclient(char *arg)
{

}
/*** END TCP CLIENT ***/


#if 0
void wakeup(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[30];
  int r=0;
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
    sprintf(sendbuf,"TEST CALLBACK");
    msgLength = pico_socket_write(send, sendbuf, sizeof("TEST CALLBACK"));
    if (msgLength < 0)
      printf("pico_err - socket_write : %d\n",pico_err);
    alarm(1);
  }
}
#endif


void callback_exit(int signum)
{
  if (signum == SIGUSR1) {
    //pico_socket_shutdown(send, PICO_SHUT_WR);
  }
}

#define NXT_MAC(x) ++x[5]

/* Copy a string until the separator, 
terminate it and return the next index, 
or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
{
  char *p, *nxt = NULL;
  char *start = str;
  p = str;
  while (p && *p) {
    if (*p == ':') {
      *p = (char)0;
      nxt = p + 1;
      if (*nxt == 0)
        nxt = 0;
      *dst = strdup(start);
      break;
    }
    p++;
  }
  return nxt;
}


void usage(char *arg0)
{
  printf("Usage: %s [--vde name:sock:address:netmask[:gateway]] [--vde ...] [--tun name:address:netmask[:gateway]] [--tun ...] [--app name[:args]]\n\n\n", arg0);
  printf("\tall arguments can be repeated, e.g. to run on multiple links or applications\n");
  printf("\t*** --app arguments must be at the end  ***\n");
  exit(255);
}

#define IF_APPNAME(x) if(strcmp(x, name) == 0)

int main(int argc, char **argv)
{
  unsigned char macaddr[6] = {0,0,0,0xa,0xb,0x0};
  struct pico_device *dev = NULL;

  struct option long_options[] = {
    {"help",0 , 0, 'h'},
    {"vde",1 , 0, 'v'},
    {"tun", 1, 0, 't'},
    {"app", 1, 0, 'a'},
    {0,0,0,0}
  };

  int option_idx = 0;
  int c;

  signal(SIGUSR1, callback_exit);
  pico_stack_init();
  /* Parse args */
  while(1) {
    c = getopt_long(argc, argv, "v:t:a:h", long_options, &option_idx);
    if (c < 0)
      break;
    switch(c) {
      case 'h':
        usage(argv[0]);
        break;
      case 't':
      {
        char *nxt, *name = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
        struct pico_ip4 ipaddr, netmask, gateway;
        do {
          nxt = cpy_arg(&name, optarg);
          if (!nxt) break;
          nxt = cpy_arg(&addr, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&nm, nxt);
          if (!nxt) break;
          cpy_arg(&gw, nxt);
        } while(0);
        if (!nm) {
          fprintf(stderr, "Tun: bad configuration...\n");
          exit(1);
        }
        dev = pico_tun_create(name);
        if (!dev) {
          perror("Creating tun");
          exit(1);
        }
        pico_string_to_ipv4(addr, &ipaddr.addr);
        pico_string_to_ipv4(nm, &netmask.addr);
        pico_ipv4_link_add(dev, ipaddr, netmask);
        if (gw && *gw) {
          pico_string_to_ipv4(gw, &gateway.addr);
          pico_ipv4_route_add(ipaddr, netmask, gateway, 1, NULL);
        }
      }
      break;
    case 'v':
      {
        char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
        struct pico_ip4 ipaddr, netmask, gateway;
        do {
          nxt = cpy_arg(&name, optarg);
          if (!nxt) break;
          nxt = cpy_arg(&sock, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&addr, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&nm, nxt);
          if (!nxt) break;
          cpy_arg(&gw, nxt);
        } while(0);
        if (!nm) {
          fprintf(stderr, "Vde: bad configuration...\n");
          exit(1);
        }
        dev = pico_vde_create(sock, name, macaddr);
        NXT_MAC(macaddr);
        if (!dev) {
          perror("Creating vde");
          exit(1);
        }
        pico_string_to_ipv4(addr, &ipaddr.addr);
        pico_string_to_ipv4(nm, &netmask.addr);
        pico_ipv4_link_add(dev, ipaddr, netmask);
        if (gw && *gw) {
          pico_string_to_ipv4(gw, &gateway.addr);
          pico_ipv4_route_add(ipaddr, netmask, gateway, 1, NULL);
        }
      }
      break;
    case 'a':
      {
        char *name = NULL, *args = NULL;
        args = cpy_arg(&name, optarg);
        IF_APPNAME("udpecho") {
          app_udpecho(args);
        }
        else IF_APPNAME("tcpecho") {
          app_tcpecho(args);
        }
        else IF_APPNAME("udpclient") {
          app_udpclient(args);
        }
        else IF_APPNAME("tcpclient") {
          app_tcpclient(args);
        }
        else {
          fprintf(stderr, "Unknown application %s\n", name);
          usage(argv[0]);
        }
      }
      break;
    }
  }
  if (!dev) {
    printf("nodev");
    usage(argv[0]);
  }


  printf("Entering loop...\n");
  while(1) {
    pico_stack_tick();
    usleep(2000);
  }
}

#if 0
int test1(char *arg) {

  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &wakeup);
  if (!sk_udp)
    return 2;

  if (pico_socket_bind(sk_udp, &address0, &port)!= 0)
    return 1;
  
  
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


#endif
