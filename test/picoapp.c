/* PicoTCP Test application */

#include "pico_stack.h"
#include "pico_config.h"
#include "pico_dev_vde.h"
#include "pico_ipv4.h"
#include "pico_socket.h"
#include "pico_dev_tun.h"
#include "pico_nat.h"
#include "pico_icmp4.h"
#include "pico_dns_client.h"
#include "pico_dev_loop.h"
#include "pico_dhcp_client.h"
#include "pico_dhcp_server.h"
#include "pico_ipfilter.h"
#include "pico_http_client.h"
#include "pico_http_server.h"
#include "pico_http_util.h"

#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

//#define INFINITE_TCPTEST
#define picoapp_dbg(...) do{}while(0)
//#define picoapp_dbg printf

//#define PICOAPP_IPFILTER 1

struct pico_ip4 inaddr_any = { };
static char *cpy_arg(char **dst, char *str);

void deferred_exit(unsigned long now, void *arg)
{
  if (arg) {
    free(arg);
    arg = NULL;
  }

  printf("%s: quitting\n", __FUNCTION__);
  exit(0);
}

/*** APPLICATIONS API: ***/
/* To create a new application, define your initialization
 * function and your callback here */


/**** UDP ECHO ****/
static int udpecho_exit = 0;

struct udpecho_pas {
  struct pico_socket *s;
  uint16_t datasize;
}; /* per application struct */

static struct udpecho_pas *udpecho_pas;

void cb_udpecho(uint16_t ev, struct pico_socket *s)
{
  int r = 0;
  uint32_t peer = 0;
  uint16_t port = 0;
  char *recvbuf = NULL;

  if (udpecho_exit)
    return;

  if (ev == PICO_SOCK_EV_RD) {
    recvbuf = calloc(1, udpecho_pas->datasize);
    if (!recvbuf) {
      printf("%s: no memory available\n", __FUNCTION__);
      return;
    }
    do {
      r = pico_socket_recvfrom(s, recvbuf, udpecho_pas->datasize, &peer, &port);
      if (r > 0) {
        if (strncmp(recvbuf, "end", 3) == 0) {
          printf("Client requested to exit... test successful.\n");
          pico_timer_add(1000, deferred_exit, udpecho_pas);
          udpecho_exit++;
        }
        pico_socket_sendto(s, recvbuf, r, &peer, port);
      }
    } while(r>0);
    free(recvbuf);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    free(udpecho_pas);
    exit(7);
  }

  picoapp_dbg("Received packet from %08X:%u\n", peer, port);
}

void app_udpecho(char *arg)
{
  int port = 0;
  uint16_t port_be = 0;
  char *sport = NULL, *s_datasize = NULL;
  char *nxt = arg;

  udpecho_pas = calloc(1, sizeof(struct udpecho_pas));
  if (!udpecho_pas) {
    printf("%s: no memory available\n", __FUNCTION__);
    exit(255);
  }
  udpecho_pas->s = NULL;
  udpecho_pas->datasize = 1400;

  if (nxt) {
    nxt = cpy_arg(&sport, arg);
    if (sport) {
      port = atoi(sport);
      free(sport);
      if (port > 0)
        port_be = short_be(port);
    }
    if (port == 0) {
      port_be = short_be(5555);
    }
  } else {
    /* missing dest_port */
    fprintf(stderr, "udpecho expects the following format: udpecho:dest_port[:datasize]\n");
    free(udpecho_pas);
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&s_datasize, nxt);
    if (s_datasize && atoi(s_datasize)) {
      udpecho_pas->datasize = atoi(s_datasize);
      free(s_datasize);
    } else {
      /* incorrect datasize */
      fprintf(stderr, "udpecho expects the following format: udpecho:dest_port[:datasize]\n");
      free(udpecho_pas);
      exit(255);
    }
  }

  printf("\n%s: UDP echo launched. Receiving packets of %u bytes on port %u\n", __FUNCTION__, udpecho_pas->datasize, short_be(port_be));

  udpecho_pas->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpecho);
  if (!udpecho_pas->s) {
    free(udpecho_pas);
    exit(1);
  }

  if (pico_socket_bind(udpecho_pas->s, &inaddr_any, &port_be)!= 0) {
    free(udpecho_pas);
    exit(1);
  }

#ifdef PICOAPP_IPFILTER
  {
    struct pico_ip4 address, in_addr_netmask, in_addr;
    //struct pico_ipv4_link *link;
    int ret = 0;
    address.addr = 0x0800280a;
    in_addr_netmask.addr = 0x00FFFFFF;
    in_addr.addr = 0x0000320a;
    //link = pico_ipv4_link_get(&address);

    printf("udpecho> IPFILTER ENABLED\n");

    /*Adjust your IPFILTER*/
    ret |= pico_ipv4_filter_add(NULL, 17, NULL, NULL, &in_addr, &in_addr_netmask, 0, 5555, 0, 0, FILTER_DROP);

    if (ret < 0)
      printf("Filter_add invalid argument\n");
  }
#endif

}
/*** END UDP ECHO ***/

/*** TCP ECHO ***/
#define BSIZE (1024 * 10)
static char recvbuf[BSIZE];
static int pos = 0, len = 0;
static int flag = 0;

int send_tcpecho(struct pico_socket *s)
{
  int w, ww = 0;
  if (len > pos) {
    do {
      w = pico_socket_write(s, recvbuf + pos, len - pos);
      if (w > 0) {
        pos += w;
        ww += w;
        if (pos >= len) {
          pos = 0;
          len = 0;
        }
      } else {
        errno = pico_err;
      }
    } while((w > 0) && (pos < len));
  }
  return ww;
}
void cb_tcpecho(uint16_t ev, struct pico_socket *s)
{
  int r=0;

//  printf("tcpecho> wakeup ev=%04x\n", ev);

  if (ev & PICO_SOCK_EV_RD) {
    if (flag & PICO_SOCK_EV_CLOSE)
      printf("SOCKET> EV_RD, FIN RECEIVED\n");
    while(len < BSIZE) {
      r = pico_socket_read(s, recvbuf + len, BSIZE - len);
      if (r > 0) {
        len += r;
        flag &= ~(PICO_SOCK_EV_RD);
      } else {
      }
      if (r <= 0) {
        flag |= PICO_SOCK_EV_RD;
        break;
      }
    }
  }
  if (ev & PICO_SOCK_EV_CONN) { 
    struct pico_socket *sock_a;
    struct pico_ip4 orig;
    uint16_t port;
    char peer[30];
    sock_a = pico_socket_accept(s, &orig, &port);
    pico_socket_accept(s, &orig, &port);
    pico_ipv4_to_string(peer, orig.addr);
    printf("Connection established with %s:%d.\n", peer, short_be(port));
    pico_socket_setoption(sock_a, PICO_TCP_NODELAY, NULL);
  }

  if (ev & PICO_SOCK_EV_FIN) {
    printf("Socket closed. Exit normally. \n");
    pico_timer_add(2000, deferred_exit, NULL);
  }

  if (ev & PICO_SOCK_EV_ERR) {
    printf("Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    exit(1);
  }
  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("Socket received close from peer.\n");
    flag |= PICO_SOCK_EV_CLOSE;
    //pico_socket_close(s);
    if ((flag & PICO_SOCK_EV_RD) && (flag & PICO_SOCK_EV_CLOSE)) {
      pico_socket_shutdown(s, PICO_SHUT_WR);
      printf("SOCKET> Called shutdown write, ev = %d\n",ev);
    }
  }
  if (ev & PICO_SOCK_EV_WR) {
    r = send_tcpecho(s);
    if (r == 0) 
      flag |= PICO_SOCK_EV_WR;
    else
      flag &= (~PICO_SOCK_EV_WR);
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

  pico_socket_setoption(s, PICO_TCP_NODELAY, NULL);

#ifdef PICOAPP_IPFILTER
  {
    struct pico_ip4 address, in_addr_netmask, in_addr;
    //struct pico_ipv4_link *link;
    int ret = 0;
    address.addr = 0x0800280a;
    in_addr_netmask.addr = 0x00FFFFFF;
    in_addr.addr = 0x0000320a;
    //link = pico_ipv4_link_get(&address);

    printf("tcpecho> IPFILTER ENABLED\n");

    /*Adjust your IPFILTER*/
    ret |= pico_ipv4_filter_add(NULL, 6, NULL, NULL, &in_addr, &in_addr_netmask, 0, 5555, 0, 0, FILTER_REJECT);

    if (ret < 0)
      printf("Filter_add invalid argument\n");
  }
#endif
  printf("%s: launching PicoTCP echo server loop\n", __FUNCTION__);
}
/*** END TCP ECHO ***/

/*** UDP DNS CLIENT ***/
/* 
./test/vde_sock_start.sh
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
iptables -A FORWARD -i pic0 -o wlan0 -j ACCEPT
iptables -A FORWARD -i wlan0 -o pic0 -j ACCEPT
./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0:10.40.0.1: -a udpdnsclient:www.google.be:173.194.67.94 
*/
void cb_udpdnsclient_getaddr(char *ip, void *arg)
{
  uint8_t *id = (uint8_t *) arg; 

  if (!ip) {
    printf("%s: ERROR occured! (id: %u)\n", __FUNCTION__, *id);
    return;
  }
  printf("%s: ip %s (id: %u)\n", __FUNCTION__, ip, *id);
  pico_free(ip);
  if (arg)
    pico_free(arg);
}

void cb_udpdnsclient_getname(char *name, void *arg)
{
  uint8_t *id = (uint8_t *) arg; 

  if (!name) {
    printf("%s: ERROR occured! (id: %u)\n", __FUNCTION__, *id);
    return;
  }
  printf("%s: name %s (id: %u)\n", __FUNCTION__, name, *id);
  pico_free(name);
  if (arg)
    pico_free(arg);
}

void app_udpdnsclient(char *arg)
{
  struct pico_ip4 nameserver;
  char *dname, *daddr;
  char *nxt;
  uint8_t *getaddr_id, *getname_id;

  nxt = cpy_arg(&dname, arg);
  if (!dname) {
    fprintf(stderr, " udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&daddr, nxt);
    if (!daddr) {
      fprintf(stderr, " udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip\n");
      fprintf(stderr, " missing dest_ip\n");
      exit(255);
    }
  } else {
    fprintf(stderr, " udpdnsclient expects the following format: udpdnsclient:dest_name:dest_ip\n");
    fprintf(stderr, " missing dest_ip\n");
    exit(255);
  }

  printf("UDP DNS client started.\n");
  
  picoapp_dbg("----- Deleting non existant nameserver -----\n");
  pico_string_to_ipv4("127.0.0.1", &nameserver.addr);
  pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_DEL);
  picoapp_dbg("----- Adding 8.8.8.8 nameserver -----\n");
  pico_string_to_ipv4("8.8.8.8", &nameserver.addr);
  pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_ADD);
  picoapp_dbg("----- Deleting 8.8.8.8 nameserver -----\n");
  pico_string_to_ipv4("8.8.8.8", &nameserver.addr);
  pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_DEL);
  picoapp_dbg("----- Adding 8.8.8.8 nameserver -----\n");
  pico_string_to_ipv4("8.8.8.8", &nameserver.addr);
  pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_ADD);
  picoapp_dbg("----- Adding 8.8.4.4 nameserver -----\n");
  pico_string_to_ipv4("8.8.4.4", &nameserver.addr);
  pico_dns_client_nameserver(&nameserver, PICO_DNS_NS_ADD);

  getaddr_id = calloc(1, sizeof(uint8_t));
  *getaddr_id = 1;
  printf(">>>>> DNS GET ADDR OF %s\n", dname);
  pico_dns_client_getaddr(dname, &cb_udpdnsclient_getaddr, getaddr_id);
  getname_id = calloc(1, sizeof(uint8_t));
  *getname_id = 2;
  printf(">>>>> DNS GET NAME OF %s\n", daddr);
  pico_dns_client_getname(daddr, &cb_udpdnsclient_getname, getname_id);

  return;
}
/*** END UDP DNS CLIENT ***/

/*** UDP NAT CLIENT ***/
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.9:255.255.0.0:10.40.0.10: -a udpnatclient:10.50.0.8:6667: */
static struct pico_ip4 udpnatclient_inaddr_dst;
static uint16_t udpnatclient_port_be;

void udpnatclient_send(unsigned long now, void *arg) {
  int i, w;
  struct pico_socket *s = (struct pico_socket *)arg;
  char buf[1400] = { };
  char end[4] = "end";
  static int loop = 0;

  for ( i = 0; i < 3; i++) {
    w = pico_socket_send(s, buf, 1400);
  }

  if (++loop > 1000) {
    udpnatclient_port_be = 0;
    for (i = 0; i < 3; i++) {
      w = pico_socket_send(s, end, 4);
      if (w <= 0)
        break;
      printf("End!\n");
    }
    pico_timer_add(1000, deferred_exit, NULL);
    return;
  }
}

void cb_udpnatclient(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[1400];
  int r=0;
  uint32_t peer;
  uint16_t port;

  if (ev & PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_recvfrom(s, recvbuf, 1400, &peer, &port);
    } while(r>0);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(7);
  }

  /* Not closing to test port check */
  //pico_socket_close(s);
}

void udpnatclient_open_socket(unsigned long now, void *arg)
{
  struct pico_socket *s = NULL;
  static int loop;

  if (!udpnatclient_port_be)
    return;

  loop++;
  picoapp_dbg(">>>>> Loop %d\n", loop);
  if (!(loop % 100))
    printf("Created %d sockets\n", loop);

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpnatclient);
  if (!s)
    exit(1);

  if (pico_socket_connect(s, &udpnatclient_inaddr_dst, udpnatclient_port_be)!= 0)
    exit(1);

  picoapp_dbg("New socket with port %u\n", s->local_port);

  pico_timer_add(25, udpnatclient_send, s);
  pico_timer_add(25, udpnatclient_open_socket, 0);
}

void app_udpnatclient(char *arg)
{
  struct pico_socket *s;
  char *daddr, *dport;
  int port = 0;
  uint16_t port_be = 0;
  struct pico_ip4 inaddr_dst = { };
  char *nxt;

  nxt = cpy_arg(&daddr, arg);
  if (!daddr) {
    fprintf(stderr, " udpnatclient expects the following format: udpnatclient:dest_addr[:dest_port]\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&dport, nxt);
    if (dport) {
      port = atoi(dport);
      if (port > 0)
        port_be = short_be(port);
    }
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  printf("UDP NAT client started. Sending packets to %s:%d\n", daddr, short_be(port_be));

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpnatclient);
    if (!s)
      exit(1);

    pico_string_to_ipv4(daddr, &inaddr_dst.addr);

    if (pico_socket_connect(s, &inaddr_dst, port_be)!= 0)
      exit(1);

    picoapp_dbg("New socket with port %u\n", s->local_port);

    udpnatclient_inaddr_dst = inaddr_dst;
    udpnatclient_port_be = port_be;

    pico_timer_add(100, udpnatclient_send, s);
    pico_timer_add(1000, udpnatclient_open_socket, 0);
}
/*** END UDP NAT CLIENT ***/

/*** UDP CLIENT ***/
struct udpclient_pas {
  struct pico_socket *s;
  uint8_t loops;
  uint8_t subloops;
  uint16_t datasize;
}; /* per application struct */

static struct udpclient_pas *udpclient_pas;

void udpclient_send(unsigned long now, void *arg) {
  struct pico_socket *s = udpclient_pas->s;
  char end[4] = "end";
  char *buf = NULL;
  int i = 0, w = 0;
  static uint16_t loop = 0;

  if (++loop > udpclient_pas->loops) {
    for (i = 0; i < 3; i++) {
      w = pico_socket_send(s, end, 4);
      if (w <= 0)
        break;
      printf("%s: requested exit of echo\n", __FUNCTION__);
    }
    pico_timer_add(1000, deferred_exit, udpclient_pas);
    return;
  } else {
    buf = calloc(1, udpclient_pas->datasize);
    if (!buf) {
      printf("%s: no memory available\n", __FUNCTION__);
      return;
    }
    memset(buf, '1', udpclient_pas->datasize);
    picoapp_dbg("%s: performing loop %u\n", __FUNCTION__, loop);
    for (i = 0; i < udpclient_pas->subloops; i++) {
      w = pico_socket_send(s, buf, udpclient_pas->datasize);
      if (w <= 0)
        break;
    }
    picoapp_dbg("%s: written %u byte(s) in each of %u subloops\n", __FUNCTION__, udpclient_pas->datasize, i);
    free(buf);
  }

  pico_timer_add(100, udpclient_send, NULL);
}

void cb_udpclient(uint16_t ev, struct pico_socket *s)
{
  char *recvbuf = NULL;
  int r = 0;
  uint32_t peer = 0;
  uint16_t port = 0;

  if (ev & PICO_SOCK_EV_RD) {
    recvbuf = calloc(1, udpclient_pas->datasize);
    if (!recvbuf) {
      printf("%s: no memory available\n", __FUNCTION__);
      return;
    }
    do {
      r = pico_socket_recvfrom(s, recvbuf, udpclient_pas->datasize, &peer, &port);
    } while(r>0);
    free(recvbuf);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    free(udpclient_pas);
    exit(7);
  }
}

void app_udpclient(char *arg)
{
  char *daddr = NULL, *dport = NULL, *s_datasize = NULL, *s_loops = NULL, *s_subloops = NULL;
  int port = 0;
  uint16_t port_be = 0;
  struct pico_ip4 inaddr_dst = { };
  char *nxt = arg;

  udpclient_pas = calloc(1, sizeof(struct udpclient_pas));
  if (!udpclient_pas) {
    printf("%s: no memory available\n", __FUNCTION__);
    exit(255);
  }
  udpclient_pas->s = NULL;
  udpclient_pas->loops = 100;
  udpclient_pas->subloops = 10;
  udpclient_pas->datasize = 1400;

  /* start of argument parsing */
  if (nxt) {
    nxt = cpy_arg(&daddr, arg);
    if (!daddr) {
      fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr[:dest_port:datasize:loops:subloops]\n");
      free(udpclient_pas);
      exit(255);
    }
  } else {
    /* missing dest_addr */
    fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr[:dest_port:datasize:loops:subloops]\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&dport, nxt);
    if (dport) {
      port = atoi(dport);
      if (port > 0)
        port_be = short_be(port);
    }
  } else {
    port_be = short_be(5555);
  }

  if (nxt) {
    nxt = cpy_arg(&s_datasize, nxt);
    if (s_datasize) {
      udpclient_pas->datasize = atoi(s_datasize);
      free(s_datasize);
    }
  } else {
    fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr[:dest_port:datasize:loops:subloops]\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&s_loops, nxt);
    if (s_loops) {
      udpclient_pas->loops = atoi(s_loops);
      free(s_loops);
    }
  } else {
    fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr[:dest_port:datasize:loops:subloops]\n");
    exit(255);
  }
 
  if (nxt) {
    nxt = cpy_arg(&s_subloops, nxt);
    if (s_subloops) {
      udpclient_pas->subloops = atoi(s_subloops);
      free(s_subloops);
    }
  } else {
    fprintf(stderr, "udpclient expects the following format: udpclient:dest_addr[:dest_port:datasize:loops:subloops]\n");
    exit(255);
  }
  /* end of argument parsing */
 
  printf("\n%s: UDP client launched. Sending packets of %u bytes in %u loops and %u subloops to %s:%u\n", 
          __FUNCTION__, udpclient_pas->datasize, udpclient_pas->loops, udpclient_pas->subloops, daddr, short_be(port_be));

  udpclient_pas->s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_udpclient);
  if (!udpclient_pas->s) {
    free(daddr);
    free(udpclient_pas);
    exit(1);
  }

  pico_string_to_ipv4(daddr, &inaddr_dst.addr);

  if (pico_socket_connect(udpclient_pas->s, &inaddr_dst, port_be)!= 0) {
    exit(1);
  }

  pico_timer_add(100, udpclient_send, NULL);
}
/*** END UDP CLIENT ***/

/*** TCP CLIENT ***/
#define TCPSIZ (1024 *1024 *50)
static char *buffer1;
static char *buffer0;

void compare_results(unsigned long now, void *arg)
{
#ifdef CONSISTENCY_CHECK /* TODO: Enable */
  int i;
  printf("Calculating result.... (%p)\n", buffer1);

  if (memcmp(buffer0,buffer1,TCPSIZ) == 0)
    exit(0);

  for (i = 0; i < TCPSIZ; i++) {
    if (buffer0[i] != buffer1[i]) {
      fprintf(stderr, "Error at byte %d - %c!=%c\n", i, buffer0[i], buffer1[i]);
      exit(115);
    }
  }
#endif
  exit(0);

}

void cb_tcpclient(uint16_t ev, struct pico_socket *s)
{
  static int w_size = 0;
  static int r_size = 0;
  static int closed = 0;
  int r,w;
  static unsigned long count = 0;

  count++;

  printf("tcpclient> wakeup %lu, event %u\n",count,ev);
  if (ev & PICO_SOCK_EV_RD) {
    do {
      r = pico_socket_read(s, buffer1 + r_size, TCPSIZ - r_size);
      if (r > 0) {
        r_size += r;
        printf("SOCKET READ - %d\n",r_size);
      }
      if (r < 0)
        exit(5);
    } while(r>0);
  }
  if (ev & PICO_SOCK_EV_CONN) { 
    printf("Connection established with server.\n");
  }

  if (ev & PICO_SOCK_EV_FIN) {
    printf("Socket closed. Exit normally. \n");
    pico_timer_add(2000, compare_results, NULL);
  }

  if (ev & PICO_SOCK_EV_ERR) {
    printf("Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    exit(1);
  }
  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("Socket received close from peer - Wrong case if not all client data sent!\n");
    pico_socket_close(s);
    return;
  }
  if (ev & PICO_SOCK_EV_WR) {
    if (w_size < TCPSIZ) {
      do {
        w = pico_socket_write(s, buffer0 + w_size, TCPSIZ-w_size);
        if (w > 0) {
          w_size += w;
          printf("SOCKET WRITTEN - %d\n",w_size);
        if (w < 0)
          exit(5);
        }
      } while(w > 0);
    } else {
#ifdef INFINITE_TCPTEST
      w_size = 0;
      return;
#endif
      if (!closed) {
        pico_socket_shutdown(s, PICO_SHUT_WR);
        printf("Called shutdown()\n");
        closed = 1;
      }
    }
  }
}

void app_tcpclient(char *arg)
{
  struct pico_socket *s;
  char *dport;
  char *dest;
  int port = 0, i;
  uint16_t port_be = 0;
  struct pico_ip4 server_addr;
  char *nxt = cpy_arg(&dest, arg);
  if (!dest) {
    fprintf(stderr, "tcpclient needs the following format: tcpclient:dst_addr[:dport]\n");
    exit(255);
  }
  printf ("+++ Dest is %s\n", dest);
  if (nxt) {
    printf("Next arg: %s\n", nxt);
    nxt=cpy_arg(&dport, nxt);
    printf("Dport: %s\n", dport);
  }
  if (dport) {
    port = atoi(dport);
    port_be = short_be((uint16_t)port);
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  buffer0 = malloc(TCPSIZ);
  buffer1 = malloc(TCPSIZ);
  printf("Buffer1 (%p)\n", buffer1);
  for (i = 0; i < TCPSIZ; i++) {
    char c = (i % 26) + 'a';
    buffer0[i] = c;
  }
  memset(buffer1, 'a', TCPSIZ);
  printf("Connecting to: %s:%d\n", dest, short_be(port_be));

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpclient);
  if (!s)
    exit(1); 

  pico_socket_setoption(s, PICO_TCP_NODELAY, NULL);
  
  /* NOTE: used to set a fixed local port and address
  local_port = short_be(6666);
  pico_string_to_ipv4("10.40.0.11", &local_addr.addr);
  pico_socket_bind(s, &local_addr, &local_port);*/
  
  pico_string_to_ipv4(dest, &server_addr.addr);
  pico_socket_connect(s, &server_addr, port_be);
}
/*** END TCP CLIENT ***/


/*** START TCP BENCH ***/

#define TCP_BENCH_TX  1
#define TCP_BENCH_RX  2

int tcpbench_mode = 0;
struct pico_socket *tcpbench_sock = NULL;
static unsigned long tcpbench_time_start,tcpbench_time_end;

void cb_tcpbench(uint16_t ev, struct pico_socket *s)
{
  static int closed = 0;
  static unsigned long count = 0;
  uint8_t recvbuf[1500];
  struct pico_ip4 orig;
  uint16_t port;
  char peer[30];
  //struct pico_socket *sock_a;

  static int tcpbench_wr_size = 0;
  static int tcpbench_rd_size = 0;
  int tcpbench_w = 0;
  int tcpbench_r = 0;
  double tcpbench_time = 0;

  count++;

  if (ev & PICO_SOCK_EV_RD) {
    do {
      /* read data, but discard */
      tcpbench_r = pico_socket_read(s, recvbuf, 1500);
      if (tcpbench_r > 0){
        tcpbench_rd_size += tcpbench_r;
      }
      else if (tcpbench_r < 0) {
        printf("tcpbench> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
        exit(5);
      }
    } while (tcpbench_r > 0);
    if (tcpbench_time_start == 0)
      tcpbench_time_start = PICO_TIME_MS();
    printf("tcpbench_rd_size = %d      \r", tcpbench_rd_size);
  }

  if (ev & PICO_SOCK_EV_CONN) { 
    if (tcpbench_mode == TCP_BENCH_TX) {
      printf("tcpbench> Connection established with server.\n");
    } else if (tcpbench_mode == TCP_BENCH_RX) {
      //sock_a = pico_socket_accept(s, &orig, &port);
      pico_socket_accept(s, &orig, &port);
      pico_ipv4_to_string(peer, orig.addr);
      printf("tcpbench> Connection established with %s:%d.\n", peer, short_be(port));
    }
  }

  if (ev & PICO_SOCK_EV_FIN) {
    printf("tcpbench> Socket closed. Exit normally. \n");
    if (tcpbench_mode == TCP_BENCH_RX) {
      tcpbench_time_end = PICO_TIME_MS();
      tcpbench_time = (tcpbench_time_end - tcpbench_time_start)/1000.0; /* get number of seconds */
      printf("tcpbench> received %d bytes in %lf seconds\n",tcpbench_rd_size,tcpbench_time);
      printf("tcpbench> average read throughput %lf kbit/sec\n",((tcpbench_rd_size*8.0)/tcpbench_time)/1000);
      pico_socket_shutdown(s, PICO_SHUT_WR);
      printf("tcpbench> Called shutdown write, ev = %d\n",ev);
    }
    exit(0);
  }

  if (ev & PICO_SOCK_EV_ERR) {
    printf("tcpbench> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
    exit(1);
  }

  if (ev & PICO_SOCK_EV_CLOSE) {
    printf("tcpbench> event close\n");
    if (tcpbench_mode == TCP_BENCH_RX) {
      pico_socket_shutdown(s, PICO_SHUT_WR);
      printf("tcpbench> Called shutdown write, ev = %d\n",ev);
    } else if (tcpbench_mode == TCP_BENCH_TX) {
      pico_socket_close(s);
      return;
    }
  }

  if (ev & PICO_SOCK_EV_WR) {
    if (tcpbench_wr_size < TCPSIZ && tcpbench_mode == TCP_BENCH_TX) {
      do {
        tcpbench_w = pico_socket_write(tcpbench_sock, buffer0 + tcpbench_wr_size, TCPSIZ-tcpbench_wr_size);
        if (tcpbench_w > 0) {
          tcpbench_wr_size += tcpbench_w;
          //printf("tcpbench> SOCKET WRITTEN - %d\n",tcpbench_w);
        }
        if (tcpbench_w < 0) {
          printf("tcpbench> Socket Error received: %s. Bailing out.\n", strerror(pico_err));
          exit(5);
        }
        if (tcpbench_time_start == 0)
          tcpbench_time_start = PICO_TIME_MS();
      } while(tcpbench_w > 0);
      printf("tcpbench_wr_size = %d      \r", tcpbench_wr_size);
    } else {
      if (!closed && tcpbench_mode == TCP_BENCH_TX) {
        tcpbench_time_end = PICO_TIME_MS();
        pico_socket_shutdown(s, PICO_SHUT_WR);
        printf("tcpbench> TCPSIZ written\n");
        printf("tcpbench> Called shutdown()\n");
        tcpbench_time = (tcpbench_time_end - tcpbench_time_start)/1000.0; /* get number of seconds */
        printf("tcpbench> Transmitted %u bytes in %lf seconds\n",TCPSIZ, tcpbench_time);
        printf("tcpbench> average write throughput %lf kbit/sec\n",((TCPSIZ*8.0)/tcpbench_time)/1000);
        closed = 1;
      }
    }
  }
}

void app_tcpbench(char *arg)
{
  struct pico_socket *s;
  char *dport;
  char *dest;
  char *mode;
  int port = 0, i;
  uint16_t port_be = 0;
  struct pico_ip4 server_addr;
  char *nxt;
  char *sport;

  nxt = cpy_arg(&mode, arg);

  if (*mode == 't') {   /* TEST BENCH SEND MODE */
    tcpbench_mode = TCP_BENCH_TX;    

    nxt = cpy_arg(&dest, nxt);
    if (!dest) {
      fprintf(stderr, "tcpbench send needs the following format: tcpbench:tx:dst_addr[:dport]\n");
      exit(255);
    }
    printf ("+++ Dest is %s\n", dest);
    if (nxt) {
      printf("Next arg: %s\n", nxt);
      nxt=cpy_arg(&dport, nxt);
      printf("Dport: %s\n", dport);
    }
    if (dport) {
      port = atoi(dport);
      port_be = short_be((uint16_t)port);
    }
    if (port == 0) {
      port_be = short_be(5555);
    }

    buffer0 = malloc(TCPSIZ);
    buffer1 = malloc(TCPSIZ);
    printf("Buffer1 (%p)\n", buffer1);
    for (i = 0; i < TCPSIZ; i++) {
      char c = (i % 26) + 'a';
      buffer0[i] = c;
    }
    memset(buffer1, 'a', TCPSIZ);
    printf("tcpbench> Connecting to: %s:%d\n", dest, short_be(port_be));

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpbench);
    if (!s)
      exit(1); 
    
    /* NOTE: used to set a fixed local port and address
    local_port = short_be(6666);
    pico_string_to_ipv4("10.40.0.11", &local_addr.addr);
    pico_socket_bind(s, &local_addr, &local_port);*/
    
    pico_string_to_ipv4(dest, &server_addr.addr);
    pico_socket_connect(s, &server_addr, port_be);

  } else if (*mode == 'r') {   /* TEST BENCH RECEIVE MODE */ 
    tcpbench_mode = TCP_BENCH_RX;    

    cpy_arg(&sport, arg);
    if (!sport) {
      fprintf(stderr, "tcpbench receive needs the following format: tcpbench:rx[:dport]\n");
      exit(255);
    }
    if (sport) {
      port = atoi(sport);
      port_be = short_be((uint16_t)port);
    }
    if (port == 0) {
      port_be = short_be(5555);
    }

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &cb_tcpbench);
    if (!s)
      exit(1);

    if (pico_socket_bind(s, &inaddr_any, &port_be)!= 0)
      exit(1);

    if (pico_socket_listen(s, 40) != 0)
      exit(1);

    printf("tcpbench> listening port %u ...\n",short_be(port_be));
  } else {
    printf("tcpbench> wrong mode argument\n");
    exit(1);
  }

  tcpbench_sock = s;


  return;
}



void app_natbox(char *arg)
{
  char *dest = NULL;
  struct pico_ip4 ipdst, pub_addr, priv_addr;
  struct pico_ipv4_link *link;

  cpy_arg(&dest, arg);
  if (!dest) {
    fprintf(stderr, "natbox needs the following format: natbox:dst_addr\n");
    exit(255);
  }
  pico_string_to_ipv4(dest, &ipdst.addr);
  link = pico_ipv4_link_get(&ipdst);
  if (!link) {
    fprintf(stderr, "natbox: Destination not found.\n");
    exit(255);
  }
  pico_ipv4_nat_enable(link);
  pico_string_to_ipv4("10.50.0.10", &pub_addr.addr);
  pico_string_to_ipv4("10.40.0.08", &priv_addr.addr);
  pico_ipv4_port_forward(pub_addr, short_be(5555), priv_addr, short_be(6667), PICO_PROTO_UDP, PICO_IPV4_FORWARD_ADD);
  fprintf(stderr, "natbox: started.\n");
}

#ifdef PICO_SUPPORT_PING
#define NUM_PING 10

void cb_ping(struct pico_icmp4_stats *s)
{
  char host[30];
  //int time_sec = 0;
  //int time_msec = 0;
  pico_ipv4_to_string(host, s->dst.addr);
  //time_sec = s->time / 1000;
  //time_msec = s->time % 1000;
  if (s->err == 0) {
    dbg("%lu bytes from %s: icmp_req=%lu ttl=%lu time=%lu ms\n", s->size, host, s->seq, s->ttl, s->time);
    if (s->seq >= NUM_PING)
      exit(0);
  } else {
    dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    exit(1);
  }
}

void app_ping(char *arg)
{
  char *dest = NULL;
  cpy_arg(&dest, arg);
  if (!dest) {
    fprintf(stderr, "ping needs the following format: ping:dst_addr\n");
    exit(255);
  }
  pico_icmp4_ping(dest, NUM_PING, 1000, 5000, 48, cb_ping);

}
#endif

/*** Multicast CLIENT ***/
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.2:255.255.0.0: -a mcastclient:224.7.7.7:10.40.0.2 */
void mcastclient_send(unsigned long now, void *arg) {
  int i, w;
  struct pico_socket *s = (struct pico_socket *)arg;
  char buf[30] = {0};
  char end[4] = "end";
  static int loop = 0;

  if (++loop > 3) {
    for (i = 0; i < 3; i++) {
      w = pico_socket_send(s, end, 4);
      if (w <= 0)
        break;
      printf("End!\n");
    }
    pico_timer_add(1000, deferred_exit, NULL);
    return;
  }

  sprintf(buf, "TESTING PACKET %d", loop);
  printf("\n---------- Sending %s\n", buf);
  w = pico_socket_send(s, buf, 30);

  pico_timer_add(1000, mcastclient_send, s);
}

void cb_mcastclient(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[30] = {0};
  char speer[16] = {0};
  int r = 0;
  uint32_t peer;
  uint16_t port;

  if (ev & PICO_SOCK_EV_RD) {
    //do {
      r = pico_socket_recvfrom(s, recvbuf, 30, &peer, &port);
    //} while(r>0);
    if (r > 0)
      pico_ipv4_to_string(speer, peer);
      printf(">>>>>>>>>> mcastclient: echo from %s -> %s\n", speer, recvbuf);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(7);
  }

}

void app_mcastclient(char *arg)
{
  struct pico_socket *s;
  char *daddr, *laddr, *dport;
  int port = 0;
  uint16_t port_be = 0;
  struct pico_ip4 inaddr_dst;
  struct pico_ip4 inaddr_link, inaddr_incorrect, inaddr_uni, inaddr_null;
  char *nxt;
#ifdef PICO_SUPPORT_MCAST
  struct pico_ip4 mcast_default_link = {0};
  uint8_t getttl = 0;
  uint8_t ttl = 64;
  uint8_t loop = 9;
  struct pico_ip_mreq mreq = {{0},{0}};
  uint8_t getloop = 0;
#endif

  nxt = cpy_arg(&daddr, arg);
  if (!daddr) {
    fprintf(stderr, " mcastclient expects the following format: mcastclient:dest_addr:link_addr[:dest_port]:\n");
    fprintf(stderr, " missing dest_addr\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&laddr, nxt);
    if (!laddr) {
      fprintf(stderr, " mcastclient expects the following format: mcastclient:dest_addr:link_addr[:dest_port]:\n");
      fprintf(stderr, " missing link_addr\n");
      exit(255);
    }
  } else {
    fprintf(stderr, " mcastclient expects the following format: mcastclient:dest_addr:link_addr[:dest_port]:\n");
    fprintf(stderr, " missing link_addr\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&dport, nxt);
    if (dport) {
      port = atoi(dport);
      if (port > 0)
        port_be = short_be(port);
    }
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  printf("Multicast client started. Sending packets to %s:%d\n", daddr, short_be(port_be));

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_mcastclient);
  if (!s)
    exit(1);

  pico_string_to_ipv4(daddr, &inaddr_dst.addr);
  pico_string_to_ipv4(laddr, &inaddr_link.addr);
  pico_string_to_ipv4("224.8.8.8", &inaddr_incorrect.addr);
  pico_string_to_ipv4("0.0.0.0", &inaddr_null.addr);
  pico_string_to_ipv4("10.40.0.9", &inaddr_uni.addr);

  if (pico_socket_bind(s, &inaddr_link, &port_be)!= 0)
    exit(1);

  if (pico_socket_connect(s, &inaddr_dst, port_be)!= 0)
    exit(1);

#ifdef PICO_SUPPORT_MCAST
  /* Start of pico_socket_setoption */
  printf("\n---------- Testing SET PICO_IP_MULTICAST_IF: not supported ----------\n");
  if(pico_socket_setoption(s, PICO_IP_MULTICAST_IF, &mcast_default_link) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_IF failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_IF succeeded\n");
    exit (10);
  }

  printf("\n---------- Testing GET PICO_IP_MULTICAST_IF: not supported ----------\n");
  if(pico_socket_getoption(s, PICO_IP_MULTICAST_IF, &mcast_default_link) < 0) {
    printf(">>>>>>>>>> socket_getoption PICO_IP_MULTICAST_IF failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_getoption PICO_IP_MULTICAST_IF succeeded\n");
    exit(11);
  }

  printf("\n---------- Testing SET PICO_IP_MULTICAST_TTL: ttl = %u ----------\n", ttl);
  if(pico_socket_setoption(s, PICO_IP_MULTICAST_TTL, &ttl) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_TTL failed with errno %d\n", pico_err);
    exit(12);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_TTL succeeded\n");
  }

  printf("\n---------- Testing GET PICO_IP_MULTICAST_TTL: expecting ttl = %u ----------\n", ttl);
  if(pico_socket_getoption(s, PICO_IP_MULTICAST_TTL, &getttl) < 0) {
    printf(">>>>>>>>>> socket_getoption PICO_IP_MULTICAST_TTL failed with errno %d\n", pico_err);
    exit(13);
  } else {
    printf(">>>>>>>>>> socket_getoption PICO_IP_MULTICAST_TTL succeeded: ttl = %u\n", getttl);
    if (getttl != ttl)
      exit(14);
  }

  printf("\n---------- Testing SET PICO_IP_MULTICAST_LOOP: loop = %u ----------\n", loop);
  if(pico_socket_setoption(s, PICO_IP_MULTICAST_LOOP, &loop) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_LOOP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_LOOP succeeded\n");
    exit(15);
  }

  loop = 0;
  printf("\n---------- Testing SET PICO_IP_MULTICAST_LOOP: loop = %u ----------\n", loop);
  if(pico_socket_setoption(s, PICO_IP_MULTICAST_LOOP, &loop) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_LOOP failed with errno %d\n", pico_err);
    exit(16);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_MULTICAST_LOOP succeeded\n");
  }

  printf("\n---------- Testing GET PICO_IP_NULTICAST_LOOP: expecting loop = %u ----------\n", loop);
  if(pico_socket_getoption(s, PICO_IP_MULTICAST_LOOP, &getloop) < 0) {
    printf(">>>>>>>>>> socket_getoption PICO_IP_MULTICAST_LOOP failed with errno %d\n", pico_err);
    exit(17);
  } else {
    printf(">>>>>>>>>> socket_getoption PICO_IP_MULTICAST_LOOP succeeded: loop = %u\n", getloop);
    if (getloop != loop)
      exit(18);
  }

  printf("\n---------- Testing PICO_IP_ADD_MEMBERSHIP: correct group and link address ----------\n");
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
    exit(19);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
  }

  printf("\n---------- Testing PICO_IP_ADD_MEMBERSHIP: unicast group address ----------\n");
  mreq.mcast_group_addr = inaddr_uni;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
    exit(20);
  }

  printf("\n---------- Testing PICO_IP_ADD_MEMBERSHIP: NULL group address ----------\n");
  mreq.mcast_group_addr = inaddr_null;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
    exit(21);
  }

  printf("\n---------- Testing PICO_IP_ADD_MEMBERSHIP: incorrect link address ----------\n");
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_uni;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
    exit(22);
  }

  printf("\n---------- Testing PICO_IP_ADD_MEMBERSHIP: NULL link address (use default link) ----------\n");
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_null;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
    exit(23);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
  }

  printf("\n---------- Testing PICO_IP_DROP_MEMBERSHIP: correct group and link address ----------\n");
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP failed with errno %d\n", pico_err);
    exit(24);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP succeeded\n");
  }

  printf("\n---------- Testing PICO_IP_DROP_MEMBERSHIP: incorrect group addresses ----------\n");
  mreq.mcast_group_addr = inaddr_incorrect;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP succeeded\n");
    exit(25);
  }

  printf("\n---------- Testing PICO_IP_DROP_MEMBERSHIP: unicast group address ----------\n");
  mreq.mcast_group_addr = inaddr_uni;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP succeeded\n");
    exit(26);
  }

  printf("\n---------- Testing PICO_IP_DROP_MEMBERSHIP: NULL group address ----------\n");
  mreq.mcast_group_addr = inaddr_null;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP succeeded\n");
    exit(27);
  }

  printf("\n---------- Testing PICO_IP_DROP_MEMBERSHIP: incorrect link address ----------\n");
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_uni;
  if(pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP failed with errno %d\n", pico_err);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP succeeded\n");
    exit(28);
  }

  printf("\n---------- Testing PICO_IP_DROP_MEMBERSHIP: NULL link address (use default link) ----------\n");
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_null;
  if(pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP failed with errno %d\n", pico_err);
    exit(29);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_DROP_MEMBERSHIP succeeded\n");
  }
  /* End of pico_socket_setoption */

  /* Testing multicast loopback */
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
    exit(30);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
  }
#endif /* PICO_SUPPORT_MCAST */

  pico_timer_add(1000, mcastclient_send, s);

}
/*** END Multicast CLIENT ***/

/*** Multicast RECEIVE + ECHO ***/
/* ./build/test/picoapp.elf --vde pic1:/tmp/pic0.ctl:10.40.0.3:255.255.0.0: -a mcastreceive:10.40.0.2:10.40.0.3:224.7.7.7 */
void cb_mcastreceive(uint16_t ev, struct pico_socket *s)
{
  char recvbuf[30] = {0};
  char speer[16] = {0};
  int r = 0;
  uint32_t peer;
  uint16_t port;
  static uint8_t is_end;

  if (ev & PICO_SOCK_EV_RD) {
    //do {
      r = pico_socket_recvfrom(s, recvbuf, 30, &peer, &port);
    //} while(r>0);
    if (strncmp(recvbuf, "end", 3) == 0) {
      if (!is_end) {
        is_end = 1;
        printf("Client requested to exit... test successful.\n");
        pico_timer_add(1000, deferred_exit, NULL);
      }
      return;
    }
    pico_ipv4_to_string(speer, peer);
    printf(">>>>>>>>>> mcastreceive: received from %s -> %s, send back to %s\n", speer, recvbuf, speer);
    pico_socket_sendto(s, recvbuf, r, &peer, port);
  }

  if (ev == PICO_SOCK_EV_ERR) {
    printf("Socket Error received. Bailing out.\n");
    exit(7);
  }

}

void app_mcastreceive(char *arg)
{
  struct pico_socket *s;
  char *daddr, *laddr, *maddr, *dport;
  int port = 0;
  uint16_t port_be = 0;
  struct pico_ip4 inaddr_dst;
  struct pico_ip4 inaddr_link, inaddr_mcast;
  struct pico_ip_mreq mreq = {{0},{0}};
  char *nxt;

  nxt = cpy_arg(&daddr, arg);
  if (!daddr) {
    fprintf(stderr, " mcastreceive expects the following format: mcastreceive:dest_addr:link_addr:mcast_addr[:dest_port]:\n");
    fprintf(stderr, " missing dest_addr\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&laddr, nxt);
    if (!laddr) {
      fprintf(stderr, " mcastreceive expects the following format: mcastreceive:dest_addr:link_addr:mcast_addr[:dest_port]:\n");
      fprintf(stderr, " missing link_addr\n");
      exit(255);
    }
  } else {
    fprintf(stderr, " mcastreceive expects the following format: mcastreceive:dest_addr:link_addr:mcast_addr[:dest_port]:\n");
    fprintf(stderr, " missing link_addr\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&maddr, nxt);
    if (!maddr) {
      fprintf(stderr, " mcastreceive expects the following format: mcastreceive:dest_addr:link_addr:mcast_addr[:dest_port]:\n");
      fprintf(stderr, " missing mcast_addr\n");
      exit(255);
    }
  } else {
    fprintf(stderr, " mcastreceive expects the following format: mcastreceive:dest_addr:link_addr:mcast_addr[:dest_port]:\n");
    fprintf(stderr, " missing mcast_addr\n");
    exit(255);
  }

  if (nxt) {
    nxt = cpy_arg(&dport, nxt);
    if (dport) {
      port = atoi(dport);
      if (port > 0)
        port_be = short_be(port);
    }
  }
  if (port == 0) {
    port_be = short_be(5555);
  }

  printf("Multicast receive started. Receiving packets from %s:%d, Echo packets to %s\n", maddr, short_be(port_be), daddr);

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &cb_mcastreceive);
  if (!s)
    exit(1);

  pico_string_to_ipv4(daddr, &inaddr_dst.addr);
  pico_string_to_ipv4(maddr, &inaddr_mcast.addr);
  pico_string_to_ipv4(laddr, &inaddr_link.addr);

  if (pico_socket_bind(s, &inaddr_link, &port_be)!= 0)
    exit(1);
  
  if (pico_socket_connect(s, &inaddr_dst, port_be)!= 0)
    exit(1);

  mreq.mcast_group_addr = inaddr_mcast;
  mreq.mcast_link_addr = inaddr_link;
  if(pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq) < 0) {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP failed with errno %d\n", pico_err);
    exit(2);
  } else {
    printf(">>>>>>>>>> socket_setoption PICO_IP_ADD_MEMBERSHIP succeeded\n");
  }
}
/*** END Multicast RECEIVE + ECHO ***/

#ifdef PICO_SUPPORT_DHCPD
/*** DHCP Server ***/
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.1:255.255.0.0: -a dhcpserver:pic0:10.40.0.1:255.255.255.0:64:128 
 * ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.255.0: \
 * -a dhcpserver:pic0:10.40.0.10:255.255.255.0:64:128:pic1:10.50.0.10:255.255.255.0:64:128
 */
void app_dhcp_server(char *arg)
{
  struct pico_device *dev = NULL;
  struct pico_dhcpd_settings s = {0};
  int pool_start = 0, pool_end = 0;
  char *s_name = NULL, *s_addr = NULL, *s_netm = NULL, *s_pool_start = NULL, *s_pool_end = NULL;
  char *nxt = arg;

  if (!nxt)
    goto out;

  while (nxt) {
    if (nxt) {
      nxt = cpy_arg(&s_name, nxt);
      if (!s_name) {
        goto out;
      }
    } else {
      goto out;
    }

    if (nxt) {
      nxt = cpy_arg(&s_addr, nxt);
      if (s_addr) {
        pico_string_to_ipv4(s_addr, &s.my_ip.addr);
      } else {
        goto out;
      }
    } else {
      goto out;
    }

    if (nxt) {
      nxt = cpy_arg(&s_netm, nxt);
      if (s_netm) {
        pico_string_to_ipv4(s_netm, &s.netmask.addr);
      } else {
        goto out;
      }
    } else {
      goto out;
    }

    if (nxt) {
      nxt = cpy_arg(&s_pool_start, nxt);
      if (s_pool_start && atoi(s_pool_start)) {
        pool_start = atoi(s_pool_start);
      } else {
        goto out;
      }
    } else {
      goto out;
    }

    if (nxt) {
      nxt = cpy_arg(&s_pool_end, nxt);
      if (s_pool_end && atoi(s_pool_end)) {
        pool_end = atoi(s_pool_end);
      } else {
        goto out;
      }
    } else {
      goto out;
    }

    dev = pico_get_device(s_name);
    if (dev == NULL) {
      fprintf(stderr, "No device with name %s found\n", s_name);
      exit(255);
    }
    s.dev = dev;
    s.pool_start = (s.my_ip.addr & s.netmask.addr) | long_be(pool_start);
    s.pool_end = (s.my_ip.addr & s.netmask.addr) | long_be(pool_end);

    pico_dhcp_server_initiate(&s);
  }
  return;

  out:
    fprintf(stderr, "dhcpserver expects the following format: dhcpserver:dev_name:dev_addr:dev_netm:pool_start:pool_end\n");
    exit(255);

}
#endif
/*** END DHCP Server ***/

/*** DHCP Client ***/
#ifdef PICO_SUPPORT_DHCPC
static void *dhcpclient_cli; 

void ping_callback_dhcpclient(struct pico_icmp4_stats *s)
{
  char host[30];
  pico_ipv4_to_string(host, s->dst.addr);
  if (s->err == 0) {
    dbg("DHCP client (id %p): %lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", 
          dhcpclient_cli, s->size, host, s->seq, s->time);
    if (s->seq >= 3) {
      dbg("DHCP client (id %p): TEST SUCCESS!\n", dhcpclient_cli);
      exit(0);
    }
  } else {
    dbg("DHCP client (id %p): ping %lu to %s error %d\n", dhcpclient_cli, s->seq, host, s->err);
    dbg("DHCP client (id %p): TEST FAILED!\n", dhcpclient_cli);
    exit(1);
  }
}

void callback_dhcpclient(void* cli, int code){
	struct pico_ip4  gateway;
	char gw_txt_addr[30];
	if(code == PICO_DHCP_SUCCESS){
		gateway = pico_dhcp_get_gateway(cli);
    pico_ipv4_to_string(gw_txt_addr, gateway.addr);
#ifdef PICO_SUPPORT_PING
    pico_icmp4_ping(gw_txt_addr, 3, 1000, 5000, 32, ping_callback_dhcpclient);
#endif
	}
	printf("DHCP client (id %p): callback happened with code %d!\n", dhcpclient_cli, code);
}

void app_dhcp_client(char* arg)
{
  struct pico_device *dev;
  char *dev_name;
  char *nxt = arg;

  if (nxt) {
    cpy_arg(&dev_name, arg);
    if(!dev_name){
      fprintf(stderr, " dhcp client expects as parameters : the name of the device\n");
      exit(255);
    }
  } else {

  }

  dev = pico_get_device(dev_name);
  if(dev == NULL){
    printf("error : no device found\n");
    exit(255);
  }
  printf("starting negotiation\n");

  dhcpclient_cli = pico_dhcp_initiate_negotiation(dev, &callback_dhcpclient);
}


static int finished1=0, finished2=0;
void ping_callback_dhcpclient1(struct pico_icmp4_stats *s)
{
  char host[30];
  pico_ipv4_to_string(host, s->dst.addr);
  if (s->err == 0) {
    dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
    if (s->seq >= 3) {
      dbg("DHCP CLIENT TEST: SUCCESS!\n\n\n");
			finished1 = 1;
			if(finished2 == 1)
				exit(0);
    }
  } else {
    dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    dbg("DHCP CLIENT TEST: FAILED!\n");
    exit(1);
  }
}

void ping_callback_dhcpclient2(struct pico_icmp4_stats *s)
{
  char host[30];
  pico_ipv4_to_string(host, s->dst.addr);
  if (s->err == 0) {
    dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
    if (s->seq >= 3) {
      dbg("DHCP CLIENT TEST: SUCCESS!\n\n\n");
			finished2 = 1;
			if(finished1 == 1)
				exit(0);
    }
  } else {
    dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    dbg("DHCP CLIENT TEST: FAILED!\n");
    exit(1);
  }
}
static void* dhcp_client_cookie1;
static void* dhcp_client_cookie2;
void callback_dhcpclient1(void* cli, int code){
	struct pico_ip4  gateway;
	char gw_txt_addr[30];
	if(code == PICO_DHCP_SUCCESS){
		gateway = pico_dhcp_get_gateway(dhcp_client_cookie1);
    pico_ipv4_to_string(gw_txt_addr, gateway.addr);
#ifdef PICO_SUPPORT_PING
    pico_icmp4_ping(gw_txt_addr, 3, 1000, 5000, 32, ping_callback_dhcpclient1);
#endif
	}
	printf("callback happened with code %d!\n", code);
}
void callback_dhcpclient2(void* cli, int code){
	struct pico_ip4  gateway;
	char gw_txt_addr[30];
	if(code == PICO_DHCP_SUCCESS){
		gateway = pico_dhcp_get_gateway(dhcp_client_cookie2);
    pico_ipv4_to_string(gw_txt_addr, gateway.addr);
#ifdef PICO_SUPPORT_PING
    pico_icmp4_ping(gw_txt_addr, 3, 1000, 5000, 32, ping_callback_dhcpclient2);
#endif
	}
	printf("callback happened with code %d!\n", code);
}

void app_dhcp_dual_client(char* arg)
{
	struct pico_device *dev1, *dev2;
	char *dev_name1, *dev_name2, *nxt;

	nxt = cpy_arg(&dev_name1, arg);
	if(!dev_name1){
		fprintf(stderr, " dhcp client expects as parameters : the names of the devices\n");
		exit(255);
	}
	if(!nxt){
		fprintf(stderr, " dhcp client expects as parameters : the names of the devices\n");
		exit(255);
	}
	cpy_arg(&dev_name2, nxt);
	if(!dev_name1){
		fprintf(stderr, " dhcp client expects as parameters : the names of the devices\n");
		exit(255);
	}

	dev1 = pico_get_device(dev_name1);
	dev2 = pico_get_device(dev_name2);
	free(dev_name1);
	free(dev_name2);
	if(dev1 == NULL){
		printf("error : no device found\n");
		exit(255);
	}
	if(dev2 == NULL){
		printf("error : no device found\n");
		exit(255);
	}
	printf("starting negotiation\n");

	dhcp_client_cookie1 = pico_dhcp_initiate_negotiation(dev1, &callback_dhcpclient1);
	dhcp_client_cookie2 = pico_dhcp_initiate_negotiation(dev2, &callback_dhcpclient2);
}


#endif
/*** END DHCP Client ***/

#ifdef PICO_SUPPORT_HTTP_CLIENT
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:192.168.24.15:255.255.255.0:192.168.24.5: -a wget:web.mit.edu/modiano/www/6.263/lec22-23.pdf
 */

static char *url_filename = NULL;

static int http_save_file(void *data, int len)
{
  int fd = open(url_filename, O_WRONLY |O_CREAT | O_TRUNC, 0660);
  int w, e;
  if (fd < 0)
    return fd;

  w = write(fd, data, len);
  e = errno;
  close(fd);
  errno = e;
  return w;
}
void wget_callback(uint16_t ev, uint16_t conn)
{
	char data[1024 * 1024]; // MAX: 1M
	static int _length = 0;


	if(ev & EV_HTTP_CON)
	{

		printf(">>> Connected to the client \n");
		pico_http_client_sendHeader(conn,NULL,HTTP_HEADER_DEFAULT);
	}

	if(ev & EV_HTTP_REQ)
	{
		struct pico_http_header * header = pico_http_client_readHeader(conn);
		printf("Received header from server...\n");
		printf("Server response : %d\n",header->responseCode);
		printf("Location : %s\n",header->location);
		printf("Transfer-Encoding : %d\n",header->transferCoding);
		printf("Size/Chunk : %d\n",header->contentLengthOrChunk);

		// sending default generated header
		pico_http_client_sendHeader(conn,NULL,HTTP_HEADER_DEFAULT);
	}

	if(ev & EV_HTTP_BODY)
	{
		int len;

		printf("Reading data...\n");
		while((len = pico_http_client_readData(conn,data + _length,1024)))
		{
			_length += len;
		}
	}


	if(ev & EV_HTTP_CLOSE)
	{
		struct pico_http_header * header = pico_http_client_readHeader(conn);
		int len;
		printf("Connection was closed...\n");
		printf("Reading remaining data, if any ...\n");
		while((len = pico_http_client_readData(conn,data,1000u)) && len > 0)
		{
			_length += len;
		}

		printf("Read a total data of : %d bytes \n",_length);

		if(header->transferCoding == HTTP_TRANSFER_CHUNKED)
		{
			if(header->contentLengthOrChunk)
			{
				printf("Last chunk data not fully read !\n");
				exit(1);
			}
			else
			{
				printf("Transfer ended with a zero chunk! OK !\n");
			}
		} else
		{
			if(header->contentLengthOrChunk == _length)
			{
				printf("Received the full : %d \n",_length);
			}
			else
			{
				printf("Received %d , waiting for %d\n",_length, header->contentLengthOrChunk);
				exit(1);
			}
		}

    if (!url_filename) {
      printf("Failed to get local filename\n");
      exit(1);
    }

    if (http_save_file(data, _length) < _length) {
      printf("Failed to save file: %s\n", strerror(errno));
      exit(1);
    }


		pico_http_client_close(conn);
		exit(0);
	}

	if(ev & EV_HTTP_ERROR)
	{
		printf("Connection error (probably dns failed : check the routing table), trying to close the client...\n");
		pico_http_client_close(conn);
		exit(1u);
	}

	if(ev & EV_HTTP_DNS)
	{
		printf("The DNS query was successful ... \n");
	}
}

void app_wget(char *arg)
{
	char * url;
	cpy_arg(&url, arg);

	if(!url)
	{
		fprintf(stderr, " wget expects the url to be received\n");
		exit(1);
	}

	if(pico_http_client_open(url,wget_callback) < 0)
	{
		fprintf(stderr," error opening the url : %s, please check the format\n",url);
		exit(1);
	}
  url_filename = basename(url);
}
#endif


#ifdef PICO_SUPPORT_HTTP_SERVER

#define SIZE 4*1024

void serverWakeup(uint16_t ev,uint16_t conn)
{
	static FILE * f;
	char buffer[SIZE];

	if(ev & EV_HTTP_CON)
	{
			printf("New connection received....\n");
			pico_http_server_accept();
	}

	if(ev & EV_HTTP_REQ) // new header received
	{
		int read;
		char * resource;
		printf("Header request was received...\n");
		printf("> Resource : %s\n",pico_http_getResource(conn));
		resource = pico_http_getResource(conn);

		if(strcmp(resource,"/")==0 || strcmp(resource,"index.html") == 0 || strcmp(resource,"/index.html") == 0)
		{
					// Accepting request
					printf("Accepted connection...\n");
					pico_http_respond(conn,HTTP_RESOURCE_FOUND);
					f = fopen("test/examples/index.html","r");

					if(!f)
					{
						fprintf(stderr,"Unable to open the file /test/examples/index.html\n");
						exit(1);
					}

					read = fread(buffer,1,SIZE,f);
					pico_http_submitData(conn,buffer,read);
		}
		else
		{ // reject
			printf("Rejected connection...\n");
			pico_http_respond(conn,HTTP_RESOURCE_NOT_FOUND);
		}

	}

	if(ev & EV_HTTP_PROGRESS) // submitted data was sent
	{
		uint16_t sent, total;
		pico_http_getProgress(conn,&sent,&total);
		printf("Chunk statistics : %d/%d sent\n",sent,total);
	}

	if(ev & EV_HTTP_SENT) // submitted data was fully sent
	{
		int read;
		read = fread(buffer,1,SIZE,f);
		printf("Chunk was sent...\n");
		if(read > 0)
		{
				printf("Sending another chunk...\n");
				pico_http_submitData(conn,buffer,read);
		}
		else
		{
				printf("Last chunk !\n");
				pico_http_submitData(conn,NULL,0);// send the final chunk
				fclose(f);
		}

	}

	if(ev & EV_HTTP_CLOSE)
	{
		printf("Close request...\n");
		pico_http_close(conn);
	}

	if(ev & EV_HTTP_ERROR)
	{
		printf("Error on server...\n");
		pico_http_close(conn);
	}
}

void app_httpd(char *arg)
{

	if( pico_http_server_start(0,serverWakeup) < 0)
	{
		fprintf(stderr,"Unable to start the server on port 80\n");
	}

}
#endif

/** From now on, parsing the command line **/

#define NXT_MAC(x) ++x[5]

/* Copy a string until the separator, 
terminate it and return the next index, 
or NULL if it encounters a EOS */
static char *cpy_arg(char **dst, char *str)
{
  char *p, *nxt = NULL;
  char *start = str;
  char *end = start + strlen(start);
  p = str;
  while (p) {
    if ((*p == ':') || (p == '\0')) {
      *p = (char)0;
      nxt = p + 1;
      if ((*nxt == 0) || (nxt >= end))
        nxt = 0;
      printf("dup'ing %s\n", start);
      *dst = strdup(start);
      break;
    }
    p++;
  }
  return nxt;
}

void __wakeup(uint16_t ev, struct pico_socket *s){}


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
  uint16_t *macaddr_low = (uint16_t *) (macaddr + 2);
  struct pico_device *dev = NULL;

  struct option long_options[] = {
    {"help",0 , 0, 'h'},
    {"vde",1 , 0, 'v'},
    {"barevde",1 , 0, 'b'},
    {"tun", 1, 0, 't'},
    {"route", 1, 0, 'r'},
    {"app", 1, 0, 'a'},
    {"loop", 0, 0, 'l'},
    {0,0,0,0}
  };
  int option_idx = 0;
  int c;

  *macaddr_low ^= getpid();
  printf("My macaddr base is: %02x %02x\n", macaddr[2], macaddr[3]);

  pico_stack_init();
  /* Parse args */
  while(1) {
    c = getopt_long(argc, argv, "v:b:t:a:r:hl", long_options, &option_idx);
    if (c < 0)
      break;
    switch(c) {
      case 'h':
        usage(argv[0]);
        break;
      case 't':
      {
        char *nxt, *name = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
        struct pico_ip4 ipaddr, netmask, gateway, zero = {};
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
          printf("Adding default route via %08x\n", gateway.addr);
          pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
        }
      }
      break;
    case 'v':
      {
        char *nxt, *name = NULL, *sock = NULL, *addr = NULL, *nm = NULL, *gw = NULL;
        struct pico_ip4 ipaddr, netmask, gateway, zero = {};
        printf("+++ OPTARG %s\n", optarg);
        do {
          nxt = cpy_arg(&name, optarg);
          if (!nxt) break;
          nxt = cpy_arg(&sock, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&addr, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&nm, nxt);
          if (!nxt) break;
          nxt = cpy_arg(&gw, nxt);
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
        printf("Vde created.\n");
        pico_string_to_ipv4(addr, &ipaddr.addr);
        pico_string_to_ipv4(nm, &netmask.addr);
        pico_ipv4_link_add(dev, ipaddr, netmask);
        if (gw && *gw) {
          pico_string_to_ipv4(gw, &gateway.addr);
          pico_ipv4_route_add(zero, zero, gateway, 1, NULL);
        }
      }
      break;
    case 'b':
      {
        char *nxt, *name = NULL, *sock = NULL;
        printf("+++ OPTARG %s\n", optarg);
        do {
          nxt = cpy_arg(&name, optarg);
          if (!nxt) break;
          nxt = cpy_arg(&sock, nxt);
        } while(0);
        if (!sock) {
          fprintf(stderr, "Vde: bad configuration...\n");
          exit(1);
        }
        dev = pico_vde_create(sock, name, macaddr);
        NXT_MAC(macaddr);
        if (!dev) {
          perror("Creating vde");
          exit(1);
        }
        printf("Vde created.\n");
      }
      break;
    case 'l':
      {
        struct pico_ip4 ipaddr, netmask;
        pico_string_to_ipv4("127.0.0.1", &ipaddr.addr);
        pico_string_to_ipv4("255.0.0.0", &netmask.addr);
        printf("Creating loopback device\n");
        dev = pico_loop_create();
        if (dev) {
          pico_ipv4_link_add(dev, ipaddr, netmask);
        }
      }
      break;
    case 'r':
      {
      char *nxt, *addr, *nm, *gw;
      struct pico_ip4 ipaddr, netmask, gateway;
      addr = NULL, nm = NULL, gw = NULL;
      printf("+++ ROUTEOPTARG %s\n", optarg);
      do {
        nxt = cpy_arg(&addr, optarg);
        if (!nxt) break;
        nxt = cpy_arg(&nm, nxt);
        if (!nxt) break;
        nxt = cpy_arg(&gw, nxt);
      } while(0);
      if (!addr || !nm || !gw) {
        fprintf(stderr, "--route expects addr:nm:gw:\n");
        usage(argv[0]);
      }
      pico_string_to_ipv4(addr, &ipaddr.addr);
      pico_string_to_ipv4(nm, &netmask.addr);
      pico_string_to_ipv4(gw, &gateway.addr);
      if (pico_ipv4_route_add(ipaddr, netmask, gateway, 1, NULL) == 0) 
        fprintf(stderr,"ROUTE ADDED *** to %s via %s\n", addr, gw);
      else
        fprintf(stderr,"ROUTE ADD: ERROR %s \n", strerror(pico_err));
      break;
      }
    case 'a':
      {
        char *name = NULL, *args = NULL;
        printf("+++ OPTARG %s\n", optarg);
        args = cpy_arg(&name, optarg);

        printf("+++ NAME: %s ARGS: %s\n", name, args);
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
        else IF_APPNAME("tcpbench") {
          app_tcpbench(args);
        }
        else IF_APPNAME("natbox") {
          app_natbox(args);
        }
        else IF_APPNAME("udpdnsclient") {
          app_udpdnsclient(args);
        }
        else IF_APPNAME("udpnatclient") {
          app_udpnatclient(args);
        }
        else IF_APPNAME("mcastclient") {
#ifndef PICO_SUPPORT_MCAST
          return 0;
#endif
          app_mcastclient(args);
        }
        else IF_APPNAME("mcastreceive") {
#ifndef PICO_SUPPORT_MCAST
          return 0;
#endif
          app_mcastreceive(args);
        }
#ifdef PICO_SUPPORT_PING
        else IF_APPNAME("ping") {
          app_ping(args);
        }
#endif
        else IF_APPNAME("dhcpserver") {
#ifndef PICO_SUPPORT_DHCPD
          return 0;
#else
          app_dhcp_server(args);
#endif
        }
        else IF_APPNAME("dhcpclient") {
#ifndef PICO_SUPPORT_DHCPC
          return 0;
#else
          app_dhcp_client(args);
#endif
        }
        else IF_APPNAME("dhcpdualclient") {
#ifndef PICO_SUPPORT_DHCPC
          return 0;
#else
          app_dhcp_dual_client(args);
#endif
        }
        else IF_APPNAME("wget")
	{
#ifndef PICO_SUPPORT_HTTP_CLIENT
       	  return 0;
#else
	  app_wget(args);
#endif
	}
        else IF_APPNAME("httpd")
	{
#ifndef PICO_SUPPORT_HTTP_SERVER
          return 0;
#else
	  app_httpd(args);
#endif
	}
				else IF_APPNAME("bcast")
	{
					struct pico_ip4 any = {.addr = 0xFFFFFFFFu};
					struct pico_socket * s = pico_socket_open(PICO_PROTO_IPV4,PICO_PROTO_UDP,&__wakeup);
					pico_socket_sendto(s,"abcd",5u,&any,1000);
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

  printf("%s: launching PicoTCP loop\n", __FUNCTION__);
  while(1) {
    pico_stack_tick();
    usleep(2000);
  }
}
