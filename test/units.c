/* PicoTCP unit test platform */
/* How does it works: 
 * 1. Define your unit test function as described in the check manual
 * 2. Add your test to the suite in the pico_suite() function
 */

#include "pico_device.c"
#include "pico_frame.c"
#include "pico_stack.c"
#include "pico_protocol.c"
#include "pico_ipv4.c"
#include "pico_socket.c"
#include "pico_dev_null.c"
#include "pico_dev_mock.c"
#include "pico_udp.c"
#include "pico_tcp.c"
#include "pico_arp.c"
#include "pico_icmp4.c"
#include "pico_dhcp_common.c"
#include "pico_dns_client.c"
#include "pico_dhcp_server.c"
#include "pico_dhcp_client.c"
#include "pico_igmp2.c"
#include "pico_nat.c"
#include <check.h>

START_TEST (test_ipv4)
{
  #define IP_TST_SIZ 256
  int i;

  struct pico_device *dev[IP_TST_SIZ];
  char devname[8]; 
  struct pico_ip4 a[IP_TST_SIZ], d[IP_TST_SIZ], *source[IP_TST_SIZ], nm16, nm32, gw[IP_TST_SIZ], r[IP_TST_SIZ], ret;
  struct pico_ipv4_link *l[IP_TST_SIZ];

  char ipstr[] = "192.168.1.1";
  struct pico_ip4 ipaddr;

  struct pico_frame *f_NULL = NULL;
  struct pico_ip4 *dst_NULL = NULL;

  pico_stack_init();

  nm16.addr = long_be(0xFFFF0000);
  nm32.addr = long_be(0xFFFFFFFF);

  /*link_add*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    snprintf(devname, 8, "nul%d", i);
    dev[i] = pico_null_create(devname);
    a[i].addr = long_be(0x0a000001 + (i << 16));
    d[i].addr = long_be(0x0a000002 + (i << 16));
    fail_if(pico_ipv4_link_add(dev[i], a[i], nm16) != 0, "Error adding link");
  }

  /*link_find + link_get + route_add*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    gw[i].addr = long_be(0x0a0000f0 + (i << 16));
    r[i].addr = long_be(0x0c00001 + (i << 16));
    fail_unless(pico_ipv4_link_find(&a[i]) == dev[i], "Error finding link");
    l[i] = pico_ipv4_link_get(&a[i]);
    fail_if(l[i] == NULL, "Error getting link");
    fail_if(pico_ipv4_route_add(r[i], nm32, gw[i], 1, l[i]) != 0, "Error adding route");
    fail_if(pico_ipv4_route_add(d[i], nm32, gw[i], 1, l[i]) != 0, "Error adding route");
  }

  /*get_gateway + source_find*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    ret = pico_ipv4_route_get_gateway(&r[i]);
    fail_if(ret.addr != gw[i].addr, "Error get gateway: returned wrong route");
    source[i] = pico_ipv4_source_find(&d[i]);
    fail_if(source[i]->addr != a[i].addr, "Error find source: returned wrong route");
  }

  /*route_del + link_del*/
  for (i = 0; i < IP_TST_SIZ; i++) {
    fail_if(pico_ipv4_route_del(r[i], nm32, gw[i], 1, l[i]) != 0, "Error deleting route");
    fail_if(pico_ipv4_link_del(dev[i], a[i]) != 0, "Error deleting link");
  }

  /*string_to_ipv4 + ipv4_to_string*/
  pico_string_to_ipv4(ipstr, &(ipaddr.addr));
  fail_if(ipaddr.addr != 0x0101a8c0, "Error string to ipv4");
  memset(ipstr, 0, 12);
  pico_ipv4_to_string(ipstr, ipaddr.addr);
  fail_if(strncmp(ipstr, "192.168.1.1", 11) != 0, "Error ipv4 to string");

  /*valid_netmask*/
  fail_if(pico_ipv4_valid_netmask(long_be(nm32.addr)) != 32, "Error checking netmask");

  /*is_unicast*/
  fail_if((pico_ipv4_is_unicast(0x0101a8c0)) != 1, "Error checking unicast");
  fail_if((pico_ipv4_is_unicast(0x010000e0)) != 0, "Error checking unicast");

  /*rebound*/
  fail_if(pico_ipv4_rebound(f_NULL) != -1, "Error rebound frame");

  /*frame_push*/
  fail_if(pico_ipv4_frame_push(f_NULL, dst_NULL, PICO_PROTO_TCP) != -1, "Error push frame");
}
END_TEST


#include "pico_icmp4.h"
#define NUM_PING 1
int ping_test_var = 0;

void cb_ping(struct pico_icmp4_stats *s)
{
  char host[30];
  pico_ipv4_to_string(host, s->dst.addr);
  if (s->err == 0) {
    dbg("%lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host, s->seq, s->time);
		if (s->seq == NUM_PING){
			ping_test_var++;
		}
		fail_if (s->seq > NUM_PING);
  } else {
    dbg("PING %lu to %s: Error %d\n", s->seq, host, s->err);
    exit(1);
  }
}

START_TEST (test_icmp4_ping)
{
  struct pico_ip4 local={0};
  struct pico_ip4 remote={0};
  struct pico_ip4 netmask={0};
  struct mock_device *mock=NULL;
  char local_address[]={"192.168.1.102"};
  char remote_address[]={"192.168.1.103"};
  uint16_t interval = 1000;
  uint16_t timeout  = 5000;
  uint8_t size  = 48;

	int bufferlen = 80;
	uint8_t buffer[bufferlen];
	int len;
	uint8_t temp_buf[4];
	printf("*********************** starting %s * \n", __func__);

  pico_string_to_ipv4(local_address,&(local.addr));
  pico_string_to_ipv4("255.255.255.0",&(netmask.addr));

  pico_string_to_ipv4(remote_address,&(remote.addr));
  pico_string_to_ipv4("255.255.255.0",&(netmask.addr));

  pico_stack_init();

  mock = pico_mock_create(NULL);
  fail_if(mock == NULL, "No device created");

  pico_ipv4_link_add(mock->dev, local, netmask);

  fail_if(pico_icmp4_ping(local_address, NUM_PING, interval, timeout, size, cb_ping));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	fail_if(ping_test_var != 1);

  pico_icmp4_ping(remote_address, NUM_PING, interval, timeout, size, cb_ping);
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	//get the packet from the mock_device
	memset(buffer, 0, bufferlen);
	len = pico_mock_network_read(mock, buffer, bufferlen);
	//inspect it
	fail_unless(mock_ip_protocol(mock, buffer, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer, len) == 8);
	fail_unless(mock_icmp_code(mock, buffer, len) == 0);
	fail_unless(pico_checksum(buffer+20, len-20) == 0);

	//cobble up a reply
	buffer[20] = 0; // type 0 : reply
	memcpy(temp_buf, buffer+12, 4);
	memcpy(buffer+12, buffer+16, 4);
	memcpy(buffer+16, temp_buf, 4);

	//using the mock-device because otherwise I have to put everything in a pico_frame correctly myself.
	pico_mock_network_write(mock, buffer, len);
	//check if it is received
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	fail_unless(ping_test_var == 2);

	//repeat but make it an invalid reply...

  pico_icmp4_ping(remote_address, NUM_PING, interval, timeout, size, cb_ping);
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	//get the packet from the mock_device
	memset(buffer, 0, bufferlen);
	len = pico_mock_network_read(mock, buffer, bufferlen);
	//inspect it
	fail_unless(mock_ip_protocol(mock, buffer, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer, len) == 8);
	fail_unless(mock_icmp_code(mock, buffer, len) == 0);
	fail_unless(pico_checksum(buffer+20, len-20) == 0);

	//cobble up a reply
	buffer[20] = 0; // type 0 : reply
	memcpy(temp_buf, buffer+12, 4);
	memcpy(buffer+12, buffer+16, 4);
	memcpy(buffer+16, temp_buf, 4);
	buffer[26] = ~buffer[26]; // flip some bits in the sequence number, to see if the packet gets ignored properly

	//using the mock-device because otherwise I have to put everything in a pico_frame correctly myself.
	pico_mock_network_write(mock, buffer, len);
	//check if it is received
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	fail_unless(ping_test_var == 2);
}
END_TEST


START_TEST (test_icmp4_incoming_ping)
{
	int bufferlen = 76;
	uint8_t buffer[76] = { 0x45, 0x00, 0x00, 0x4c, 
													0x91, 0xc3, 0x40, 0x00, 
													0x40, 0x01, 0x24, 0xd0, 
													0xc0, 0xa8, 0x01, 0x64, 
													0xc0, 0xa8, 0x01, 0x66, 
													0x00, 0x00, 0x66, 0x3c, 
													0x91, 0xc2, 0x01, 0x01, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00, 
													0x00, 0x00, 0x00, 0x00};
	int buffer2len = 76;
	int len;
	uint8_t buffer2[bufferlen];
  struct pico_ip4 local={.addr = long_be(0xc0a80164)};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
	struct mock_device* mock;
	printf("*********************** starting %s * \n", __func__);

  pico_stack_init();

  mock = pico_mock_create(NULL);
  fail_if(mock == NULL, "No device created");

  pico_ipv4_link_add(mock->dev, local, netmask);


	pico_mock_network_write(mock, buffer, bufferlen);
	//check if it is received
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();


	len = pico_mock_network_read(mock, buffer2, buffer2len);
	//inspect it

	int cntr = 0;
	while(cntr < len){
		printf("0x%02x ",buffer2[cntr]);
		cntr++;
		if(cntr %4 == 0)
			printf("\n");
	}

	fail_unless(len == buffer2len, "ping reply lenght does not match, expected len: %d, got: %d", buffer2len, len);
	fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer2, len) == 0);
	fail_unless(mock_icmp_code(mock, buffer2, len) == 0);
	fail_unless(pico_checksum(buffer2+20, len-20) == 0);

}
END_TEST

START_TEST (test_icmp4_unreachable_send)
{
  struct pico_ip4 local={.addr = long_be(0x0a280064)};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
	struct mock_device* mock;
	int len=0;
	int bufferlen = 80;
	uint8_t buffer2[bufferlen];

	uint8_t buffer[32] = {0x45, 0x00, 0x00, 0x20,  0x91, 0xc0, 0x40, 0x00,  
												 0x40, 0x11, 0x94, 0xb4,  0x0a, 0x28, 0x00, 0x05,  
												 0x0a, 0x28, 0x00, 0x04,  0x15, 0xb3, 0x15, 0xb3,  
												 0x00, 0x0c, 0x00, 0x00,  'e', 'l', 'l', 'o'};

	struct pico_frame* f = pico_zalloc(sizeof(struct pico_frame));
	printf("*********************** starting %s * \n", __func__);

	f->net_hdr = buffer;
	f->buffer = buffer;

  pico_stack_init();

  mock = pico_mock_create(NULL);
  fail_if(mock == NULL, "No device created");

  pico_ipv4_link_add(mock->dev, local, netmask);


	fail_if(pico_icmp4_dest_unreachable(f));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	len = pico_mock_network_read(mock, buffer2, bufferlen);

	fail_unless(len == 56);
	fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer2, len) == 3);//destination unreachable
	fail_unless(mock_icmp_code(mock, buffer2, len) == 1);//host unreachable
	fail_unless(pico_checksum(buffer2+20, len-20) == 0);


	fail_if(pico_icmp4_port_unreachable(f));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	len = pico_mock_network_read(mock, buffer2, bufferlen);

	fail_unless(len == 56);
	fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer2, len) == 3);//destination unreachable
	fail_unless(mock_icmp_code(mock, buffer2, len) == 3);//port unreachable
	fail_unless(pico_checksum(buffer2+20, len-20) == 0);


	fail_if(pico_icmp4_proto_unreachable(f));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	len = pico_mock_network_read(mock, buffer2, bufferlen);

	fail_unless(len == 56);
	fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer2, len) == 3);//destination unreachable
	fail_unless(mock_icmp_code(mock, buffer2, len) == 2);//proto unreachable
	fail_unless(pico_checksum(buffer2+20, len-20) == 0);


	fail_if(pico_icmp4_ttl_expired(f));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	len = pico_mock_network_read(mock, buffer2, bufferlen);

	fail_unless(len == 56);
	fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer2, len) == 11);//ttl expired
	fail_unless(mock_icmp_code(mock, buffer2, len) == 0);
	fail_unless(pico_checksum(buffer2+20, len-20) == 0);



	//fake packet with bad upper-layer-protocol
	uint8_t buffer3[20] = {0x45, 0x00, 0x00, 0x14,  0x91, 0xc0, 0x40, 0x00,  
												 0x40, 0xff, 0x94, 0xb4,  0x0a, 0x28, 0x00, 0x05,  
												 0x0a, 0x28, 0x00, 0x04 };

	f->net_hdr = buffer3;
	f->buffer = buffer3;

	fail_if(pico_icmp4_proto_unreachable(f));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();

	len = pico_mock_network_read(mock, buffer2, bufferlen);

	fail_unless(len == 56);
	fail_unless(mock_ip_protocol(mock, buffer2, len) == 1);
	fail_unless(mock_icmp_type(mock, buffer2, len) == 3);//destination unreachable
	fail_unless(mock_icmp_code(mock, buffer2, len) == 2);//proto unreachable
	fail_unless(pico_checksum(buffer2+20, len-20) == 0);

	uint8_t nullbuf[8] = {0,0,0,0,0,0,0};
	fail_if(memcmp(buffer+48, nullbuf , 8)); // there was no data, assuming that the 64 bits of payload should then be zeroed out. Otherwise you're either reading uninitialized memory, or you're leaking stack data.
}
END_TEST

int icmp4_socket_unreach_status = 0;
void icmp4_unreach_socket_cb(uint16_t ev, struct pico_socket *s)
{
	if (ev == PICO_SOCK_EV_ERR){
		icmp4_socket_unreach_status=1;
	}
}

START_TEST (test_icmp4_unreachable_recv)
{
  struct pico_ip4 local={.addr = long_be(0x0a280064)};
  struct pico_ip4 remote={.addr = long_be(0x0a280065)};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
	struct mock_device* mock;
	struct pico_socket* sock;
	uint16_t port = short_be(7777);

	printf("*********************** starting %s * \n", __func__);
  pico_stack_init();

  mock = pico_mock_create(NULL);
  fail_if(mock == NULL, "No device created");

  pico_ipv4_link_add(mock->dev, local, netmask);

	//open a socket
	sock = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, &icmp4_unreach_socket_cb);
	fail_if(sock == NULL);
	fail_if(pico_socket_bind(sock, &local, &port));
	pico_socket_connect(sock, &remote, port);
	pico_socket_write(sock, "fooo", 4);
	//put a host unreachable in the queue, run a few stack ticks
	uint8_t buffer[] = {0x45, 0x00, 0x00, 0x20,
											0x91, 0xc0, 0x40, 0x00,
											0x40, 0x01, 0x94, 0xb4,
											0x0a, 0x28, 0x00, 0x65,
											0x0a, 0x28, 0x00, 0x64,
											0x03, 0x01, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,

											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
											0x00, 0x00, 0x00, 0x00,
	};
	//see if my callback was called with the proper code
	
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	//filling in the IP header and first 8 bytes
	printf("read %d bytes\n",pico_mock_network_read(mock, buffer+28, 28));
	
	printf("wrote %d bytes\n", pico_mock_network_write(mock, buffer, 56));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	fail_unless(icmp4_socket_unreach_status == 1);
}
END_TEST


START_TEST (test_dhcp)
{
	struct pico_device* dev;
	struct pico_dhcpd_settings s = {0};
	struct pico_ip4 address = {.addr=long_be(0x0a280001)};
	struct pico_ip4 netmask = {.addr=long_be(0xffffff00)};

	pico_stack_init();
	dev = pico_null_create("null");
	pico_ipv4_link_add(dev, address, netmask);

	s.dev = dev;

	fail_if(pico_dhcp_server_initiate(&s));
}
END_TEST



void cb_dns(char *ip)
{
  if (!ip) {
    /* Error occured */
    printf("DNS error getaddr\n");
    return;
  }
  /* Do something */
  printf("DNS -> %s\n",ip);
  pico_free(ip);
}


START_TEST (test_dns)
{
  int ret;
  char url[] = "www.google.com";
  char ip[]  = "8.8.4.4";
  struct pico_ip4 ns;

  ns.addr = long_be(0x0a00280a);  // 10.40.0.10

  pico_stack_init();

  printf("START DNS TEST\n");

  /* testing nameserver API */
  ret = pico_dns_client_nameserver(NULL,PICO_DNS_NS_ADD);
  fail_if(ret == 0, "dns> dns_client_nameserver add error");

  ret = pico_dns_client_nameserver(NULL,PICO_DNS_NS_DEL);
  fail_if(ret == 0, "dns> dns_client_nameserver del error");

  ret = pico_dns_client_nameserver(NULL,99);
  fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

  ret = pico_dns_client_nameserver(NULL,-99);
  fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

  ret = pico_dns_client_nameserver(&ns,PICO_DNS_NS_DEL);  /* delete non added ns */
  fail_if(ret == 0, "dns> dns_client_nameserver del error");

  ret = pico_dns_client_nameserver(&ns,99);
  fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

  ret = pico_dns_client_nameserver(&ns,PICO_DNS_NS_ADD);  /* add correct one */
  fail_if(ret < 0, "dns> dns_client_nameserver add error: %s",strerror(pico_err));

  ret = pico_dns_client_nameserver(&ns,99);
  fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

  ret = pico_dns_client_nameserver(&ns,PICO_DNS_NS_DEL);
  fail_if(ret < 0, "dns> dns_client_nameserver del error: %s",strerror(pico_err));

  ret = pico_dns_client_nameserver(&ns,PICO_DNS_NS_ADD);  /* add correct one */
  fail_if(ret < 0, "dns> dns_client_nameserver add error: %s",strerror(pico_err));

  ret = pico_dns_client_nameserver(&ns,PICO_DNS_NS_ADD);  /* add correct one again */
  fail_if(ret == 0, "dns> dns_client_nameserver add double");

  /* testing getaddr API */
  ret = pico_dns_client_getaddr(url,cb_dns); /* ask correct one */
  fail_if(ret < 0, "dns> dns_client_getaddr: %s",strerror(pico_err));

  ret = pico_dns_client_getaddr(NULL,cb_dns);
  fail_if(ret == 0, "dns> dns_client_getaddr: no url");
  
  ret = pico_dns_client_getaddr(url,NULL);
  fail_if(ret == 0, "dns> dns_client_getaddr: no cb");

  /* testing getname API */
  ret = pico_dns_client_getname(ip,cb_dns); /* ask correct one */
  fail_if(ret < 0, "dns> dns_client_getname: %s",strerror(pico_err));

  ret = pico_dns_client_getname(NULL,cb_dns);
  fail_if(ret == 0, "dns> dns_client_getname: no ip");

  ret = pico_dns_client_getname(ip,NULL);
  fail_if(ret == 0, "dns> dns_client_getname: no cb");
}
END_TEST


/* RB tree unit test */
struct rbtree_element {
  int value;
  RB_ENTRY(rbtree_element) node;
};

RB_HEAD(rbtree, rbtree_element);

static struct rbtree RBTREE;

int rbtree_compare(struct rbtree_element *a, struct rbtree_element *b)
{
  return a->value - b->value;
}
RB_GENERATE(rbtree, rbtree_element, node, rbtree_compare);
RB_PROTOTYPE(rbtree, rbtree_element, node, rbtree_compare);

#define RBTEST_SIZE 400000

START_TEST (test_rbtree)
{
  struct rbtree_element *e, *s, t;
  int i;
  struct timeval start, end;
  gettimeofday(&start, 0);
  for (i = 0; i < (RBTEST_SIZE >> 1); i++) {
    e = malloc(sizeof(struct rbtree_element));
    fail_if(!e, "Out of memory");
    e->value = i;
    RB_INSERT(rbtree, &RBTREE, e);
    e = malloc(sizeof(struct rbtree_element));
    fail_if(!e, "Out of memory");
    e->value = (RBTEST_SIZE - 1) - i;
    RB_INSERT(rbtree, &RBTREE, e);
  }

  i = 0;
  RB_FOREACH(s, rbtree, &RBTREE) {
    fail_if (i++ != s->value);
  }

  t.value = RBTEST_SIZE >> 2;
  s = RB_FIND(rbtree, &RBTREE, &t);
  fail_if(!s, "Search failed...");
  fail_if(s->value != t.value, "Wrong element returned...");

  RB_FOREACH_REVERSE_SAFE(e, rbtree, &RBTREE, s) {
    fail_if(!e, "Reverse safe returned null");
    RB_REMOVE(rbtree, &RBTREE, e);
    free(e);
  }
  fail_if(!RB_EMPTY(&RBTREE), "Not empty");
  gettimeofday(&end, 0);

  printf("Rbtree test duration with %d entries: %lu milliseconds\n", RBTEST_SIZE, 
    (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) /1000);
}
END_TEST

void callback_dhcpclient(void* cli, int code){
  struct pico_ip4  gateway;
  char gw_txt_addr[30];
  if(code == PICO_DHCP_SUCCESS){
    gateway = pico_dhcp_get_gateway(&dhcp_client);
    pico_ipv4_to_string(gw_txt_addr, gateway.addr);
  }
  printf("callback happened with code %d!\n", code);
}
int printbuf(uint8_t *buf, uint32_t len, char *str, uint8_t printbufactive){
  uint8_t printMethod =0;
  uint32_t cntr = 0;
  uint32_t cntr2 = 0;

  if((printbufactive)&&(printMethod== 0)){
    printf("\n%s:\n",str);
    for(cntr =0;cntr<len;cntr++){
      if((cntr %8) == 0 && cntr !=0)
        printf(" ");
      if((cntr % 16) == 0 && cntr != 0)
        printf("\n");
      if((cntr % 16) == 0)
        printf("%03x0  ",cntr2++);
      printf("%02x ",buf[cntr]);
    }
    printf("\n");
  }else if((printbufactive)&&(printMethod== 1)){
    printf("Buf = {");
    for(cntr =0;cntr<len;cntr++){
      if(cntr !=0)
        printf(",");
      printf("0x%02x",buf[cntr]);
    }
    printf("}\n");
  }
  return 0;
}
int tick_it(uint32_t nticks){
  uint32_t i = 0;
  for (i=0;i<nticks;i++) {
    pico_stack_tick();
  }
  return 0;
}
int mock_print_protocol(uint8_t *buf){
  uint8_t pnr = buf[0x17];// protocol number

  printf("transport protocol: %s\n",
   (pnr == PICO_PROTO_ICMP4 ? "icmp4" :
   (pnr == PICO_PROTO_IGMP2 ? "igmp2" :
   (pnr == PICO_PROTO_TCP   ? "tcp" :
   (pnr == PICO_PROTO_UDP   ? "udp" :
   (pnr == PICO_PROTO_ICMP6 ? "icmp6": 
   "unknown proto")))))); 
   return 0;
}
#define BUFLEN (576+14+20+8) 
START_TEST (test_dhcp_client)
{
  struct mock_device* mock;
  uint32_t dhcp_hdr_offset = PICO_SIZE_ETHHDR+PICO_SIZE_IP4HDR+PICO_UDPHDR_SIZE;
  unsigned char macaddr1[6] = {0xc1,0,0,0xa,0xb,0xf};
  struct pico_ip4 address = {0};
  struct pico_ip4 yiaddr = {.addr = long_be(0xC0A8000A)};
  struct pico_ip4 gateway = {0};
  struct pico_ip4 router = {.addr = long_be(0xC0A800FE)};
  uint8_t buf[BUFLEN] = {0}; 
  uint8_t offer_buf1[]={0x00,0x00,0x00,0x00,0xC0,0xA8,0x00,0x01};
  uint8_t offer_buf2[] = {0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x02, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x3a, 0x04, 0x00, 0x00, 0x07, 0x08, 0x3b, 0x04, 0x00, 0x00, 0x0c, 0x4e, 0x33, 0x04, 0x00, 0x00, 0x0e, 0x10, 0x36, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0xff}; 
  uint8_t routeropt_buf[]={PICO_DHCPOPT_ROUTER,0x04,0xC0,0xA8,0x00,0xFE,0xFF};
  int type = 0;
  uint8_t printbufactive = 0;
  uint32_t len = 0;
  struct pico_dhcp_client_cookie *cli = NULL;

  pico_stack_init();

  /* Create mock device  */
  mock = pico_mock_create(macaddr1);
	fail_if(!mock,"MOCK DEVICE creation failed");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");

  // initiate negotiation -> change state to  
	cli = pico_dhcp_initiate_negotiation(mock->dev, &callback_dhcpclient);
	fail_if(cli == NULL,"initiate fail");
  fail_unless(cli->state == DHCPSTATE_DISCOVER,"Not in discover state after init negotiate");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");
  
  /* push discover msg on network */
  tick_it(3);

  /* read discover message from network */
  len = pico_mock_network_read(mock, buf,BUFLEN );
  fail_unless(len,"No msg received on network!");
  printbuf(&(buf[0]),len,"DHCP-DISCOVER packet",printbufactive);
  mock_print_protocol(buf);
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");
  
  /* check API access functions */
  address = pico_dhcp_get_address(cli);
  fail_unless(address.addr == 0,"Client address gets value at init -> should get it from dhcp server"); 

  gateway = pico_dhcp_get_gateway(cli);
  fail_unless(gateway.addr == 0,"Gateway gets value at init -> should get it from dhcp server "); 

  // Change received discovery msg to offer offer msg
  buf[0x2a]=0x02;
  memcpy(&(buf[0x3a]),&(offer_buf1[0]),sizeof(offer_buf1)); 
  memcpy(&(buf[0x3a]),&(yiaddr.addr),sizeof(struct pico_ip4));
  memcpy(&(buf[0x116]),&(offer_buf2[0]),sizeof(offer_buf2));
  memcpy(&(buf[0x13b]),&(routeropt_buf[0]),sizeof(routeropt_buf));
  memcpy(&(buf[0x13d]),&(router.addr),sizeof(struct pico_ip4));
  printbuf(&(buf[dhcp_hdr_offset]),len-dhcp_hdr_offset,"DHCP-OFFER message",printbufactive);

  /* generate dhcp type from msg */ 
  type = pico_dhcp_verify_and_identify_type(&(buf[dhcp_hdr_offset]), len-dhcp_hdr_offset, cli);
  fail_if(type ==0, "unkown DHCP type");

  /* simulate reception of a DHCP server offer */
  pico_dhcp_state_machine(type, cli, &(buf[dhcp_hdr_offset]), len-dhcp_hdr_offset);
  fail_if(cli->state == DHCPSTATE_DISCOVER ,"still in discover state after dhcp server offer");
  fail_unless(cli->state == DHCPSTATE_REQUEST,"not in REQUEST state after dhcp server offer");

  address = pico_dhcp_get_address(cli);
  fail_unless(address.addr == yiaddr.addr,"Client address incorrect => yiaddr or pico_dhcp_get_address incorrect"); 
  gateway = pico_dhcp_get_gateway(cli);
  fail_unless(gateway.addr == router.addr,"Gateway incorrect! => routeroption or pico_dhcp_get_gateway incorrect"); 
  tick_it(3);

  len = pico_mock_network_read(mock, buf, BUFLEN);
  fail_unless(len,"received msg on network of %d bytes",len);
  printbuf(&(buf[0]),len,"DHCP-REQUEST packet",printbufactive);
  
}
END_TEST
START_TEST (test_socket)
{
  int ret = 0;
  uint16_t port_be = 0;
  struct pico_socket *sk_tcp, *sk_udp;
  struct pico_device *dev;
  struct pico_ip4 inaddr_dst, inaddr_link, inaddr_incorrect, inaddr_uni, inaddr_null, netmask;

  pico_stack_init();
    
  pico_string_to_ipv4("224.7.7.7", &inaddr_dst.addr);
  pico_string_to_ipv4("10.40.0.2", &inaddr_link.addr);
  pico_string_to_ipv4("224.8.8.8", &inaddr_incorrect.addr);
  pico_string_to_ipv4("0.0.0.0", &inaddr_null.addr);
  pico_string_to_ipv4("10.40.0.3", &inaddr_uni.addr);

  dev = pico_null_create("dummy");
  netmask.addr = long_be(0xFFFF0000);
  ret = pico_ipv4_link_add(dev, inaddr_link, netmask); 
  fail_if(ret < 0, "socket> error adding link");

  sk_tcp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, NULL);
  fail_if(sk_tcp == NULL, "socket> tcp socket open failed");
  port_be = short_be(5555);
  ret = pico_socket_bind(sk_tcp, &inaddr_link, &port_be);
  fail_if(ret < 0, "socket> tcp socket bind failed");

  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
  fail_if(sk_udp == NULL, "socket> udp socket open failed");
  port_be = short_be(5555);
  ret = pico_socket_bind(sk_udp, &inaddr_link, &port_be);
  fail_if(ret < 0, "socket> udp socket bind failed");

  /*
  if (pico_socket_connect(s, &inaddr_dst, port_be)!= 0)
    exit(1);
  */

  printf("START SOCKET TEST\n");

  uint8_t getnodelay = -1;
  ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
  fail_if(getnodelay != 1, "socket> socket_setoption: default PICO_TCP_NODELAY != 1\n");

  uint8_t nodelay = -1;
  ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_TCP_NODELAY failed\n");

  ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
  fail_if(getnodelay != 0, "socket> socket_setoption: PICO_TCP_NODELAY != 0\n");

  struct pico_ip4 mcast_default_link = {0};
  ret = pico_socket_setoption(sk_udp, PICO_IP_MULTICAST_IF, &mcast_default_link);
  fail_if(ret == 0, "socket> socket_setoption: unsupported PICO_IP_MULTICAST_IF succeeded\n");

  ret = pico_socket_getoption(sk_udp, PICO_IP_MULTICAST_IF, &mcast_default_link);
  fail_if(ret == 0, "socket> socket_getoption: unsupported PICO_IP_MULTICAST_IF succeeded\n");

  uint8_t ttl = 64;
  ret = pico_socket_setoption(sk_udp, PICO_IP_MULTICAST_TTL, &ttl);
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_IP_MULTICAST_TTL failed\n");

  uint8_t getttl = 0;
  ret = pico_socket_getoption(sk_udp, PICO_IP_MULTICAST_TTL, &getttl);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_IP_MULTICAST_TTL failed\n");
  fail_if(getttl != ttl, "socket> socket_getoption: setoption ttl != getoption ttl\n");

  uint8_t loop = 9;
  ret = pico_socket_setoption(sk_udp, PICO_IP_MULTICAST_LOOP, &loop);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_MULTICAST_LOOP succeeded with invalid (not 0 or 1) loop value\n");

  loop = 0;
  ret = pico_socket_setoption(sk_udp, PICO_IP_MULTICAST_LOOP, &loop);
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_IP_MULTICAST_LOOP failed\n");

  uint8_t getloop = 0;
  ret = pico_socket_getoption(sk_udp, PICO_IP_MULTICAST_LOOP, &getloop);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_IP_MULTICAST_LOOP failed\n");
  fail_if(getloop != loop, "socket> socket_getoption: setoption loop != getoption loop\n");

  struct pico_ip_mreq mreq = {{0},{0}};
  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_ADD_MEMBERSHIP, &mreq); 
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_IP_ADD_MEMBERSHIP failed\n");

  mreq.mcast_group_addr = inaddr_uni;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_ADD_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_ADD_MEMBERSHIP succeeded with invalid (unicast) group address\n");

  mreq.mcast_group_addr = inaddr_null;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_ADD_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_ADD_MEMBERSHIP succeeded with invalid (NULL) group address\n");

  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_uni;
  ret = pico_socket_setoption(sk_udp, PICO_IP_ADD_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_ADD_MEMBERSHIP succeeded with invalid link address\n");

  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_null;
  ret = pico_socket_setoption(sk_udp, PICO_IP_ADD_MEMBERSHIP, &mreq);
  fail_if(ret < 0, "socket> socket_setoption: PICO_IP_ADD_MEMBERSHIP failed with valid NULL (use default) link address\n");

  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_DROP_MEMBERSHIP, &mreq);
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_IP_DROP_MEMBERSHIP failed\n");

  mreq.mcast_group_addr = inaddr_incorrect;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_DROP_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_DROP_MEMBERSHIP succeeded with invalid (not added) group address\n");

  mreq.mcast_group_addr = inaddr_uni;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_DROP_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_DROP_MEMBERSHIP succeeded with invalid (unicast) group address\n");

  mreq.mcast_group_addr = inaddr_null;
  mreq.mcast_link_addr = inaddr_link;
  ret = pico_socket_setoption(sk_udp, PICO_IP_DROP_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_DROP_MEMBERSHIP succeeded with invalid (NULL) group address\n");

  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_uni;
  ret = pico_socket_setoption(sk_udp, PICO_IP_DROP_MEMBERSHIP, &mreq);
  fail_if(ret == 0, "socket> socket_setoption: PICO_IP_DROP_MEMBERSHIP succeeded with invalid (unicast) link address\n");

  mreq.mcast_group_addr = inaddr_dst;
  mreq.mcast_link_addr = inaddr_null;
  ret = pico_socket_setoption(sk_udp, PICO_IP_DROP_MEMBERSHIP, &mreq);
  fail_if(ret < 0, "socket> socket_setoption: PICO_IP_DROP_MEMBERSHIP failed with valid NULL (use default) link address\n");

  ret = pico_socket_close(sk_tcp);
  fail_if(ret < 0, "socket> tcp socket close failed: %s\n", strerror(pico_err));
  ret = pico_socket_close(sk_udp);
  fail_if(ret < 0, "socket> udp socket close failed: %s\n", strerror(pico_err));
}
END_TEST

Suite *pico_suite(void)
{
  Suite *s = suite_create("PicoTCP");

  TCase *ipv4 = tcase_create("IPv4");
  tcase_add_test(ipv4, test_ipv4);
  suite_add_tcase(s, ipv4);

  TCase *icmp = tcase_create("ICMP4");
  tcase_add_test(icmp, test_icmp4_ping);
  tcase_add_test(icmp, test_icmp4_incoming_ping);
  tcase_add_test(icmp, test_icmp4_unreachable_send);
  tcase_add_test(icmp, test_icmp4_unreachable_recv);
  suite_add_tcase(s, icmp);

  TCase *dhcp = tcase_create("DHCP");
  tcase_add_test(dhcp, test_dhcp);
  tcase_add_test(dhcp, test_dhcp_client);
  suite_add_tcase(s, dhcp);

  TCase *dns = tcase_create("DNS");
  tcase_add_test(dns, test_dns);
  suite_add_tcase(s, dns);

  TCase *rb = tcase_create("RB TREE");
  tcase_add_test(rb, test_rbtree);
  suite_add_tcase(s, rb);

  TCase *socket = tcase_create("SOCKET");
  tcase_add_test(socket, test_socket);
  suite_add_tcase(s, socket);

  return s;
}




int main(void) {
  int fails;
  Suite *s = pico_suite();
  SRunner *sr = srunner_create(s);
  srunner_run_all(sr, CK_NORMAL);
  fails = srunner_ntests_failed(sr);
  srunner_free(sr);
  return fails;
}
