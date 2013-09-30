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
#include "pico_nat.c"
#include "pico_ipfilter.c"
#include "pico_tree.c"
#include <check.h>

#ifdef PICO_SUPPORT_MCAST
#include "pico_igmp.c"
#endif

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
    fail_if(pico_ipv4_route_del(r[i], nm32, 1) != 0, "Error deleting route");
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

START_TEST (test_nat_enable_disable)
{
	struct pico_ipv4_link link = {.address = {.addr = long_be(0x0a320001)}}; /* 10.50.0.1 */
	struct pico_frame *f = pico_ipv4_alloc(&pico_proto_ipv4, PICO_UDPHDR_SIZE);
  struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
  struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
  char *raw_data = "ello";
  
  net->vhl = 0x45; /* version = 4, hdr len = 5 (32-bit words) */
  net->tos = 0;
  net->len = short_be(32); /* hdr + data (bytes) */
  net->id = short_be(0x91c0);
  net->frag = short_be(0x4000); /* don't fragment flag, offset = 0 */
  net->ttl = 64;
  net->proto = 17; /* UDP */
  net->crc = 0;
  net->crc = pico_ipv4_checksum(f);
  net->src.addr = long_be(0x0a280008); /* 10.40.0.8 */
  net->dst.addr = long_be(0x0a320001); /* 10.50.0.1 */

  udp->trans.sport = short_be(5555);
  udp->trans.dport = short_be(6667);
  udp->len = 12;
  udp->crc = 0;

  f->payload = f->transport_hdr + PICO_UDPHDR_SIZE;
  memcpy(f->payload, raw_data, 4);

  printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> NAT ENABLE/DISABLE TEST\n");
	pico_stack_init();

	fail_if(pico_ipv4_nat_enable(&link));
	fail_unless(nat_link->address.addr == link.address.addr);
	fail_unless(pico_ipv4_nat_is_enabled(&link.address));

	fail_if(pico_ipv4_nat_outbound(f, &net->dst));

	fail_if(pico_ipv4_nat_disable());
	fail_if(pico_ipv4_nat_is_enabled(&link.address));
}
END_TEST

START_TEST (test_nat_translation)
{
	struct pico_ipv4_link link = {.address = {.addr = long_be(0x0a320001)}}; /* 10.50.0.1 */
	struct pico_frame *f = pico_ipv4_alloc(&pico_proto_ipv4, PICO_UDPHDR_SIZE);
  struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
  struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
  struct pico_ip4 src_ori = {.addr = long_be(0x0a280008) }; /* 10.40.0.8 */
  struct pico_ip4 dst_ori = {.addr = long_be(0x0a320009) }; /* 10.50.0.9 */
  struct pico_ip4 nat = {.addr = long_be(0x0a320001) }; /* 10.50.0.9 */
  char *raw_data = "ello";
  uint16_t sport_ori = short_be(5555);
  uint16_t dport_ori = short_be(6667);
  uint16_t nat_port = 0;
  
  net->vhl = 0x45; /* version = 4, hdr len = 5 (32-bit words) */
  net->tos = 0;
  net->len = short_be(32); /* hdr + data (bytes) */
  net->id = short_be(0x91c0);
  net->frag = short_be(0x4000); /* don't fragment flag, offset = 0 */
  net->ttl = 64;
  net->proto = 17; /* UDP */
  net->crc = 0;
  net->crc = pico_ipv4_checksum(f);
  net->src = src_ori;
  net->dst = dst_ori;

  udp->trans.sport = sport_ori;
  udp->trans.dport = dport_ori;
  udp->len = 12;
  udp->crc = 0;

  f->payload = f->transport_hdr + PICO_UDPHDR_SIZE;
  memcpy(f->payload, raw_data, 4);

  printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> NAT TRANSLATION TEST\n");
	pico_stack_init();
	fail_if(pico_ipv4_nat_enable(&link));
  
  /* perform outbound translation, check if source IP got translated */
	fail_if(pico_ipv4_nat_outbound(f, &nat_link->address));
	fail_if(net->src.addr != link.address.addr, "source address not translated");

  /* perform outbound translation of same packet, check if source IP and PORT got translated the same as previous packet */
  nat_port = udp->trans.sport;
  net->src = src_ori; /* restore original src */
  udp->trans.sport = sport_ori; /* restore original sport */
	fail_if(pico_ipv4_nat_outbound(f, &nat_link->address));
	fail_if(net->src.addr != link.address.addr, "source address not translated");
	fail_if(udp->trans.sport != nat_port, "frames with the same source IP, source PORT and PROTO did not get translated the same");

  /* perform outbound translation of packet with changed source PORT, check if source PORT got translated differently as previous packet */
  nat_port = udp->trans.sport;
  net->src = src_ori; /* restore original src */
  udp->trans.sport = short_be(5556); /* change sport */
	fail_if(pico_ipv4_nat_outbound(f, &nat_link->address));
	fail_if(net->src.addr != link.address.addr, "source address not translated");
	fail_if(udp->trans.sport == short_be(sport_ori), "two frames with different sport get translated the same");

  /* perform inbound translation of previous packet, check if destination IP and PORT got translated to the original source IP and PORT */
  nat_port = udp->trans.sport;
  net->src = dst_ori;
  net->dst = nat;
  udp->trans.sport = sport_ori;
  udp->trans.dport = nat_port;
	fail_if(pico_ipv4_nat_inbound(f, &nat_link->address));
	fail_if(net->dst.addr != src_ori.addr, "destination address not translated correctly");
	fail_if(udp->trans.dport != short_be(5556), "ports not translated correctly");

	fail_if(pico_ipv4_nat_disable());
}
END_TEST

START_TEST (test_nat_port_forwarding)
{
	struct pico_ipv4_link link = {.address = {.addr = long_be(0x0a320001)}}; /* 10.50.0.1 */
	struct pico_frame *f = pico_ipv4_alloc(&pico_proto_ipv4, PICO_UDPHDR_SIZE);
  struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
  struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
  struct pico_ip4 src_addr = {.addr = long_be(0x0a280008) }; /* 10.40.0.8 */
  struct pico_ip4 dst_addr = {.addr = long_be(0x0a320009) }; /* 10.50.0.9 */
  struct pico_ip4 nat_addr = {.addr = long_be(0x0a320001) }; /* 10.50.0.9 */
  char *raw_data = "ello";
  uint16_t sport_ori = short_be(5555);
  uint16_t fport_pub = short_be(80);
  uint16_t fport_priv = short_be(8080);
  
  net->vhl = 0x45; /* version = 4, hdr len = 5 (32-bit words) */
  net->tos = 0;
  net->len = short_be(32); /* hdr + data (bytes) */
  net->id = short_be(0x91c0);
  net->frag = short_be(0x4000); /* don't fragment flag, offset = 0 */
  net->ttl = 64;
  net->proto = 17; /* UDP */
  net->crc = 0;
  net->crc = pico_ipv4_checksum(f);
  net->src = dst_addr;
  net->dst = nat_addr;

  udp->trans.sport = sport_ori;
  udp->trans.dport = fport_pub;
  udp->len = 12;
  udp->crc = 0;

  f->payload = f->transport_hdr + PICO_UDPHDR_SIZE;
  memcpy(f->payload, raw_data, 4);

  printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> NAT PORT FORWARD TEST\n");
	pico_stack_init();
	fail_if(pico_ipv4_nat_enable(&link));

	fail_if(pico_ipv4_port_forward(nat_addr, fport_pub, src_addr, fport_priv, 17, PICO_NAT_PORT_FORWARD_ADD));

	fail_if(pico_ipv4_nat_inbound(f, &nat_link->address));
	fail_if(net->dst.addr != src_addr.addr, "destination address not translated correctly");
	fail_if(udp->trans.dport != fport_priv, "destination port not translated correctly");

	fail_if(pico_ipv4_port_forward(nat_addr, fport_pub, src_addr, fport_priv, 17, PICO_NAT_PORT_FORWARD_DEL));
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
													0xc0, 0xa8, 0x01, 0x66, 
													0xc0, 0xa8, 0x01, 0x64, 
													0x08, 0x00, 0x66, 0x3c, 
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
	int cntr = 0;
	uint8_t buffer2[bufferlen];
  struct pico_ip4 local={.addr = long_be(0xc0a80164)};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
	struct mock_device* mock;
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) buffer;
	printf("*********************** starting %s * \n", __func__);

  pico_stack_init();

  mock = pico_mock_create(NULL);
  fail_if(mock == NULL, "No device created");

  pico_ipv4_link_add(mock->dev, local, netmask);

  hdr->crc = 0;
  hdr->crc = short_be(pico_checksum(hdr, PICO_SIZE_IP4HDR));
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

	//fake packet with bad upper-layer-protocol
	uint8_t buffer3[20] = {0x45, 0x00, 0x00, 0x14,  0x91, 0xc0, 0x40, 0x00,  
												 0x40, 0xff, 0x94, 0xb4,  0x0a, 0x28, 0x00, 0x05,  
												 0x0a, 0x28, 0x00, 0x04 };

	struct pico_frame* f = pico_zalloc(sizeof(struct pico_frame));
	uint8_t nullbuf[8] = {};
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

	fail_if(memcmp(buffer+48, nullbuf , 8)==0); // there was no data 
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
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) buffer;

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
	//see if my callback was called with the proper code
	
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	//filling in the IP header and first 8 bytes
  hdr->crc = 0;
  hdr->crc = short_be(pico_checksum(hdr, PICO_SIZE_IP4HDR));
	printf("read %d bytes\n",pico_mock_network_read(mock, buffer+28, 28));
	
	printf("wrote %d bytes\n", pico_mock_network_write(mock, buffer, 56));
	pico_stack_tick();
	pico_stack_tick();
	pico_stack_tick();
	fail_unless(icmp4_socket_unreach_status == 1);
}
END_TEST



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
    printf("\n%s:\n",str);
    printf("Buf = {");
    for(cntr =0;cntr<len;cntr++){
      if(cntr !=0)
        printf(",");
      if((cntr%16==0)&&(cntr!=0))
        printf("\n");
      printf("0x%02x",buf[cntr]);
    }
    printf("}\n");
  }
  return 0;
}

#define BUFLEN (576+14+20+8)
#define DHCP_MSG_TYPE_DISCOVER (1)
#define DHCP_MSG_TYPE_OFFER    (2)
#define DHCP_MSG_TYPE_REQUEST  (3)
#define DHCP_MSG_TYPE_ACK      (4)
int tick_it(uint32_t nticks){
  uint32_t i = 0;
  for (i=0;i<nticks;i++) {
    pico_stack_tick();
  }
  return 0;
}

int generate_dhcp_msg(uint8_t *buf, uint32_t *len, uint8_t type){
  if(type == DHCP_MSG_TYPE_DISCOVER){ 
    uint8_t buffer[]={
    0x01,0x01,0x06,0x00,0x0c,0x10,
    0x53,0xe6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xc1,0x00,0x00,0x0a,0x0b,0x0f,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x63,0x82,0x53,0x63,0x35,0x01,0x01,0x37,0x07,0x01,
    0x1c,0x02,0x03,0x0c,0x3a,0x3b,0x39,0x02,0x02,0x40,0xff,0x00};
    *len=sizeof(buffer);
    memcpy(&(buf[0]),buffer,*len);
  }else if(type == DHCP_MSG_TYPE_OFFER){ 
     return 1;
  }else if(type == DHCP_MSG_TYPE_REQUEST){ 
    int i = 0;
    uint8_t buffer1[]={
    //0x63,0x82,0x53,0x63,// MAGIC COOCKIE
    // 0x35,0x01,0x03,     // DHCP REQUEST
    // 0x36,0x04,0x00,0x00,0x00,0x00 // SERVER ID
    0x32,0x04,buf[0x3a],buf[0x3b],buf[0x3c],buf[0x3e],//requested ip
    0x37,0x04,0x01,0x03,0x06,0x2a, // Parameter list
    0x3d,0x07,0x01,buf[0x06],buf[0x07],buf[0x08],buf[0x09],buf[0x0a],buf[0x0b],//Client id
    0xff};

    buf[0x02a]=0x01;// change to boot request 
    buf[0x11c]=0x03;// request 

    memcpy(&(buf[0x123]),&(buffer1[0]),sizeof(buffer1));
    *len = sizeof(buffer1) + 0x123; 
    for(i=*len;i<0x150;i++){
      buf[i+10]=0x00;
    }
     return 0;
  }else if(type ==DHCP_MSG_TYPE_ACK){ 
     return 1;
  }
    return 0; 
}
 
START_TEST (test_dhcp_server_api)
{
/************************************************************************
* Check if dhcp recv works correctly if
*     MAC address of client is not in arp table yet
* Status : Done
************************************************************************/

  struct mock_device *mock;
  uint8_t macaddr1[6] = {0xc1,0,0,0xa,0xb,0xf};
  struct pico_ip4 netmask = {.addr = long_be(0xffffff00)};
  struct pico_ip4 serverip = {.addr = long_be(0x0A28000A)};
  uint8_t buf[600] = {0};
  /* Declaration test 1 */ 
  struct pico_dhcp_server_setting s1 = {0};
  /* Declaration test 2 */ 
  struct pico_dhcp_server_setting s2 = {0};

	printf("*********************** starting %s * \n", __func__);

  /* Create mock device  */
  mock = pico_mock_create(macaddr1);
  fail_if(!mock,"MOCK DEVICE creation failed");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");
  fail_if(pico_ipv4_link_add(mock->dev, serverip , netmask),"add link to mock device failed");

  /* test 0 */ 
  /* Clear error code */
  pico_err = PICO_ERR_NOERR;
  /* Test 0 statements */
  fail_unless(pico_dhcp_server_initiate(NULL),"DHCP_SERVER> initiate succeeded after pointer to dev == NULL");
  fail_unless(pico_err == PICO_ERR_EINVAL,"DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");
 
  /* test 1 */ 
  /* Clear error code */
  pico_err = PICO_ERR_NOERR;
  /* Store data in settings */
  s1.server_ip.addr = long_be(0x0A28000F); /* make sure this IP is not assigned */
  /* Test 1 statements */
  fail_unless(pico_dhcp_server_initiate(&s1),"DHCP_SERVER> initiate succeeded after pointer to dev == NULL");
  fail_unless(pico_err == PICO_ERR_EINVAL,"DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");

  /* test 2 */ 
  /* Clear error code */
  pico_err = PICO_ERR_NOERR;
  /* Store data in settings */
  s2.server_ip = serverip;
  /* Test 2 statements */
  fail_if(pico_dhcp_server_initiate(&s2),"DHCP_SERVER> failed after correct parameter");
}
END_TEST
 
START_TEST (test_dhcp)
{
/************************************************************************
* Check if all states (offer, bound) are changed correctly 
*   and if response messages are replied correctly 
* Status : Done 
*************************************************************************/
  struct mock_device* mock;
  struct pico_dhcp_server_setting s = {0};
  struct pico_ip4 xid = {.addr=long_be(0x00003d1d)};
  uint8_t macaddr1[6] = {0xc1,0,0,0xa,0xb,0xf};
  uint8_t macaddr2[6] = {0xc6,0,0,0xa,0xb,0xf};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
  struct pico_ip4 serverip={.addr = long_be(0x0A28000A)};
  struct pico_socket sock = { };
  struct pico_dhcp_server_negotiation *dn = NULL;
  struct pico_ip4 *stored_ipv4=NULL;
  uint32_t len = 0;
  uint8_t buf[600]={0};
  uint8_t printbufactive = 0;

	printf("*********************** starting %s * \n", __func__);

  /*Insert custom values in buffer*/
  fail_if(generate_dhcp_msg(buf,&len,DHCP_MSG_TYPE_DISCOVER),"DHCP_SERVER->failed to generate buffer");
  memcpy(&(buf[4]),&(xid.addr),sizeof(struct pico_ip4));
  memcpy(&(buf[28]),&(macaddr1[0]),sizeof(struct pico_ip4));
  printbuf(&(buf[0]),len,"DHCP-DISCOVER packet",printbufactive);

  /*Initiate test setup*/
  pico_stack_init();

  /* Create mock device  */
  mock = pico_mock_create(macaddr2);
  fail_if(!mock,"MOCK DEVICE creation failed");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");
  fail_if(pico_ipv4_link_add(mock->dev, serverip , netmask),"add link to mock device failed");

  s.server_ip = serverip;

  fail_if(pico_dhcp_server_initiate(&s),"DHCP_SERVER> server initiation failed");

  dn = pico_dhcp_server_find_negotiation(xid.addr);
  fail_unless(dn==NULL,"DCHP SERVER -> negotiation data available befor discover msg recvd");

  /* simulate reception of a DISCOVER packet */
  sock.local_addr.ip4 = serverip;
  pico_dhcp_server_recv(&sock, buf, len);

  tick_it(3);

  /* check if negotiation data is stored */
  dn = pico_dhcp_server_find_negotiation(xid.addr);
  fail_if(dn==NULL,"DCHP SERVER -> no negotiation stored after discover msg recvd");

  /* check if new ip is in ARP cache */
  stored_ipv4 = pico_arp_reverse_lookup(&dn->hwaddr);
  fail_if(stored_ipv4 == NULL,"DCHP SERVER -> new address is not inserted in ARP");
  fail_unless(stored_ipv4->addr== dn->ciaddr.addr,"DCHP SERVER -> new ip not stored in negotiation data");

  /* check if state is changed and reply is received  */
  len = pico_mock_network_read(mock, buf, BUFLEN);
  fail_unless(len,"received msg on network of %d bytes",len);
  printbuf(&(buf[0]),len,"DHCP-OFFER msg",printbufactive);
  fail_unless(buf[0x011c]==0x02,"No DHCP offer received after discovery");
  fail_unless(dn->state == PICO_DHCP_STATE_OFFER,"DCHP SERVER -> negotiation state not changed to OFFER");
  
  /*change offer to request*/
  fail_if(generate_dhcp_msg(buf,&len,DHCP_MSG_TYPE_REQUEST),"DHCP_SERVER->failed to generate buffer");
  printbuf(&(buf[0x2a]) , len-0x2a , "request buffer",printbufactive);

  /* simulate reception of a offer packet */
  pico_dhcp_server_recv(&sock, &(buf[0x2a]) , len-0x2a);
  fail_unless(dn->state == PICO_DHCP_STATE_BOUND,"DCHP SERVER -> negotiation state not changed to BOUND");

  tick_it(3);

  /* check if state is changed and reply is received  */
  len = pico_mock_network_read(mock, buf, BUFLEN);
  fail_unless(len,"received msg on network of %d bytes",len);
  fail_unless(len,"received msg on network of %d bytes",len);
  printbuf(&(buf[0]),len,"DHCP-ACK msg",printbufactive);
  fail_unless(buf[0x11c]==0x05,"No DHCP ACK received after discovery");
}
END_TEST


START_TEST (test_dhcp_server_ipninarp)
{
/************************************************************************
* Check if dhcp recv works correctly if
*     MAC address of client is not in arp table yet
* Status : Done
*************************************************************************/
  struct mock_device* mock;
  struct pico_dhcp_server_setting s = {0};
  struct pico_ip4 xid = {.addr=long_be(0x00003d1d)};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
  struct pico_ip4 serverip={.addr = long_be(0x0A28000A)};
  struct pico_socket sock = { };
  struct pico_dhcp_server_negotiation *dn = NULL;
  struct pico_ip4 *stored_ipv4=NULL;
  unsigned char macaddr1[6] = {0xc1,0,0,0xa,0xb,0xf};
  uint32_t len = 0;
  uint8_t buf[600]={0};
  uint8_t printbufactive = 0;

	printf("*********************** starting %s * \n", __func__);

  /*Insert custom values in buffer*/
  fail_if(generate_dhcp_msg(buf,&len,DHCP_MSG_TYPE_DISCOVER),"DHCP_SERVER->failed to generate buffer");
  memcpy(&(buf[4]),&(xid.addr),sizeof(struct pico_ip4));
  memcpy(&(buf[28]),&(macaddr1[0]),sizeof(struct pico_ip4));
  printbuf(&(buf[0]),len,"DHCP-DISCOVER packet",printbufactive);
    
  /*Initiate test setup*/
  pico_stack_init();
  
  /* Create mock device  */
  mock = pico_mock_create(macaddr1);
  fail_if(!mock,"MOCK DEVICE creation failed");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");
  fail_if(pico_ipv4_link_add(mock->dev, serverip , netmask),"add link to mock device failed");
  s.server_ip = serverip; 
    
  fail_if(pico_dhcp_server_initiate(&s),"DHCP_SERVER> server initiation failed");
      
  dn = pico_dhcp_server_find_negotiation(xid.addr);
  fail_unless(dn==NULL,"DCHP SERVER -> negotiation data available before discover msg recvd");

  /* simulate reception of a DISCOVER packet */
  sock.local_addr.ip4 = serverip;
  pico_dhcp_server_recv(&sock, buf, len);
  
  /* check if negotiation data is stored */
  dn = pico_dhcp_server_find_negotiation(xid.addr);
  fail_if(dn==NULL,"DCHP SERVER -> no negotiation stored after discover msg recvd");

  /* check if new ip is in ARP cache */
  stored_ipv4 = pico_arp_reverse_lookup(&dn->hwaddr);
  fail_if(stored_ipv4 == NULL,"DCHP SERVER -> new address is not inserted in ARP");
  fail_unless(stored_ipv4->addr== dn->ciaddr.addr,"DCHP SERVER -> new ip not stored in negotiation data");
  
  /* check if new ip is in ARP cache */
  fail_if(pico_arp_reverse_lookup(&dn->hwaddr)== NULL,"DCHP SERVER -> new address is not inserted in ARP");
} 
END_TEST

START_TEST (test_dhcp_server_ipinarp)
{
/************************************************************************
* Check if dhcp recv works correctly if
*     MAC address of client is allready in arp table
* Status : Done
*************************************************************************/
  struct mock_device* mock;
  struct pico_dhcp_server_setting s = {0};
  struct pico_ip4 ipv4address ={.addr = long_be(0x0a280067)};
  struct pico_ip4 xid = {.addr=long_be(0x00003d1d)};
  struct pico_ip4 netmask={.addr = long_be(0xffffff00)};
  struct pico_ip4 serverip={.addr = long_be(0x0A28000A)};
  struct pico_socket sock = { };
  struct pico_ip4 *stored_ipv4=NULL;
  struct pico_dhcp_server_negotiation *dn = NULL;
  struct pico_eth *arp_resp=NULL;
  unsigned char macaddr1[6] = {0xc1,0,0,0xa,0xb,0xf};
  uint32_t len = 0;
  uint8_t buf[600]={0};

	printf("*********************** starting %s * \n", __func__);

  /*Insert custom values in buffer*/
  fail_if(generate_dhcp_msg(buf,&len,DHCP_MSG_TYPE_DISCOVER),"DHCP_SERVER->failed to generate buffer");
  memcpy(&(buf[28]),&(macaddr1[0]),sizeof(struct pico_ip4));
  memcpy(&(buf[4]),&(xid.addr),sizeof(struct pico_ip4));

  /* Create mock device  */
  mock = pico_mock_create(macaddr1);
  fail_if(!mock,"MOCK DEVICE creation failed");
  fail_if(pico_ipv4_link_add(mock->dev, serverip , netmask),"add link to mock device failed");
  s.server_ip = serverip;

  /*Initiate test setup*/
  pico_stack_init();
  pico_arp_create_entry(&(macaddr1[0]),ipv4address , s.dev);

  fail_if(pico_dhcp_server_initiate(&s),"DHCP_SERVER> server initiation failed");

  /* simulate reception of a DISCOVER packet */
  sock.local_addr.ip4 = serverip;
  pico_dhcp_server_recv(&sock, buf, len);

  /* check if negotiation data is stored */
  dn = pico_dhcp_server_find_negotiation(xid.addr);
  fail_if(dn==NULL,"DCHP SERVER -> no negotiation stored after discover msg recvd");

  /* check if new ip is in ARP cache */
  stored_ipv4 = pico_arp_reverse_lookup(&dn->hwaddr);
  fail_if(stored_ipv4 == NULL,"DCHP SERVER -> new address is not inserted in ARP");
  fail_unless(stored_ipv4->addr== dn->ciaddr.addr,"DCHP SERVER -> new ip not stored in negotiation data");

  /* check if new ip is in ARP cache */
  arp_resp = pico_arp_lookup(&ipv4address);
  fail_if(arp_resp==NULL,"DCHP SERVER -> address unavailable in arp cache");
}
END_TEST


void cb_dns(char *ip, void *arg)
{
  if (!ip) {
    /* Error occured */
    printf("DNS error getaddr\n");
    return;
  }
  /* Do something */
  printf("DNS -> %s\n",ip);
  pico_free(ip);
  if (arg)
    pico_free(arg);
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
  fail_if(ret < 0, "dns> dns_client_nameserver add double failed");

  /* testing getaddr API */
  /* not testable since we do not have a stub for the pico_socket_send */
  // ret = pico_dns_client_getaddr(url, cb_dns, NULL); /* ask correct one */
  // fail_if(ret < 0, "dns> dns_client_getaddr: %s",strerror(pico_err));

  ret = pico_dns_client_getaddr(NULL, cb_dns, NULL);
  fail_if(ret == 0, "dns> dns_client_getaddr: no url");
  
  ret = pico_dns_client_getaddr(url, NULL, NULL);
  fail_if(ret == 0, "dns> dns_client_getaddr: no cb");

  /* testing getname API */
  /* not testable since we do not have a stub for the pico_socket_send */
  // ret = pico_dns_client_getname(ip, cb_dns, NULL); /* ask correct one */
  // fail_if(ret < 0, "dns> dns_client_getname: %s",strerror(pico_err));

  ret = pico_dns_client_getname(NULL, cb_dns, NULL);
  fail_if(ret == 0, "dns> dns_client_getname: no ip");

  ret = pico_dns_client_getname(ip, NULL, NULL);
  fail_if(ret == 0, "dns> dns_client_getname: no cb");
}
END_TEST


/* RB tree unit test */
typedef struct
{
	int value;
}elem;

int compare(void * a, void * b)
{
	return ((elem *)a)->value - ((elem *)b)->value;
}

PICO_TREE_DECLARE(test_tree,compare);
#define RBTEST_SIZE 400000

START_TEST (test_rbtree)
{
  struct pico_tree_node  *s;
  elem t,*e;
  int i;
  struct timeval start, end;
  printf("Started test...\n");
  gettimeofday(&start, 0);

  for (i = 0; i < (RBTEST_SIZE >> 1); i++) {
    e = malloc(sizeof(elem));
    e->value = i;
    pico_tree_insert(&test_tree,e);
    //RB_INSERT(rbtree, &RBTREE, e);
    e = malloc(sizeof(elem));
    e->value = (RBTEST_SIZE - 1) - i;
    pico_tree_insert(&test_tree,e);
  }

  i = 0;

  pico_tree_foreach(s,&test_tree){
    fail_if (i++ != ((elem *)(s->keyValue))->value,"error");
  }
  t.value = RBTEST_SIZE >> 2;

  e = pico_tree_findKey(&test_tree,&t);
  fail_if(!e, "Search failed...");
  fail_if(e->value != t.value, "Wrong element returned...");

  pico_tree_foreach_reverse(s,&test_tree){
    fail_if(!s, "Reverse safe returned null");
    e = (elem *)pico_tree_delete(&test_tree,s->keyValue);
    free(e);
  }

  fail_if(!pico_tree_empty(&test_tree), "Not empty");
  gettimeofday(&end, 0);
  printf("Rbtree test duration with %d entries: %d milliseconds\n", RBTEST_SIZE,
	(int)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) /1000));
  printf("Test finished...\n");
}
END_TEST

static struct pico_dhcp_client_cookie* dhcp_client_ptr;

void callback_dhcpclient(void* cli, int code){
  struct pico_ip4  gateway;
  char gw_txt_addr[30];
  if(code == PICO_DHCP_SUCCESS){
    gateway = pico_dhcp_get_gateway(&dhcp_client_ptr);
    pico_ipv4_to_string(gw_txt_addr, gateway.addr);
  }
  printf("callback happened with code %d!\n", code);
}

int mock_print_protocol(uint8_t *buf){
  uint8_t pnr = buf[0x17];// protocol number

  printf("transport protocol: %s\n",
   (pnr == PICO_PROTO_ICMP4 ? "icmp4" :
   (pnr == PICO_PROTO_IGMP ? "igmp" :
   (pnr == PICO_PROTO_TCP   ? "tcp" :
   (pnr == PICO_PROTO_UDP   ? "udp" :
   (pnr == PICO_PROTO_ICMP6 ? "icmp6": 
   "unknown proto")))))); 
   return 0;
}
#define BUFLEN (576+14+20+8) 
#if 0
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
  uint32_t xid = 0;
  struct pico_dhcp_client_cookie *cli = NULL;

  pico_stack_init();

  /* Create mock device  */
  mock = pico_mock_create(macaddr1);
	fail_if(!mock,"MOCK DEVICE creation failed");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");

  // initiate negotiation -> change state to  
	pico_dhcp_initiate_negotiation(mock->dev, &callback_dhcpclient, &xid);
  cli = get_cookie_by_xid(xid);
	dhcp_client_ptr = cli;
	fail_if(cli == NULL,"initiate fail");
  fail_unless(cli->state == DHCPSTATE_DISCOVER,"Not in discover state after init negotiate");
  fail_if(pico_mock_network_read(mock,buf,BUFLEN),"data on network that shouldn't be there");
  
  /* push discover msg on network */
  tick_it(3);

  /* read discover message from network */
  len = pico_mock_network_read(mock, buf,BUFLEN );
  fail_unless(len,"No msg received on network!");
  printbuf(&(buf[0]),len,"DHCP-DISCOVER packet",printbufactive);
  fail_unless(buf[0x011c]==0x01,"No DHCP Discover received after initiate negotiation");
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
  fail_unless(buf[0x011c]==0x03,"No DHCP request received after offer");
  
}
END_TEST
#endif

START_TEST (test_dhcp_client_api)
{
/************************************************************************
* Check API of pico_dhcp_initiate_negotiation 
* Status : Done
************************************************************************/

  /* Declaration test 0 */ 
  uint32_t xid0 = 0;
  struct pico_dhcp_client_cookie *cli0 = NULL;
  /* Declaration test 1 */ 
  uint32_t xid1 = 0;
  struct pico_dhcp_client_cookie *cli1 = NULL;

	printf("*********************** starting %s * \n", __func__);

  /* test 0 */ 
  /* Clear error code */
  pico_err = PICO_ERR_NOERR;
  /* Test 0 statements */
	pico_dhcp_initiate_negotiation(NULL, NULL, &xid0);
  cli0 = pico_dhcp_client_find_cookie(xid0);
  fail_unless(cli0 == NULL,"DHCP_CLIENT> initiate succeeded after pointer to dev == NULL");
  fail_unless(pico_err == PICO_ERR_EINVAL,"DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");
 
  /* test 1 */ 
  /* Clear error code */
  pico_err = PICO_ERR_NOERR;
  /* Test 1 statements */
	pico_dhcp_initiate_negotiation(NULL, &callback_dhcpclient, &xid1);
  cli1 = pico_dhcp_client_find_cookie(xid1);
  fail_unless(cli1 == NULL,"DHCP_CLIENT> initiate succeeded after pointer to dev == NULL");
  fail_unless(pico_err == PICO_ERR_EINVAL,"DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");

#if 0
  /* not testable since we do not have a stub for the pico_socket_sendto */
  /* Declaration test 2 */ 
  uint32_t xid2 = 0;
  struct pico_dhcp_client_cookie *cli2 = NULL;
  struct pico_device *dev2;
  struct mock_device *mock2=NULL;

  /* test 2 */ 
  /* Create device  */
  dev2 = pico_null_create("dummy");
  mock2 = pico_mock_create(NULL);
  fail_if(mock2 == NULL, "No device created");
  /* Clear error code */
  pico_err = PICO_ERR_NOERR;
  /* Test 2 statements */
	xid2 = pico_dhcp_initiate_negotiation(dev2, &callback_dhcpclient);
  cli2 = get_cookie_by_xid(xid2);
  fail_if(cli2 == NULL,"DHCP_CLIENT: error initiating: %s", strerror(pico_err));
	xid2 = pico_dhcp_initiate_negotiation(mock2->dev, &callback_dhcpclient);
  cli2 = get_cookie_by_xid(xid2);
  fail_if(cli2 == NULL,"DHCP_CLIENT: error initiating: %s", strerror(pico_err));
	xid2 = pico_dhcp_initiate_negotiation(dev2, &callback_dhcpclient);
  cli2 = get_cookie_by_xid(xid2);
  fail_if(cli2 == NULL,"DHCP_CLIENT: error initiating: %s", strerror(pico_err));
#endif
}
END_TEST
 
START_TEST (test_socket)
{
  int ret = 0;
  uint16_t port_be = 0, porta;
  char buf[] = "test";
  struct pico_socket *sk_tcp, *sk_udp, *s, *sl, *sa;
  struct pico_device *dev;
  struct pico_ip4 inaddr_dst, inaddr_link, inaddr_incorrect, inaddr_uni, inaddr_null, netmask,orig;

  int getnodelay = -1;
  int nodelay = -1;

  pico_stack_init();
    
  printf("START SOCKET TEST\n");

  pico_string_to_ipv4("224.7.7.7", &inaddr_dst.addr);
  pico_string_to_ipv4("10.40.0.2", &inaddr_link.addr);
  pico_string_to_ipv4("224.8.8.8", &inaddr_incorrect.addr);
  pico_string_to_ipv4("0.0.0.0", &inaddr_null.addr);
  pico_string_to_ipv4("10.40.0.3", &inaddr_uni.addr);

  dev = pico_null_create("dummy");
  netmask.addr = long_be(0xFFFF0000);
  ret = pico_ipv4_link_add(dev, inaddr_link, netmask); 
  fail_if(ret < 0, "socket> error adding link");


  /* socket_open passing wrong parameters */
  s = pico_socket_open(PICO_PROTO_IPV4, 99, NULL);
  fail_if(s != NULL, "Error got socket wrong parameters");

  s = pico_socket_open(PICO_PROTO_IPV4, -109, NULL);
  fail_if(s != NULL, "Error got socket");

  s = pico_socket_open(99, PICO_PROTO_UDP, NULL);
  fail_if(s != NULL, "Error got socket");

  s = pico_socket_open(-99, PICO_PROTO_UDP, NULL);
  fail_if(s != NULL, "Error got socket");


  sk_tcp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, NULL);
  fail_if(sk_tcp == NULL, "socket> tcp socket open failed");

  port_be = short_be(5555);
  /* socket_bind passing wrong parameters */
  ret = pico_socket_bind(NULL, &inaddr_link, &port_be);
  fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
  ret = pico_socket_bind(sk_tcp, NULL, &port_be);
  fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
  ret = pico_socket_bind(sk_tcp, &inaddr_link, NULL);
  fail_if(ret == 0, "socket> tcp socket bound wrong parameter");
  /* socket_bind passing correct parameters */
  ret = pico_socket_bind(sk_tcp, &inaddr_link, &port_be);
  fail_if(ret < 0, "socket> tcp socket bind failed");

  sk_udp = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
  fail_if(sk_udp == NULL, "socket> udp socket open failed");
  port_be = short_be(5555);
  ret = pico_socket_bind(sk_udp, &inaddr_link, &port_be);
  fail_if(ret < 0, "socket> udp socket bind failed");
  /* socket_close passing wrong parameter */
  ret = pico_socket_close(NULL);
  fail_if(ret == 0, "Error socket close with wrong parameters");


  /* socket_connect passing wrong parameters */
  ret = pico_socket_connect(sk_udp, NULL, port_be);
  fail_if(ret == 0, "Error socket connect with wrong parameters");
  ret = pico_socket_connect(NULL, &inaddr_dst, port_be);
  fail_if(ret == 0, "Error socket connect with wrong parameters");

  /* socket_connect passing correct parameters */
  ret = pico_socket_connect(sk_udp, &inaddr_dst, port_be);
  fail_if(ret < 0, "Error socket connect");
  ret = pico_socket_connect(sk_tcp, &inaddr_dst, port_be);
  fail_if(ret < 0, "Error socket connect");


  /* testing listening socket */
  sl = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_TCP, NULL);
  fail_if(sl == NULL, "socket> tcp socket open failed");
  port_be = short_be(6666);
  ret = pico_socket_bind(sl, &inaddr_link, &port_be);
  fail_if(ret < 0, "socket> tcp socket bind failed");
  /* socket_listen passing wrong parameters */
  ret = pico_socket_listen(sl,0);
  fail_if(ret == 0, "Error socket tcp socket listen done, wrong parameter");
  ret = pico_socket_listen(NULL,10);
  fail_if(ret == 0, "Error socket tcp socket listen done, wrong parameter");
  /* socket_listen passing correct parameters */
  ret = pico_socket_listen(sl,10);
  fail_if(ret < 0, "socket> tcp socket listen failed: %s",strerror(pico_err));

  /* socket_accept passing wrong parameters */
  sa = pico_socket_accept(sl,&orig,NULL);
  fail_if(sa != NULL, "Error socket tcp socket accept wrong argument");
  sa = pico_socket_accept(sl,NULL,&porta);
  fail_if(sa != NULL, "Error socket tcp socket accept wrong argument");
  /* socket_accept passing correct parameters */
  sa = pico_socket_accept(sl,&orig,&porta);
  fail_if(sa == NULL && pico_err != PICO_ERR_EAGAIN, "socket> tcp socket accept failed: %s",strerror(pico_err));

  ret = pico_socket_close(sl);
  fail_if(ret < 0, "socket> tcp socket close failed: %s\n", strerror(pico_err));


  /* testing socket read/write */
  /* socket_write passing wrong parameters */
  ret = pico_socket_write(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
  ret = pico_socket_write(sk_tcp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
  ret = pico_socket_write(sk_tcp,(void *)buf,0);
  fail_if(ret > 0, "Error socket write succeeded, wrong argument\n");
  /* socket_write passing correct parameters */
  ret = pico_socket_write(sk_tcp,(void *)buf,sizeof(buf));
  fail_if(ret < 0, "socket> tcp socket write failed: %s\n", strerror(pico_err));
  /* socket_read passing wrong parameters */
  ret = pico_socket_read(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
  ret = pico_socket_read(sk_tcp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
  ret = pico_socket_read(sk_tcp,(void *)buf,0);
  fail_if(ret > 0, "Error socket read succeeded, wrong argument\n");
  /* socket_read passing correct parameters */
  ret = pico_socket_read(sk_tcp,(void *)buf,sizeof(buf));
  fail_if(ret < 0, "socket> tcp socket read failed, ret = %d: %s\n",ret, strerror(pico_err));  /* tcp_recv returns 0 when no frame !? */


  /* send/recv */
  /* socket_send passing wrong parameters */
  ret = pico_socket_send(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
  ret = pico_socket_send(sk_tcp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
  ret = pico_socket_send(sk_tcp,(void *)buf,0);
  fail_if(ret > 0, "Error socket send succeeded, wrong argument\n");
  /* socket_write passing correct parameters */
  ret = pico_socket_send(sk_tcp,(void *)buf,sizeof(buf));
  fail_if(ret <= 0, "socket> tcp socket send failed: %s\n", strerror(pico_err));
  /* socket_recv passing wrong parameters */
  ret = pico_socket_recv(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
  ret = pico_socket_recv(sk_tcp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
  ret = pico_socket_recv(sk_tcp,(void *)buf,0);
  fail_if(ret > 0, "Error socket recv succeeded, wrong argument\n");
  /* socket_recv passing correct parameters */
  ret = pico_socket_recv(sk_tcp,(void *)buf,sizeof(buf));
  fail_if(ret < 0, "socket> tcp socket recv failed, ret = %d: %s\n",ret, strerror(pico_err));  /* tcp_recv returns 0 when no frame !? */
  

  /* sendto/recvfrom */
  /* socket_sendto passing wrong parameters */
  ret = pico_socket_sendto(NULL,(void *)buf,sizeof(buf),&inaddr_dst,port_be);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_tcp,NULL,sizeof(buf),&inaddr_dst,port_be);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_tcp,(void *)buf,0,&inaddr_dst,port_be);
  fail_if(ret > 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_tcp,(void *)buf,sizeof(buf),NULL,port_be);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_tcp,(void *)buf,sizeof(buf),&inaddr_dst,-120);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  /* socket_write passing correct parameters */
  ret = pico_socket_sendto(sk_tcp,(void *)buf,sizeof(buf),&inaddr_dst,short_be(5555));
  fail_if(ret <= 0, "socket> udp socket sendto failed, ret = %d: %s\n",ret, strerror(pico_err));
  /* socket_recvfrom passing wrong parameters */
  ret = pico_socket_recvfrom(NULL,(void *)buf,sizeof(buf),&orig,&porta);
  fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
  ret = pico_socket_recvfrom(sk_tcp,NULL,sizeof(buf),&orig,&porta);
  fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
  ret = pico_socket_recvfrom(sk_tcp,(void *)buf,0,&orig,&porta);
  fail_if(ret > 0, "Error socket recvfrom succeeded, wrong argument\n");
  ret = pico_socket_recvfrom(sk_tcp,(void *)buf,sizeof(buf),NULL,&porta);
  fail_if(ret > 0, "Error socket recvfrom succeeded, wrong argument\n");
  ret = pico_socket_recvfrom(sk_tcp,(void *)buf,sizeof(buf),&orig,NULL);
  fail_if(ret > 0, "Error socket recvfrom succeeded, wrong argument\n");
  /* socket_recvfrom passing correct parameters */
  ret = pico_socket_recvfrom(sk_tcp,(void *)buf,sizeof(buf),&orig,&porta);
  fail_if(ret != 0, "socket> tcp socket recvfrom failed, ret = %d: %s\n",ret, strerror(pico_err));  /* tcp_recv returns -1 when no frame !? */


  /* testing socket read/write */
  /* socket_write passing wrong parameters */
  ret = pico_socket_write(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
  ret = pico_socket_write(sk_udp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket write succeeded, wrong argument\n");
  ret = pico_socket_write(sk_udp,(void *)buf,0);
  fail_if(ret > 0, "Error socket write succeeded, wrong argument\n");
  /* socket_write passing correct parameters */
  ret = pico_socket_write(sk_udp,(void *)buf,sizeof(buf));
  fail_if(ret < 0, "socket> tcp socket write failed: %s\n", strerror(pico_err));
  /* socket_read passing wrong parameters */
  ret = pico_socket_read(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
  ret = pico_socket_read(sk_udp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket read succeeded, wrong argument\n");
  ret = pico_socket_read(sk_udp,(void *)buf,0);
  fail_if(ret > 0, "Error socket read succeeded, wrong argument\n");
  /* socket_read passing correct parameters */
  ret = pico_socket_read(sk_udp,(void *)buf,sizeof(buf));
  fail_if(ret != 0, "socket> udp socket read failed, ret = %d: %s\n",ret, strerror(pico_err)); 


  /* send/recv */
  /* socket_send passing wrong parameters */
  ret = pico_socket_send(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
  ret = pico_socket_send(sk_udp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket send succeeded, wrong argument\n");
  ret = pico_socket_send(sk_udp,(void *)buf,0);
  fail_if(ret > 0, "Error socket send succeeded, wrong argument\n");
  /* socket_write passing correct parameters */
  ret = pico_socket_send(sk_udp,(void *)buf,sizeof(buf));
  fail_if(ret <= 0, "socket> tcp socket send failed: %s\n", strerror(pico_err));
  /* socket_recv passing wrong parameters */
  ret = pico_socket_recv(NULL,(void *)buf,sizeof(buf));
  fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
  ret = pico_socket_recv(sk_udp,NULL,sizeof(buf));
  fail_if(ret == 0, "Error socket recv succeeded, wrong argument\n");
  ret = pico_socket_recv(sk_udp,(void *)buf,0);
  fail_if(ret > 0, "Error socket recv succeeded, wrong argument\n");
  /* socket_recv passing correct parameters */
  ret = pico_socket_recv(sk_udp,(void *)buf,sizeof(buf));
  fail_if(ret != 0, "socket> udp socket recv failed, ret = %d: %s\n",ret, strerror(pico_err));
  

  /* sendto/recvfrom */
  /* socket_sendto passing wrong parameters */
  ret = pico_socket_sendto(NULL,(void *)buf,sizeof(buf),&inaddr_dst,port_be);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_udp,NULL,sizeof(buf),&inaddr_dst,port_be);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_udp,(void *)buf,0,&inaddr_dst,port_be);
  fail_if(ret > 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_udp,(void *)buf,sizeof(buf),NULL,port_be);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  ret = pico_socket_sendto(sk_udp,(void *)buf,sizeof(buf),&inaddr_dst,-120);
  fail_if(ret >= 0, "Error socket sendto succeeded, wrong argument\n");
  /* socket_write passing correct parameters */
  ret = pico_socket_sendto(sk_udp,(void *)buf,sizeof(buf),&inaddr_dst,short_be(5555));
  fail_if(ret <= 0, "socket> udp socket sendto failed, ret = %d: %s\n",ret, strerror(pico_err));
  /* socket_recvfrom passing wrong parameters */
  ret = pico_socket_recvfrom(NULL,(void *)buf,sizeof(buf),&orig,&porta);
  fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
  ret = pico_socket_recvfrom(sk_udp,NULL,sizeof(buf),&orig,&porta);
  fail_if(ret >= 0, "Error socket recvfrom succeeded, wrong argument\n");
  /* socket_recvfrom passing correct parameters */
  ret = pico_socket_recvfrom(sk_udp,(void *)buf,0,&orig,&porta);
  fail_if(ret != 0, "socket> udp socket recvfrom failed, ret = %d: %s\n",ret, strerror(pico_err));
  ret = pico_socket_recvfrom(sk_udp,(void *)buf,sizeof(buf),&orig,&porta);
  fail_if(ret != 0, "socket> udp socket recvfrom failed, ret = %d: %s\n",ret, strerror(pico_err));

  // temporary fix, until Nagle problems are analyzed and fixed
  {
  	nodelay = 0;
  	ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
  }

  /* setoption/getoption */
  ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
  fail_if(getnodelay != 0, "socket> socket_setoption: default PICO_TCP_NODELAY != 0 (nagle disabled by default)\n");

  nodelay = 1;
  ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_TCP_NODELAY failed\n");
  ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
  fail_if(getnodelay == 0, "socket> socket_setoption: PICO_TCP_NODELAY is off (expected: on!)\n");

  nodelay = 0;
  ret = pico_socket_setoption(sk_tcp, PICO_TCP_NODELAY, &nodelay);
  fail_if(ret < 0, "socket> socket_setoption: supported PICO_TCP_NODELAY failed\n");
  ret = pico_socket_getoption(sk_tcp, PICO_TCP_NODELAY, &getnodelay);
  fail_if(ret < 0, "socket> socket_getoption: supported PICO_TCP_NODELAY failed\n");
  fail_if(getnodelay != 0, "socket> socket_setoption: PICO_TCP_NODELAY is on (expected: off!)\n");

  ret = pico_socket_close(sk_tcp);
  fail_if(ret < 0, "socket> tcp socket close failed: %s\n", strerror(pico_err));
  ret = pico_socket_close(sk_udp);
  fail_if(ret < 0, "socket> udp socket close failed: %s\n", strerror(pico_err));
}
END_TEST

START_TEST (test_ipfilter)
{  
  struct pico_device *dev = NULL;
  uint8_t proto = 0, sport = 0, dport = 0, tos = 0;
  int8_t priority = 0;
  int ret =0;

  struct pico_ip4 src_addr = {0};
  struct pico_ip4 saddr_netmask= {0};
  struct pico_ip4 dst_addr = {0};
  struct pico_ip4 daddr_netmask = {0} ;

  enum filter_action action = 1;

  int filter_id1;
  int filter_id2;
  int filter_id3;

  uint8_t ipv4_buf[]= {0x45, 0x00, 0x00, 0x4a, 0x91, 0xc3, 0x40, 0x00, 0x3f, 0x06, 0x95, 0x8c, 0x0a, 0x32, 0x00, 0x03, 0x0a, 0x28, 0x00, 0x02};
  uint8_t tcp_buf[]= { 0x15, 0xb4, 0x15, 0xb3, 0xd5, 0x75, 0x77, 0xee, 0x00, 0x00, 0x00, 0x00, 0x90, 0x08, 0xf5, 0x3c, 0x55, 0x1f, 0x00, 0x00, 0x03, 0x03,  0x00, 0x08, 0x0a, 0xb7, 0xeb, 0xce, 0xc1, 0xb7, 0xeb, 0xce, 0xb5, 0x01, 0x01, 0x00};

  uint8_t ipv4_buf2[]= {0x45, 0x00, 0x00, 0x4a, 0x91, 0xc3, 0x40, 0x00, 0x3f, 0x06, 0x95, 0x8c, 0x0a, 0x32, 0x00, 0x03, 0x0a, 0x28, 0x00, 0x02};
  uint8_t tcp_buf2[]= { 0x15, 0xb4, 0x15, 0xb3, 0xd5, 0x75, 0x77, 0xee, 0x00, 0x00, 0x00, 0x00, 0x90, 0x08, 0xf5, 0x3c, 0x55, 0x1f, 0x00, 0x00, 0x03, 0x03,  0x00, 0x08, 0x0a, 0xb7, 0xeb, 0xce, 0xc1, 0xb7, 0xeb, 0xce, 0xb5, 0x01, 0x01, 0x00};

  int8_t *buffer= pico_zalloc(200);
  struct pico_frame *f= (struct pico_frame *) buffer;
  struct pico_frame *f2= (struct pico_frame *) buffer;

  printf("============================== IPFILTER ===============================\n");

  f->buffer = pico_zalloc(10);
  f->usage_count = pico_zalloc(sizeof(uint32_t));

  /*======================== EMPTY FILTER*/
  printf("===========> EMPTY FILTER\n");

  filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, action);

  fail_if(filter_id1 != -1, "Error adding filter\n");
  printf("filter_id1 = %d\n", filter_id1);

   // connect the buffer to the f->net_hdr pointer
  f->net_hdr= ipv4_buf;
  // connect the buffer to the f->transport_hdr pointer
  f->transport_hdr= tcp_buf;

  fail_if(ipfilter(f) != 0, "Error filtering packet: EMPTY FILTER");


  filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, 4545, priority, tos, action);
  /*======================= DROP PROTO FILTER: TCP*/
  printf("===========> DROP PROTO FILTER: TCP\n");

  filter_id2 = pico_ipv4_filter_add(dev, PICO_PROTO_TCP, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, FILTER_DROP);
  printf("filter_id2 = %d\n", filter_id2);
  fail_if(filter_id2 == -1, "Error adding filter\n");


  // connect the buffer to the f->net_hdr pointer
  f2->net_hdr= ipv4_buf2;
  // connect the buffer to the f->transport_hdr pointer
  f2->transport_hdr= tcp_buf2;

  printf("UNIT: :packet proto:%d\n",f2->proto);

  ret = ipfilter(f2);

  fail_if(ret < 0, "Error filtering packet: DROP PROTO FILTER: TCP");

  /*====================== DELETING FILTERS*/
  printf("===========> DELETING FILTER\n");

  /*Adjust your IPFILTER*/
  filter_id3 = pico_ipv4_filter_add(NULL, 17, NULL, NULL , NULL, NULL, 0, 0, 0, 0, FILTER_DROP);
  fail_if(filter_id3 == -1, "Error adding filter\n");

  printf("filter_id3: %d\n", filter_id3);
  /*Deleting IPFILTER*/

  fail_if(pico_ipv4_filter_del(filter_id2) != 0 , "Error deleting filter 2");
  fail_if(pico_ipv4_filter_del(filter_id3) != 0 , "Error deleting filter 3");
  fail_if(pico_ipv4_filter_del(filter_id1) != 0 , "Error deleting filter 1");

  printf("filters deleted\n");

  /*======================= REJECT SPORT FILTER*/
  /*printf("===========> REJECT SPORT FILTER\n");

  pico_ipv4_filter_add(dev, proto, src_addr, saddr_netmask, dst_addr, daddr_netmask, 3333, dport, priority, tos, 3);

  struct pico_frame *f3= (struct pico_frame *) buffer;
  uint8_t ipv4_buf3[]= {0x45, 0x00, 0x00, 0x4a, 0x91, 0xc3, 0x40, 0x00, 0x3f, 0x06, 0x95, 0x8c, 0x0a, 0x32, 0x00, 0x03, 0x0a, 0x28, 0x00, 0x02};
  uint8_t tcp_buf3[]= { 0x0D, 0x05, 0x15, 0xb3, 0xd5, 0x75, 0x77, 0xee, 0x00, 0x00, 0x00, 0x00, 0x90, 0x08, 0xf5, 0x3c, 0x55, 0x1f, 0x00, 0x00, 0x03, 0x03,  0x00, 0x08, 0x0a, 0xb7, 0xeb, 0xce, 0xc1, 0xb7, 0xeb, 0xce, 0xb5, 0x01, 0x01, 0x00};

  // connect the buffer to the f->net_hdr pointer
  f3->net_hdr= ipv4_buf3;
  // connect the buffer to the f->transport_hdr pointer
  f3->transport_hdr= tcp_buf3;

  fail_if(ipfilter(f3) != 1, "Error filtering packet: REJECT SPORT FILTER");
*/
}
END_TEST

#ifdef PICO_SUPPORT_CRC
START_TEST (test_crc_check)
{
  uint8_t buffer[64] = { 0x45, 0x00, 0x00, 0x40, /* start of IP hdr */
                         0x91, 0xc3, 0x40, 0x00, 
                         0x40, 0x11, 0x24, 0xcf, /* last 2 bytes are CRC */
                         0xc0, 0xa8, 0x01, 0x66, 
                         0xc0, 0xa8, 0x01, 0x64, /* end of IP hdr */
                         0x15, 0xb3, 0x1F, 0x90, /* start of UDP/TCP hdr */
                         0x00, 0x2c, 0x27, 0x22, /* end of UDP hdr */
                         0x00, 0x00, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, 
                         0x00, 0x0b, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, /* end of TCP hdr */
                         0x01, 0x23, 0x45, 0x67, /* start of data */
                         0x89, 0xab, 0xcd, 0xef, 
                         0xc0, 0xca, 0xc0, 0x1a};
  struct pico_frame *f = NULL;
  struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) buffer;
  struct pico_udp_hdr *udp_hdr = NULL;
  struct pico_tcp_hdr *tcp_hdr = NULL;
  uint32_t *f_usage_count = NULL;
  uint8_t *f_buffer = NULL;
  int ret = -1;

  printf("START CRC TEST\n");
  pico_stack_init();

  /* IPv4 CRC unit tests */
  /* Allocated memory will be freed when pico_ipv4_crc_check fails */
  f = calloc(1, sizeof(struct pico_frame));
  f_usage_count = calloc(1, sizeof(uint32_t));
  f_buffer = calloc(1, sizeof(uint8_t));
  f->net_hdr = buffer;
  f->transport_hdr = buffer + PICO_SIZE_IP4HDR;
  f->transport_len = sizeof(buffer) - PICO_SIZE_IP4HDR;
  f->usage_count = f_usage_count;
  f->buffer = f_buffer;
  *(f->usage_count) = 1;

  //hdr->crc = 0;
  //printf(">>>>>>>>>>>>>>>>>>>>> CRC VALUE = %X\n", pico_checksum(hdr, PICO_SIZE_IP4HDR));
  ret = pico_ipv4_crc_check(f);
  fail_if(ret == 0, "correct IPv4 checksum got rejected\n");
  hdr->crc = short_be(0x8899); /* Make check fail */
  ret = pico_ipv4_crc_check(f);
  fail_if(ret == 1, "incorrect IPv4 checksum got accepted\n");

  /* UDP CRC unit tests */
  /* Allocated memory will be freed when pico_transport_crc_check fails */
  f = calloc(1, sizeof(struct pico_frame));
  f_usage_count = calloc(1, sizeof(uint32_t));
  f_buffer = calloc(1, sizeof(uint8_t));
  f->net_hdr = buffer;
  f->transport_hdr = buffer + PICO_SIZE_IP4HDR;
  f->transport_len = sizeof(buffer) - PICO_SIZE_IP4HDR;
  f->usage_count = f_usage_count;
  f->buffer = f_buffer;
  *(f->usage_count) = 1;
  hdr->proto = 0x11; /* UDP */
  hdr->crc = short_be(0x24cf); /* Set IPv4 CRC correct */
  udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;

  //udp_hdr->crc = 0;
  //printf(">>>>>>>>>>>>>>>>>>>>> UDP CRC VALUE = %X\n", pico_udp_checksum_ipv4(f));
  ret = pico_transport_crc_check(f);
  fail_if(ret == 0, "correct UDP checksum got rejected\n");
  udp_hdr->crc = 0;
  ret = pico_transport_crc_check(f);
  fail_if(ret == 0, "UDP checksum of 0 did not get ignored\n");
  udp_hdr->crc = short_be(0x8899); /* Make check fail */
  ret = pico_transport_crc_check(f);
  fail_if(ret == 1, "incorrect UDP checksum got accepted\n");

  /* TCP CRC unit tests */
  /* Allocated memory will be freed when pico_transport_crc_check fails */
  f = calloc(1, sizeof(struct pico_frame));
  f_usage_count = calloc(1, sizeof(uint32_t));
  f_buffer = calloc(1, sizeof(uint8_t));
  f->net_hdr = buffer;
  f->transport_hdr = buffer + PICO_SIZE_IP4HDR;
  f->transport_len = sizeof(buffer) - PICO_SIZE_IP4HDR;
  f->usage_count = f_usage_count;
  f->buffer = f_buffer;
  *(f->usage_count) = 1;
  hdr->proto = 0x06; /* TCP */
  hdr->crc = short_be(0x24cf); /* Set IPv4 CRC correct */
  tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  tcp_hdr->seq = long_be(0x002c2722); /* Set sequence number correct */

  //tcp_hdr = 0;
  //printf(">>>>>>>>>>>>>>>>>>>>> TCP CRC VALUE = %X\n", pico_tcp_checksum_ipv4(f));
  tcp_hdr->crc = short_be(0x0016); /* Set correct TCP CRC */
  ret = pico_transport_crc_check(f);
  fail_if(ret == 0, "correct TCP checksum got rejected\n");
  tcp_hdr->crc = short_be(0x8899); /* Make check fail */
  ret = pico_transport_crc_check(f);
  fail_if(ret == 1, "incorrect TCP checksum got accepted\n");
}
END_TEST
#endif

#ifdef PICO_SUPPORT_MCAST
START_TEST (test_igmp_sockopts)
{
  int i = 0, j = 0, k = 0, ret = 0;
  struct pico_socket *s, *s1 = NULL;
  struct pico_device *dev = NULL;
  struct pico_ip4 *source = NULL;
  struct pico_ip4 inaddr_dst = {0}, inaddr_incorrect = {0}, inaddr_uni = {0}, inaddr_null = {0}, netmask = {0};
  struct pico_ip4 inaddr_link[2] = {{0}};
  struct pico_ip4 inaddr_mcast[8] = {{0}};
  struct pico_ip4 inaddr_source[8] = {{0}};
  struct pico_ip_mreq _mreq = {{0}}, mreq[16] = {{{0}}};
  struct pico_ip_mreq_source mreq_source[128] = {{{0}}};
  struct pico_tree_node *index = NULL;

  int ttl = 64;
  int  getttl = 0;
  int  loop = 9;
  int  getloop = 0;
  struct pico_ip4 mcast_default_link = {0};

  pico_stack_init();
    
  printf("START IGMP SOCKOPTS TEST\n");

  pico_string_to_ipv4("224.7.7.7", &inaddr_dst.addr);
  pico_string_to_ipv4("10.40.0.2", &inaddr_uni.addr);
  pico_string_to_ipv4("224.8.8.8", &inaddr_incorrect.addr);
  pico_string_to_ipv4("0.0.0.0", &inaddr_null.addr);

  pico_string_to_ipv4("10.40.0.1", &inaddr_link[0].addr); /* 0 */
  pico_string_to_ipv4("10.50.0.1", &inaddr_link[1].addr); /* 1 */

  pico_string_to_ipv4("232.1.1.0", &inaddr_mcast[0].addr); /* 0 */
  pico_string_to_ipv4("232.2.2.1", &inaddr_mcast[1].addr); /* 1 */
  pico_string_to_ipv4("232.3.3.2", &inaddr_mcast[2].addr); /* 2 */
  pico_string_to_ipv4("232.4.4.3", &inaddr_mcast[3].addr); /* 3 */
  pico_string_to_ipv4("232.5.5.4", &inaddr_mcast[4].addr); /* 4 */
  pico_string_to_ipv4("232.6.6.5", &inaddr_mcast[5].addr); /* 5 */
  pico_string_to_ipv4("232.7.7.6", &inaddr_mcast[6].addr); /* 6 */
  pico_string_to_ipv4("232.8.8.7", &inaddr_mcast[7].addr); /* 7 */

  pico_string_to_ipv4("10.40.1.0", &inaddr_source[0].addr); /* 0 */
  pico_string_to_ipv4("10.40.1.1", &inaddr_source[1].addr); /* 1 */
  pico_string_to_ipv4("10.40.1.2", &inaddr_source[2].addr); /* 2 */
  pico_string_to_ipv4("10.40.1.3", &inaddr_source[3].addr); /* 3 */
  pico_string_to_ipv4("10.40.1.4", &inaddr_source[4].addr); /* 4 */
  pico_string_to_ipv4("10.40.1.5", &inaddr_source[5].addr); /* 5 */
  pico_string_to_ipv4("10.40.1.6", &inaddr_source[6].addr); /* 6 */
  pico_string_to_ipv4("10.40.1.7", &inaddr_source[7].addr); /* 7 */

  /* 00 01 02 03 04 05 06 07 | 10 11 12 13 14 15 16 17 */
  for (i = 0; i < 16; i++) {
    mreq[i].mcast_link_addr = inaddr_link[i/8];
    mreq[i].mcast_group_addr = inaddr_mcast[i%8];
  }

  /* 000 001 002 003 004 005 006 007 | 010 011 012 013 014 015 016 017  */
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 8; j++) {
      //printf(">>>>> mreq_source[%d]: link[%d] mcast[%d] source[%d]\n", (i*8)+j, i/8, i%8, j);
      mreq_source[(i*8)+j].mcast_link_addr = inaddr_link[i/8];
      mreq_source[(i*8)+j].mcast_group_addr = inaddr_mcast[i%8];
      mreq_source[(i*8)+j].mcast_source_addr = inaddr_source[j];
    }
  }

  dev = pico_null_create("dummy0");
  netmask.addr = long_be(0xFFFF0000);
  ret = pico_ipv4_link_add(dev, inaddr_link[0], netmask); 
  fail_if(ret < 0, "link add failed");

  dev = pico_null_create("dummy1");
  netmask.addr = long_be(0xFFFF0000);
  ret = pico_ipv4_link_add(dev, inaddr_link[1], netmask); 
  fail_if(ret < 0, "link add failed");

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
  fail_if(s == NULL, "UDP socket open failed");
  s1 = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
  fail_if(s1 == NULL, "UDP socket open failed");

  /* argument validation tests */
  printf("IGMP SETOPTION ARGUMENT VALIDATION TEST\n");
  ret = pico_socket_setoption(s, PICO_IP_MULTICAST_IF, &mcast_default_link);
  fail_if(ret == 0, "unsupported PICO_IP_MULTICAST_IF succeeded\n");
  ret = pico_socket_getoption(s, PICO_IP_MULTICAST_IF, &mcast_default_link);
  fail_if(ret == 0, "unsupported PICO_IP_MULTICAST_IF succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_MULTICAST_TTL, &ttl);
  fail_if(ret < 0, "supported PICO_IP_MULTICAST_TTL failed\n");

  ret = pico_socket_getoption(s, PICO_IP_MULTICAST_TTL, &getttl);
  fail_if(ret < 0, "supported PICO_IP_MULTICAST_TTL failed\n");
  fail_if(getttl != ttl, "setoption ttl != getoption ttl\n");

  ret = pico_socket_setoption(s, PICO_IP_MULTICAST_LOOP, &loop);
  fail_if(ret == 0, "PICO_IP_MULTICAST_LOOP succeeded with invalid (not 0 or 1) loop value\n");
  loop = 0;
  ret = pico_socket_setoption(s, PICO_IP_MULTICAST_LOOP, &loop);
  fail_if(ret < 0, "supported PICO_IP_MULTICAST_LOOP failed\n");
  ret = pico_socket_getoption(s, PICO_IP_MULTICAST_LOOP, &getloop);
  fail_if(ret < 0, "supported PICO_IP_MULTICAST_LOOP failed\n");
  fail_if(getloop != loop, "setoption loop != getoption loop\n");

  _mreq.mcast_group_addr = inaddr_dst;
  _mreq.mcast_link_addr = inaddr_link[0];
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq); 
  fail_if(ret < 0, "supported PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq); 
  fail_if(ret < 0, "supported PICO_IP_DROP_MEMBERSHIP failed\n");
  _mreq.mcast_group_addr = inaddr_dst;
  _mreq.mcast_link_addr = inaddr_null;
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed with valid NULL (use default) link address\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed with valid NULL (use default) link address\n");
  _mreq.mcast_group_addr = inaddr_uni;
  _mreq.mcast_link_addr = inaddr_link[0];
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded with invalid (unicast) group address\n");
  _mreq.mcast_group_addr = inaddr_null;
  _mreq.mcast_link_addr = inaddr_link[0];
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded with invalid (NULL) group address\n");
  _mreq.mcast_group_addr = inaddr_dst;
  _mreq.mcast_link_addr = inaddr_uni;
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded with invalid link address\n");
  _mreq.mcast_group_addr = inaddr_incorrect;
  _mreq.mcast_link_addr = inaddr_link[0];
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (not added) group address\n");
  _mreq.mcast_group_addr = inaddr_uni;
  _mreq.mcast_link_addr = inaddr_link[0];
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (unicast) group address\n");
  _mreq.mcast_group_addr = inaddr_null;
  _mreq.mcast_link_addr = inaddr_link[0];
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (NULL) group address\n");
  _mreq.mcast_group_addr = inaddr_dst;
  _mreq.mcast_link_addr = inaddr_uni;
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
  fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (unicast) link address\n");

  /* flow validation tests */
  printf("IGMP SETOPTION FLOW VALIDATION TEST\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed with err %s\n", strerror(pico_err));
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_BLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");

  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_BLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_BLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_SOURCE succeeded\n");

  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_BLOCK_SOURCE succeeded\n");

  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_BLOCK_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_UNBLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_BLOCK_SOURCE succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");

  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_UNBLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret == 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP succeeded\n");
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  /* stress tests */
  printf("IGMP SETOPTION STRESS TEST\n");
  for (k = 0; k < 2; k++) {
    /* ADD for even combinations of group and link, ADD_SOURCE for uneven */
    for (i = 0; i < 16; i++) {
      if (i%2) {
        ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[i]); 
        fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
        for (j = 0; j < 8; j++) {
          ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[(i*8)+j]); 
          fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
        }
      } else {
        for (j = 0; j < 8; j++) {
          ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[(i*8)+j]); 
          fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
        }
      }
    }

    /* UNBLOCK and DROP for even combinations, DROP_SOURCE for uneven */
    for (i = 0; i < 16; i++) {
      if (i%2) {
        for (j = 0; j < 8; j++) {
          ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[(i*8)+j]); 
          fail_if(ret < 0, "PICO_IP_UNBLOCK_SOURCE failed\n");
        }
        ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[i]); 
        fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
      } else {
        for (j = 0; j < 8; j++) {
          ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[(i*8)+j]); 
          fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");
        }
      }
    }
    /* everything should be cleanup up, next iteration will fail if not */
  }

  /* filter validation tests */
  printf("IGMP SETOPTION FILTER VALIDATION TEST\n");
  /* INCLUDE + INCLUDE expected filter: source of 0 and 1*/
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[1]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  i = 0;
  pico_tree_foreach(index, &MCASTFilter)
  {
    if (++i > 2)
      fail("MCASTFilter (INCLUDE + INCLUDE) too many elements\n");
    source = index->keyValue;
    if (source->addr == mreq_source[0].mcast_source_addr.addr) { /* OK */ }
    else if (source->addr == mreq_source[1].mcast_source_addr.addr) { /* OK */ }
    else { fail("MCASTFilter (INCLUDE + INCLUDE) incorrect\n"); }
  }
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  /* INCLUDE + EXCLUDE expected filter: source of 2 */
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[1]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_BLOCK_SOURCE, &mreq_source[1]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_BLOCK_SOURCE, &mreq_source[2]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  i = 0;
  pico_tree_foreach(index, &MCASTFilter)
  {
    if (++i > 1)
      fail("MCASTFilter (INCLUDE + EXCLUDE) too many elements\n");
    source = index->keyValue;
    if (source->addr == mreq_source[2].mcast_source_addr.addr) { /* OK */ }
    else { fail("MCASTFilter (INCLUDE + EXCLUDE) incorrect\n"); }
  }
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  /* EXCLUDE + INCLUDE expected filter: source of 0 and 1 */
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[1]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[3]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[4]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[3]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[4]); 
  fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
  i = 0;
  pico_tree_foreach(index, &MCASTFilter)
  {
    if (++i > 2)
      fail("MCASTFilter (EXCLUDE + INCLUDE) too many elements\n");
    source = index->keyValue;
    if (source->addr == mreq_source[0].mcast_source_addr.addr) { /* OK */ }
    else if (source->addr == mreq_source[1].mcast_source_addr.addr) { /* OK */ }
    else { fail("MCASTFilter (EXCLUDE + INCLUDE) incorrect\n"); }
  }
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");

  /* EXCLUDE + EXCLUDE expected filter: source of 3 and 4 */
  ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[0]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[1]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[3]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[4]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_ADD_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_BLOCK_SOURCE, &mreq_source[3]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_BLOCK_SOURCE, &mreq_source[4]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_BLOCK_SOURCE, &mreq_source[5]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_BLOCK_SOURCE, &mreq_source[6]); 
  fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
  i = 0;
  pico_tree_foreach(index, &MCASTFilter)
  {
    if (++i > 2)
      fail("MCASTFilter (EXCLUDE + EXCLUDE) too many elements\n");
    source = index->keyValue;
    if (source->addr == mreq_source[3].mcast_source_addr.addr) { /* OK */ }
    else if (source->addr == mreq_source[4].mcast_source_addr.addr) { /* OK */ }
    else { fail("MCASTFilter (EXCLUDE + EXCLUDE) incorrect\n"); }
  }
  ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
  ret = pico_socket_setoption(s1, PICO_IP_DROP_MEMBERSHIP, &mreq[0]); 
  fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");


  ret = pico_socket_close(s);
  fail_if(ret < 0, "socket close failed: %s\n", strerror(pico_err));
  ret = pico_socket_close(s1);
  fail_if(ret < 0, "socket close failed: %s\n", strerror(pico_err));
}
END_TEST
#endif

START_TEST (test_frame)
{
  struct pico_frame *f1;
  struct pico_frame *cpy;
  struct pico_frame *deepcpy;

  f1 = pico_frame_alloc(200);
  f1->payload = f1->buffer +32;
  f1->net_hdr = f1->buffer +16;
  cpy = pico_frame_copy(f1);
  deepcpy = pico_frame_deepcopy(f1);
  fail_unless(*f1->usage_count == 2);
  fail_unless(*deepcpy->usage_count == 1);
  pico_frame_discard(f1);
  fail_unless(*cpy->usage_count == 1);
  pico_frame_discard(cpy);
  fail_unless(*deepcpy->usage_count == 1);
  pico_frame_discard(deepcpy);
}
END_TEST

START_TEST (test_timers)
{

  struct pico_timer *T[128];
  int i;
  pico_stack_init();
  for (i = 0; i < 128; i++) {
    T[i] = pico_timer_add(1 + i, 0xff00 + i, 0xaa00 + i);
    printf("New timer @ %p (%x-%x)\n", T[i], T[i]->timer, T[i]->arg); 
  }
  for (i = 0; i < 128; i++) {
    fail_if(i + 1 > Timers->n);
    fail_unless(Timers->top[i+1].tmr == T[i]);
    fail_unless(T[i]->timer == (0xff00 + i));
    fail_unless(T[i]->arg == (0xaa00 + i));
  }
  for (i = 0; i < 128; i++) {
    printf("Deleting timer %d \n", i );
    pico_timer_cancel(T[i]);
    printf("Deleted timer %d \n", i );
    fail_unless(Timers->top[i+1].tmr == NULL);
  }
  pico_stack_tick();
  pico_stack_tick();
  pico_stack_tick();
  pico_stack_tick();
}
END_TEST

Suite *pico_suite(void)
{
  Suite *s = suite_create("PicoTCP");

  TCase *ipv4 = tcase_create("IPv4");
  TCase *icmp = tcase_create("ICMP4");
  TCase *dhcp = tcase_create("DHCP");
  TCase *dns = tcase_create("DNS");
  TCase *rb = tcase_create("RB TREE");
  TCase *socket = tcase_create("SOCKET");
  TCase *nat = tcase_create("NAT");
  TCase *ipfilter = tcase_create("IPFILTER");
#ifdef PICO_SUPPORT_CRC
  TCase *crc = tcase_create("CRC");
#endif
#ifdef PICO_SUPPORT_MCAST
  TCase *igmp = tcase_create("IGMP");
#endif
  TCase *frame = tcase_create("FRAME");
  TCase *timers = tcase_create("TIMERS");

  tcase_add_test(ipv4, test_ipv4);
  suite_add_tcase(s, ipv4);

  tcase_add_test(icmp, test_icmp4_ping);
  tcase_add_test(icmp, test_icmp4_incoming_ping);
  tcase_add_test(icmp, test_icmp4_unreachable_send);
  tcase_add_test(icmp, test_icmp4_unreachable_recv);
  suite_add_tcase(s, icmp);

  /* XXX: rewrite test_dhcp_client due to architectural changes to support multiple devices */
  //tcase_add_test(dhcp, test_dhcp_client);
  tcase_add_test(dhcp, test_dhcp_client_api);

  tcase_add_test(dhcp, test_dhcp_server_ipinarp);
  tcase_add_test(dhcp, test_dhcp_server_ipninarp);
  tcase_add_test(dhcp,test_dhcp_server_api);
  tcase_add_test(dhcp, test_dhcp);
  suite_add_tcase(s, dhcp);

  tcase_add_test(dns, test_dns);
  suite_add_tcase(s, dns);

  tcase_add_test(rb, test_rbtree);
  tcase_set_timeout(rb, 10);
  suite_add_tcase(s, rb);

  tcase_add_test(socket, test_socket);
  suite_add_tcase(s, socket);

  tcase_add_test(nat, test_nat_enable_disable);
  tcase_add_test(nat, test_nat_translation);
  tcase_add_test(nat, test_nat_port_forwarding);
  tcase_set_timeout(nat, 10);
  suite_add_tcase(s, nat);

  tcase_add_test(ipfilter, test_ipfilter);
  suite_add_tcase(s, ipfilter);

#ifdef PICO_SUPPORT_CRC
  tcase_add_test(crc, test_crc_check);
  suite_add_tcase(s, crc);
#endif

#ifdef PICO_SUPPORT_MCAST
  tcase_add_test(igmp, test_igmp_sockopts);
  suite_add_tcase(s, igmp);
#endif

  tcase_add_test(frame, test_frame);
  suite_add_tcase(s, frame);

  tcase_add_test(timers, test_timers);
  suite_add_tcase(s, timers);

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
