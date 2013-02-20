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

#include "pico_dev_mock.c"
#include "pico_dev_tun.c"

START_TEST (test_ipv4)
{
  #define IP_TST_SIZ 256
  int i;

  struct pico_device *dev[IP_TST_SIZ];
  char devname[8];
  struct pico_ip4 a[IP_TST_SIZ], nm16, nm32, gw[IP_TST_SIZ], r[IP_TST_SIZ], ret;
  struct pico_ipv4_link *l[IP_TST_SIZ];

  pico_stack_init();

  nm16.addr = long_be(0xFFFF0000);
  nm32.addr = long_be(0xFFFFFFFF);
  for (i = 0; i < IP_TST_SIZ; i++) {
    snprintf(devname, 8, "nul%d", i);
    dev[i] = pico_null_create(devname);
    a[i].addr = long_be(0x0a000001 + (i << 16));
    pico_ipv4_link_add(dev[i], a[i], nm16);
  }

  for (i = 0; i < IP_TST_SIZ; i++) {
    gw[i].addr = long_be(0x0a0000f0 + (i << 16));
    r[i].addr = long_be(0x0c00001 + (i << 16));
    fail_unless(pico_ipv4_link_find(&a[i]) == dev[i], "pico_ipv4_link_find");
    l[i] = pico_ipv4_link_get(&a[i]);
    fail_if(l[i] == NULL, "Link not found...");
    fail_if(pico_ipv4_route_add(r[i], nm32, gw[i], 1, l[i]) != 0, "Error adding route");

  }
  for (i = 0; i < IP_TST_SIZ; i++) {
    ret = pico_ipv4_route_get_gateway(&r[i]);
    fail_if(ret.addr != gw[i].addr, "gw find: returned wrong route");
  }
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
  uint8_t printbufactive = 1;
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
  printf("address.addr = 0x%08x\n",long_be(address.addr));
  printf("yiaddr.addr = 0x%08x\n",long_be(yiaddr.addr));
  fail_unless(address.addr == yiaddr.addr,"Client address incorrect => yiaddr or pico_dhcp_get_address incorrect"); 
  gateway = pico_dhcp_get_gateway(cli);
  fail_unless(gateway.addr == router.addr,"Gateway incorrect! => routeroption or pico_dhcp_get_gateway incorrect"); 
  tick_it(3);

  len = pico_mock_network_read(mock, buf, BUFLEN);
  fail_unless(len,"received msg on network of %d bytes",len);
  printbuf(&(buf[0]),len,"DHCP-REQUEST packet",printbufactive);
  
}
END_TEST


Suite *pico_suite(void)
{
  Suite *s = suite_create("PicoTCP");

  TCase *ipv4 = tcase_create("IPv4");
  tcase_add_test(ipv4, test_ipv4);
  suite_add_tcase(s, ipv4);

	TCase *dhcp = tcase_create("DHCP");
	tcase_add_test(dhcp, test_dhcp_client);
	suite_add_tcase(s, dhcp);

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
