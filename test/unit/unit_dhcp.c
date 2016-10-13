
static struct pico_dhcp_client_cookie*dhcp_client_ptr;

void callback_dhcpclient(void*cli, int code);
int generate_dhcp_msg(uint8_t *buf, uint32_t *len, uint8_t type);

void callback_dhcpclient(void*cli, int code)
{
    struct pico_ip4 gateway;
    char gw_txt_addr[30];
    IGNORE_PARAMETER(cli);

    if(code == PICO_DHCP_SUCCESS) {
        gateway = pico_dhcp_get_gateway(&dhcp_client_ptr);
        pico_ipv4_to_string(gw_txt_addr, gateway.addr);
    }

    printf("callback happened with code %d!\n", code);
}

int generate_dhcp_msg(uint8_t *buf, uint32_t *len, uint8_t type)
{
    if(type == DHCP_MSG_TYPE_DISCOVER) {
        uint8_t buffer[] = {
            0x01, 0x01, 0x06, 0x00, 0x0c, 0x10,
            0x53, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc1, 0x00, 0x00, 0x0a, 0x0b, 0x0f, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x37, 0x07, 0x01,
            0x1c, 0x02, 0x03, 0x0c, 0x3a, 0x3b, 0x39, 0x02, 0x02, 0x40, 0xff, 0x00
        };
        *len = sizeof(buffer);
        memcpy(&(buf[0]), buffer, *len);
    }else if(type == DHCP_MSG_TYPE_OFFER) {
        return 1;
    }else if(type == DHCP_MSG_TYPE_REQUEST) {
        uint32_t i = 0;
        uint8_t buffer1[] = {
            /* 0x63,0x82,0x53,0x63,// MAGIC COOCKIE */
            /* 0x35,0x01,0x03,     // DHCP REQUEST */
            /* 0x36,0x04,0x00,0x00,0x00,0x00 // SERVER ID */
            0x32, 0x04, buf[0x3a], buf[0x3b], buf[0x3c], buf[0x3e], /* requested ip */
            0x37, 0x04, 0x01, 0x03, 0x06, 0x2a, /* Parameter list */
            0x3d, 0x07, 0x01, buf[0x06], buf[0x07], buf[0x08], buf[0x09], buf[0x0a], buf[0x0b], /* Client id */
            0xff
        };

        buf[0x02a] = 0x01; /* change to boot request */
        buf[0x11c] = 0x03; /* request */

        memcpy(&(buf[0x123]), &(buffer1[0]), sizeof(buffer1));
        *len = sizeof(buffer1) + 0x123;
        for(i = *len; i < 0x150; i++) {
            buf[i + 10] = 0x00;
        }
        return 0;
    }else if(type == DHCP_MSG_TYPE_ACK) {
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
    uint8_t macaddr1[6] = {
        0xc1, 0, 0, 0xa, 0xb, 0xf
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct pico_ip4 serverip = {
        .addr = long_be(0x0A28000A)
    };
    uint8_t buf[600] = {
        0
    };
    /* Declaration test 1 */
    struct pico_dhcp_server_setting s1 = {
        0
    };
    /* Declaration test 2 */
    struct pico_dhcp_server_setting s2 = {
        0
    };

    printf("*********************** starting %s * \n", __func__);

    /* Create mock device  */
    mock = pico_mock_create(macaddr1);
    fail_if(!mock, "MOCK DEVICE creation failed");
    fail_if(pico_mock_network_read(mock, buf, BUFLEN), "data on network that shouldn't be there");
    fail_if(pico_ipv4_link_add(mock->dev, serverip, netmask), "add link to mock device failed");

    /* test 0 */
    /* Clear error code */
    pico_err = PICO_ERR_NOERR;
    /* Test 0 statements */
    fail_unless(pico_dhcp_server_initiate(NULL), "DHCP_SERVER> initiate succeeded after pointer to dev == NULL");
    fail_unless(pico_err == PICO_ERR_EINVAL, "DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");

    /* test 1 */
    /* Clear error code */
    pico_err = PICO_ERR_NOERR;
    /* Store data in settings */
    s1.server_ip.addr = long_be(0x0A28000F); /* make sure this IP is not assigned */
    /* Test 1 statements */
    fail_unless(pico_dhcp_server_initiate(&s1), "DHCP_SERVER> initiate succeeded after pointer to dev == NULL");
    fail_unless(pico_err == PICO_ERR_EINVAL, "DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");

    /* test 2 */
    /* Clear error code */
    pico_err = PICO_ERR_NOERR;
    /* Store data in settings */
    s2.server_ip = serverip;
    /* Test 2 statements */
    fail_if(pico_dhcp_server_initiate(&s2), "DHCP_SERVER> failed after correct parameter");
}
END_TEST

START_TEST (test_dhcp)
{
/************************************************************************
 * Check if all states (offer, bound) are changed correctly
 *   and if response messages are replied correctly
 * Status : Done
 *************************************************************************/
    struct mock_device*mock;
    struct pico_dhcp_server_setting s = {
        0
    };
    struct pico_ip4 xid = {
        .addr = long_be(0x00003d1d)
    };
    uint8_t macaddr1[6] = {
        0xc1, 0, 0, 0xa, 0xb, 0xf
    };
    uint8_t macaddr2[6] = {
        0xc6, 0, 0, 0xa, 0xb, 0xf
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct pico_ip4 serverip = {
        .addr = long_be(0x0A28000A)
    };
    struct pico_socket sock = { };
    struct pico_dhcp_server_negotiation *dn = NULL;
    struct pico_ip4 *stored_ipv4 = NULL;
    uint32_t len = 0;
    int network_read = 0;
    uint8_t *buf;
    uint8_t printbufactive = 0;

    buf = PICO_ZALLOC(600);

    printf("*********************** starting %s * \n", __func__);

    /*Insert custom values in buffer*/
    fail_if(generate_dhcp_msg(buf, &len, DHCP_MSG_TYPE_DISCOVER), "DHCP_SERVER->failed to generate buffer");
    memcpy(&(buf[4]), &(xid.addr), sizeof(struct pico_ip4));
    memcpy(&(buf[28]), &(macaddr1[0]), sizeof(struct pico_ip4));
    printbuf(&(buf[0]), len, "DHCP-DISCOVER packet", printbufactive);

    /*Initiate test setup*/
    pico_stack_init();

    /* Create mock device  */
    mock = pico_mock_create(macaddr2);
    fail_if(!mock, "MOCK DEVICE creation failed");
    fail_if(pico_mock_network_read(mock, buf, BUFLEN), "data on network that shouldn't be there");
    fail_if(pico_ipv4_link_add(mock->dev, serverip, netmask), "add link to mock device failed");

    s.server_ip = serverip;

    fail_if(pico_dhcp_server_initiate(&s), "DHCP_SERVER> server initiation failed");

    dn = pico_dhcp_server_find_negotiation(xid.addr);
    fail_unless(dn == NULL, "DCHP SERVER -> negotiation data available befor discover msg recvd");

    /* simulate reception of a DISCOVER packet */
    sock.local_addr.ip4 = serverip;
    pico_dhcp_server_recv(&sock, buf, len);

    tick_it(3);

    /* check if negotiation data is stored */
    dn = pico_dhcp_server_find_negotiation(xid.addr);
    fail_if(dn == NULL, "DCHP SERVER -> no negotiation stored after discover msg recvd");

    /* check if new ip is in ARP cache */
    stored_ipv4 = pico_arp_reverse_lookup(&dn->hwaddr);
    fail_if(stored_ipv4 == NULL, "DCHP SERVER -> new address is not inserted in ARP");
    fail_unless(stored_ipv4->addr == dn->ciaddr.addr, "DCHP SERVER -> new ip not stored in negotiation data");

    /* check if state is changed and reply is received  */
    network_read = pico_mock_network_read(mock, buf, BUFLEN);
    fail_unless(network_read > 0, "received msg on network of %u bytes", network_read);
    printbuf(&(buf[0]), (uint32_t)network_read, "DHCP-OFFER msg", printbufactive);
    fail_unless(buf[0x011c] == 0x02, "No DHCP offer received after discovery");
    fail_unless(dn->state == PICO_DHCP_STATE_OFFER, "DCHP SERVER -> negotiation state not changed to OFFER");

    /*change offer to request*/
    fail_if(generate_dhcp_msg(buf, &len, DHCP_MSG_TYPE_REQUEST), "DHCP_SERVER->failed to generate buffer");
    printbuf(&(buf[0x2a]), len - 0x2a, "request buffer", printbufactive);

    /* simulate reception of a offer packet */
    pico_dhcp_server_recv(&sock, &(buf[0x2a]), len - 0x2a);
    fail_unless(dn->state == PICO_DHCP_STATE_BOUND, "DCHP SERVER -> negotiation state not changed to BOUND");

    tick_it(3);

    /* check if state is changed and reply is received  */
    do {
        network_read = pico_mock_network_read(mock, buf, BUFLEN);
    } while (buf[0] == 0x33);
    printf("Received message: %d bytes\n", network_read);
    fail_unless(network_read > 0, "received msg on network of %d bytes", network_read);
    printbuf(&(buf[0]), (uint32_t)network_read, "DHCP-ACK msg", printbufactive);
    fail_unless(buf[0x11c] == 0x05, "No DHCP ACK received after discovery");
}
END_TEST


START_TEST (test_dhcp_server_ipninarp)
{
/************************************************************************
 * Check if dhcp recv works correctly if
 *     MAC address of client is not in arp table yet
 * Status : Done
 *************************************************************************/
    struct mock_device*mock;
    struct pico_dhcp_server_setting s = {
        0
    };
    struct pico_ip4 xid = {
        .addr = long_be(0x00003d1d)
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct pico_ip4 serverip = {
        .addr = long_be(0x0A28000A)
    };
    struct pico_socket sock = { };
    struct pico_dhcp_server_negotiation *dn = NULL;
    struct pico_ip4 *stored_ipv4 = NULL;
    unsigned char macaddr1[6] = {
        0xc1, 0, 0, 0xa, 0xb, 0xf
    };
    uint32_t len = 0;
    uint8_t buf[600] = {
        0
    };
    uint8_t printbufactive = 0;

    printf("*********************** starting %s * \n", __func__);

    /*Insert custom values in buffer*/
    fail_if(generate_dhcp_msg(buf, &len, DHCP_MSG_TYPE_DISCOVER), "DHCP_SERVER->failed to generate buffer");
    memcpy(&(buf[4]), &(xid.addr), sizeof(struct pico_ip4));
    memcpy(&(buf[28]), &(macaddr1[0]), sizeof(struct pico_ip4));
    printbuf(&(buf[0]), len, "DHCP-DISCOVER packet", printbufactive);

    /*Initiate test setup*/
    pico_stack_init();

    /* Create mock device  */
    mock = pico_mock_create(macaddr1);
    fail_if(!mock, "MOCK DEVICE creation failed");
    fail_if(pico_mock_network_read(mock, buf, BUFLEN), "data on network that shouldn't be there");
    fail_if(pico_ipv4_link_add(mock->dev, serverip, netmask), "add link to mock device failed");
    s.server_ip = serverip;

    fail_if(pico_dhcp_server_initiate(&s), "DHCP_SERVER> server initiation failed");

    dn = pico_dhcp_server_find_negotiation(xid.addr);
    fail_unless(dn == NULL, "DCHP SERVER -> negotiation data available before discover msg recvd");

    /* simulate reception of a DISCOVER packet */
    sock.local_addr.ip4 = serverip;
    pico_dhcp_server_recv(&sock, buf, len);

    /* check if negotiation data is stored */
    dn = pico_dhcp_server_find_negotiation(xid.addr);
    fail_if(dn == NULL, "DCHP SERVER -> no negotiation stored after discover msg recvd");

    /* check if new ip is in ARP cache */
    stored_ipv4 = pico_arp_reverse_lookup(&dn->hwaddr);
    fail_if(stored_ipv4 == NULL, "DCHP SERVER -> new address is not inserted in ARP");
    fail_unless(stored_ipv4->addr == dn->ciaddr.addr, "DCHP SERVER -> new ip not stored in negotiation data");

    /* check if new ip is in ARP cache */
    fail_if(pico_arp_reverse_lookup(&dn->hwaddr) == NULL, "DCHP SERVER -> new address is not inserted in ARP");
}
END_TEST

START_TEST (test_dhcp_server_ipinarp)
{
/************************************************************************
 * Check if dhcp recv works correctly if
 *     MAC address of client is allready in arp table
 * Status : Done
 *************************************************************************/
    struct mock_device*mock;
    struct pico_dhcp_server_setting s = {
        0
    };
    struct pico_ip4 ipv4address = {
        .addr = long_be(0x0a280067)
    };
    struct pico_ip4 xid = {
        .addr = long_be(0x00003d1d)
    };
    struct pico_ip4 netmask = {
        .addr = long_be(0xffffff00)
    };
    struct pico_ip4 serverip = {
        .addr = long_be(0x0A28000A)
    };
    struct pico_socket sock = { };
    struct pico_ip4 *stored_ipv4 = NULL;
    struct pico_dhcp_server_negotiation *dn = NULL;
    struct pico_eth *arp_resp = NULL;
    unsigned char macaddr1[6] = {
        0xc1, 0, 0, 0xa, 0xb, 0xf
    };
    uint32_t len = 0;
    uint8_t buf[600] = {
        0
    };

    printf("*********************** starting %s * \n", __func__);

    /*Insert custom values in buffer*/
    fail_if(generate_dhcp_msg(buf, &len, DHCP_MSG_TYPE_DISCOVER), "DHCP_SERVER->failed to generate buffer");
    memcpy(&(buf[28]), &(macaddr1[0]), sizeof(struct pico_ip4));
    memcpy(&(buf[4]), &(xid.addr), sizeof(struct pico_ip4));

    /* Create mock device  */
    mock = pico_mock_create(macaddr1);
    fail_if(!mock, "MOCK DEVICE creation failed");
    fail_if(pico_ipv4_link_add(mock->dev, serverip, netmask), "add link to mock device failed");
    s.server_ip = serverip;

    /*Initiate test setup*/
    pico_stack_init();
    pico_arp_create_entry(&(macaddr1[0]), ipv4address, s.dev);

    fail_if(pico_dhcp_server_initiate(&s), "DHCP_SERVER> server initiation failed");

    /* simulate reception of a DISCOVER packet */
    sock.local_addr.ip4 = serverip;
    pico_dhcp_server_recv(&sock, buf, len);

    /* check if negotiation data is stored */
    dn = pico_dhcp_server_find_negotiation(xid.addr);
    fail_if(dn == NULL, "DCHP SERVER -> no negotiation stored after discover msg recvd");

    /* check if new ip is in ARP cache */
    stored_ipv4 = pico_arp_reverse_lookup(&dn->hwaddr);
    fail_if(stored_ipv4 == NULL, "DCHP SERVER -> new address is not inserted in ARP");
    fail_unless(stored_ipv4->addr == dn->ciaddr.addr, "DCHP SERVER -> new ip not stored in negotiation data");

    /* check if new ip is in ARP cache */
    arp_resp = pico_arp_lookup(&ipv4address);
    fail_if(arp_resp == NULL, "DCHP SERVER -> address unavailable in arp cache");
}
END_TEST

#if 0
START_TEST (test_dhcp_client)
{
    struct mock_device*mock;
    uint32_t dhcp_hdr_offset = PICO_SIZE_ETHHDR + PICO_SIZE_IP4HDR + PICO_UDPHDR_SIZE;
    unsigned char macaddr1[6] = {
        0xc1, 0, 0, 0xa, 0xb, 0xf
    };
    struct pico_ip4 address = {
        0
    };
    struct pico_ip4 yiaddr = {
        .addr = long_be(0xC0A8000A)
    };
    struct pico_ip4 gateway = {
        0
    };
    struct pico_ip4 router = {
        .addr = long_be(0xC0A800FE)
    };
    uint8_t buf[BUFLEN] = {
        0
    };
    uint8_t offer_buf1[] = {
        0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x00, 0x01
    };
    uint8_t offer_buf2[] = {
        0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x02, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x3a, 0x04, 0x00, 0x00, 0x07, 0x08, 0x3b, 0x04, 0x00, 0x00, 0x0c, 0x4e, 0x33, 0x04, 0x00, 0x00, 0x0e, 0x10, 0x36, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0xff
    };
    uint8_t routeropt_buf[] = {
        PICO_DHCPOPT_ROUTER, 0x04, 0xC0, 0xA8, 0x00, 0xFE, 0xFF
    };
    int type = 0;
    uint8_t printbufactive = 0;
    uint32_t len = 0;
    uint32_t xid = 0;
    struct pico_dhcp_client_cookie *cli = NULL;

    pico_stack_init();

    /* Create mock device  */
    mock = pico_mock_create(macaddr1);
    fail_if(!mock, "MOCK DEVICE creation failed");
    fail_if(pico_mock_network_read(mock, buf, BUFLEN), "data on network that shouldn't be there");

    /* initiate negotiation -> change state to */
    pico_dhcp_initiate_negotiation(mock->dev, &callback_dhcpclient, &xid);
    cli = get_cookie_by_xid(xid);
    dhcp_client_ptr = cli;
    fail_if(cli == NULL, "initiate fail");
    fail_unless(cli->state == DHCPSTATE_DISCOVER, "Not in discover state after init negotiate");
    fail_if(pico_mock_network_read(mock, buf, BUFLEN), "data on network that shouldn't be there");

    /* push discover msg on network */
    tick_it(3);

    /* read discover message from network */
    len = pico_mock_network_read(mock, buf, BUFLEN );
    fail_unless(len, "No msg received on network!");
    printbuf(&(buf[0]), len, "DHCP-DISCOVER packet", printbufactive);
    fail_unless(buf[0x011c] == 0x01, "No DHCP Discover received after initiate negotiation");
    mock_print_protocol(buf);
    fail_if(pico_mock_network_read(mock, buf, BUFLEN), "data on network that shouldn't be there");

    /* check API access functions */
    address = pico_dhcp_get_address(cli);
    fail_unless(address.addr == 0, "Client address gets value at init -> should get it from dhcp server");

    gateway = pico_dhcp_get_gateway(cli);
    fail_unless(gateway.addr == 0, "Gateway gets value at init -> should get it from dhcp server ");

    /* Change received discovery msg to offer offer msg */
    buf[0x2a] = 0x02;
    memcpy(&(buf[0x3a]), &(offer_buf1[0]), sizeof(offer_buf1));
    memcpy(&(buf[0x3a]), &(yiaddr.addr), sizeof(struct pico_ip4));
    memcpy(&(buf[0x116]), &(offer_buf2[0]), sizeof(offer_buf2));
    memcpy(&(buf[0x13b]), &(routeropt_buf[0]), sizeof(routeropt_buf));
    memcpy(&(buf[0x13d]), &(router.addr), sizeof(struct pico_ip4));
    printbuf(&(buf[dhcp_hdr_offset]), len - dhcp_hdr_offset, "DHCP-OFFER message", printbufactive);

    /* generate dhcp type from msg */
    type = pico_dhcp_verify_and_identify_type(&(buf[dhcp_hdr_offset]), len - dhcp_hdr_offset, cli);
    fail_if(type == 0, "unkown DHCP type");

    /* simulate reception of a DHCP server offer */
    pico_dhcp_state_machine(type, cli, &(buf[dhcp_hdr_offset]), len - dhcp_hdr_offset);
    fail_if(cli->state == DHCPSTATE_DISCOVER, "still in discover state after dhcp server offer");
    fail_unless(cli->state == DHCPSTATE_REQUEST, "not in REQUEST state after dhcp server offer");

    address = pico_dhcp_get_address(cli);
    fail_unless(address.addr == yiaddr.addr, "Client address incorrect => yiaddr or pico_dhcp_get_address incorrect");
    gateway = pico_dhcp_get_gateway(cli);
    fail_unless(gateway.addr == router.addr, "Gateway incorrect! => routeroption or pico_dhcp_get_gateway incorrect");
    tick_it(3);

    len = pico_mock_network_read(mock, buf, BUFLEN);
    fail_unless(len, "received msg on network of %d bytes", len);
    printbuf(&(buf[0]), len, "DHCP-REQUEST packet", printbufactive);
    fail_unless(buf[0x011c] == 0x03, "No DHCP request received after offer");

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
    fail_unless(cli0 == NULL, "DHCP_CLIENT> initiate succeeded after pointer to dev == NULL");
    fail_unless(pico_err == PICO_ERR_EINVAL, "DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");

    /* test 1 */
    /* Clear error code */
    pico_err = PICO_ERR_NOERR;
    /* Test 1 statements */
    pico_dhcp_initiate_negotiation(NULL, &callback_dhcpclient, &xid1);
    cli1 = pico_dhcp_client_find_cookie(xid1);
    fail_unless(cli1 == NULL, "DHCP_CLIENT> initiate succeeded after pointer to dev == NULL");
    fail_unless(pico_err == PICO_ERR_EINVAL, "DHCP_SERVER> initiate succeeded without PICO_ERR_EINVAL after wrong parameter");

#if 0
    /* not testable since we do not have a stub for the pico_socket_sendto */
    /* Declaration test 2 */
    uint32_t xid2 = 0;
    struct pico_dhcp_client_cookie *cli2 = NULL;
    struct pico_device *dev2;
    struct mock_device *mock2 = NULL;

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
    fail_if(cli2 == NULL, "DHCP_CLIENT: error initiating: %s", strerror(pico_err));
    xid2 = pico_dhcp_initiate_negotiation(mock2->dev, &callback_dhcpclient);
    cli2 = get_cookie_by_xid(xid2);
    fail_if(cli2 == NULL, "DHCP_CLIENT: error initiating: %s", strerror(pico_err));
    xid2 = pico_dhcp_initiate_negotiation(dev2, &callback_dhcpclient);
    cli2 = get_cookie_by_xid(xid2);
    fail_if(cli2 == NULL, "DHCP_CLIENT: error initiating: %s", strerror(pico_err));
#endif
}
END_TEST
