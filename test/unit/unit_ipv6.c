
#ifdef PICO_SUPPORT_IPV6
START_TEST (test_ipv6)
{
    char ipstr[40] = {
        0
    };
    char ipstr0[] = "2001:0db8:130f:0000:0000:09c0:876a:130b";
    char ipstr0_t[] = "2001:0db8:130f:0000:0000:09c0:876a:130b";
    char ipstr1[] = "2001:db8:130f:0000:0000:09c0:876a:130b";
    char ipstr1_t[] = "2001:0db8:130f:0000:0000:09c0:876a:130b";
    char ipstr2[] = "2001:b8:130f:0000:0000:09c0:876a:130b";
    char ipstr2_t[] = "2001:00b8:130f:0000:0000:09c0:876a:130b";
    char ipstr3[] = "2001:8:130f:0000:0000:09c0:876a:130b";
    char ipstr3_t[] = "2001:0008:130f:0000:0000:09c0:876a:130b";
    char ipstr4[] = "2001:8:130f:0:0:09c0:876a:130b";
    char ipstr4_t[] = "2001:0008:130f:0000:0000:09c0:876a:130b";
    char ipstr5[] = "2001::8:130f:09c0:876a:130b";
    char ipstr5_t[] = "2001:0000:0000:0008:130f:09c0:876a:130b";
    char ipstr6[] = "2001::8:09c0:876a:130b";
    char ipstr6_t[] = "2001:0000:0000:0000:0008:09c0:876a:130b";
    char ipstr7[] = "2001::8:876a:130b";
    char ipstr7_t[] = "2001:0000:0000:0000:0000:0008:876a:130b";
    char ipstr8[] = "2001::876a:130b";
    char ipstr8_t[] = "2001:0000:0000:0000:0000:0000:876a:130b";
    char ipstr9[] = "ff01::1";
    char ipstr9_t[] = "ff01:0000:0000:0000:0000:0000:0000:0001";
    char ipstr10[] = "::1";
    char ipstr10_t[] = "0000:0000:0000:0000:0000:0000:0000:0001";
    char ipstr11[] = "fe80::";
    char ipstr11_t[] = "fe80:0000:0000:0000:0000:0000:0000:0000";
    char ipstr12[] = "::";
    char ipstr12_t[] = "0000:0000:0000:0000:0000:0000:0000:0000";
    char ipstr13[] = "2001:8:130f::09c0::130b"; /* invalid */
    char ipstr14[] = "2001:8:xxxx::09c0:130b"; /* invalid */
    char ipstr15[] = "2001:8:$$$$::09c0:130b"; /* invalid */
    char ipstr16[] = "2001:8:!@#$::%^&*:()0b"; /* invalid */
    char ipstr17[] = "2001:1"; /* invalid */
    char ipstr18[] = "20010db8:130f:0000:0000:09c0:876a:130b"; /* invalid */
    char ipstr19[] = "20010db8130f0000000009c0876a130b"; /* invalid */
    char ipstr20[] = "2001;0db8;130f;0000;0000;09c0;876a;130b"; /* invalid */
    uint8_t iphex0[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex1[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex2[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex3[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0x08, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex4[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0x08, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex5[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x13, 0x0f, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex6[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex7[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex8[PICO_SIZE_IP6] = {
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0x6a, 0x13, 0x0b
    };
    uint8_t iphex9[PICO_SIZE_IP6] = {
        0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    uint8_t iphex10[PICO_SIZE_IP6] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    uint8_t iphex11[PICO_SIZE_IP6] = {
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t iphex12[PICO_SIZE_IP6] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    struct pico_ip6 iphex_a = {{ 0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }};
    struct pico_ip6 iphex_r = {{ 0x40, 0x02, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }};
    struct pico_ip6 iphex_gw = {{ 0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f }};
    struct pico_ip6 nm64 = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    struct pico_ip6 nm128 = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};
    struct pico_ip6 ipaddr = {{0}};

    struct pico_ip6 _gw, r[IP_TST_SIZ], a[IP_TST_SIZ], gw[IP_TST_SIZ], *source[IP_TST_SIZ];
    struct pico_device *dev[IP_TST_SIZ];
    struct pico_ipv6_link *l[IP_TST_SIZ];
    struct pico_ipv6_link *_link = NULL;
    struct pico_ipv6_route *_route = NULL;
    char devname[8];
    int ret = 0;
    int i = 0;

    pico_stack_init();

    /* pico_string_to_ipv6 and pico_ipv6_to_string */
    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr0);
    pico_string_to_ipv6(ipstr0, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex0, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr0_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr1);
    pico_string_to_ipv6(ipstr1, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex1, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr1_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr2);
    pico_string_to_ipv6(ipstr2, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex2, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr2_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr3);
    pico_string_to_ipv6(ipstr3, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex3, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr3_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr4);
    pico_string_to_ipv6(ipstr4, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex4, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr4_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr5);
    pico_string_to_ipv6(ipstr5, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex5, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr5_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr6);
    pico_string_to_ipv6(ipstr6, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex6, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr6_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr7);
    pico_string_to_ipv6(ipstr7, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex7, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr7_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr8);
    pico_string_to_ipv6(ipstr8, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex8, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr8_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr9);
    pico_string_to_ipv6(ipstr9, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex9, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr9_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr10);
    pico_string_to_ipv6(ipstr10, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex10, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr10_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr11);
    pico_string_to_ipv6(ipstr11, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex11, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr11_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 valid conversion of %s\n", ipstr12);
    pico_string_to_ipv6(ipstr12, ipaddr.addr);
    fail_if(memcmp(ipaddr.addr, iphex12, PICO_SIZE_IP6), "Error string to ipv6");
    pico_ipv6_to_string(ipstr, ipaddr.addr);
    printf("pico_ipv6_to_string valid conversion to %s\n", ipstr);
    fail_if(strncmp(ipstr, ipstr12_t, 40) != 0, "Error ipv6 to string");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr13);
    ret = pico_string_to_ipv6(ipstr13, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr14);
    ret = pico_string_to_ipv6(ipstr14, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr15);
    ret = pico_string_to_ipv6(ipstr15, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr16);
    ret = pico_string_to_ipv6(ipstr16, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr17);
    ret = pico_string_to_ipv6(ipstr17, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr18);
    ret = pico_string_to_ipv6(ipstr18, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr19);
    ret = pico_string_to_ipv6(ipstr19, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    printf("pico_string_to_ipv6 invalid conversion of %s\n", ipstr20);
    ret = pico_string_to_ipv6(ipstr20, ipaddr.addr);
    fail_if(ret == 0, "Error string to ipv6");

    /*link_add*/
    for (i = 0; i < 10; ++i) {
        snprintf(devname, 8, "nul%d", i);
        dev[i] = pico_null_create(devname);
        a[i] = iphex_a;
        a[i].addr[4] += i;
        fail_if(pico_ipv6_link_add(dev[i], a[i], nm64) == NULL, "Error adding link");
    }
    /*link_find + link_get + route_add*/
    for (i = 0; i < 10; ++i) {
        gw[i] = iphex_gw;
        gw[i].addr[4] += i;
        fail_unless(pico_ipv6_link_find(&a[i]) == dev[i], "Error finding link");
        l[i] = pico_ipv6_link_get(&a[i]);
        fail_if(l[i] == NULL, "Error getting link");
        r[i] = iphex_r;
        r[i].addr[4] += i;
        fail_if(pico_ipv6_route_add(r[i], nm128, a[i], 1, l[i]) != 0, "Error adding route");
    }
    /*get_gateway*/
    for (i = 0; i < 10; i++) {
        _gw = pico_ipv6_route_get_gateway(&r[i]);
        fail_if(memcmp(_gw.addr, a[i].addr, PICO_SIZE_IP6) != 0, "Error get gateway: returned wrong route");
        source[i] = pico_ipv6_source_find(&r[i]);
        fail_if(memcmp(source[i]->addr, a[i].addr, PICO_SIZE_IP6) != 0, "Error find source: returned wrong route");
    }
    /*route_del + link_del*/
    for (i = 0; i < 10; i++) {
        fail_if(pico_ipv6_route_del(r[i], nm128, a[i], 1, l[i]) != 0, "Error deleting route");
        fail_if(pico_ipv6_link_del(dev[i], a[i]) != 0, "Error deleting link");
    }
    /* add 2 links to dev[0] */
    _link = pico_ipv6_link_add(dev[0], a[0], nm64);
    fail_if (!_link, "Error adding link");
    _link = pico_ipv6_link_add(dev[0], a[1], nm64);
    fail_if (!_link, "Error adding link");
    /* add 2 routes to each of the links */
    ret = pico_ipv6_route_add(r[0], nm128, a[0], 1, l[0]);
    fail_if(ret != 0, "Error adding route");
    ret = pico_ipv6_route_add(r[1], nm128, a[0], 1, l[0]);
    fail_if(ret != 0, "Error adding route");
    ret = pico_ipv6_route_add(r[2], nm128, a[1], 1, l[1]);
    fail_if(ret != 0, "Error adding route");
    ret = pico_ipv6_route_add(r[3], nm128, a[1], 1, l[1]);
    fail_if(ret != 0, "Error adding route");

    /* add 2 links to dev[1] */
    _link = pico_ipv6_link_add(dev[1], a[8], nm64);
    fail_if (!_link, "Error adding link");
    _link = pico_ipv6_link_add(dev[1], a[9], nm64);
    fail_if (!_link, "Error adding link");
    /* add 2 routes to each of the links */
    ret = pico_ipv6_route_add(r[6], nm128, a[8], 1, l[8]);
    fail_if(ret != 0, "Error adding route");
    ret = pico_ipv6_route_add(r[7], nm128, a[8], 1, l[8]);
    fail_if(ret != 0, "Error adding route");
    ret = pico_ipv6_route_add(r[8], nm128, a[9], 1, l[9]);
    fail_if(ret != 0, "Error adding route");
    ret = pico_ipv6_route_add(r[9], nm128, a[9], 1, l[9]);
    fail_if(ret != 0, "Error adding route");

    /* destroy device, should clean up all links and routes */
    pico_device_destroy(dev[0]);
    _link = pico_ipv6_link_get(&a[0]);
    fail_if(_link != NULL, "Error destroying device");
    _link = pico_ipv6_link_get(&a[1]);
    fail_if(_link != NULL, "Error destroying device");
    _link = pico_ipv6_link_get(&a[8]);
    fail_if(_link == NULL, "Error destroying device");
    _link = pico_ipv6_link_get(&a[9]);
    fail_if(_link == NULL, "Error destroying device");

    _route = pico_ipv6_route_find(&r[0]);
    fail_if(_route != NULL, "Error destroying device");
    _route = pico_ipv6_route_find(&r[1]);
    fail_if(_route != NULL, "Error destroying device");
    _route = pico_ipv6_route_find(&r[2]);
    fail_if(_route != NULL, "Error destroying device");
    _route = pico_ipv6_route_find(&r[3]);
    fail_if(_route != NULL, "Error destroying device");

    _route = pico_ipv6_route_find(&r[6]);
    fail_if(_route == NULL, "Error destroying device");
    _route = pico_ipv6_route_find(&r[7]);
    fail_if(_route == NULL, "Error destroying device");
    _route = pico_ipv6_route_find(&r[8]);
    fail_if(_route == NULL, "Error destroying device");
    _route = pico_ipv6_route_find(&r[9]);
    fail_if(_route == NULL, "Error destroying device");
}
END_TEST

#ifdef PICO_SUPPORT_MCAST
START_TEST (test_mld_sockopts)
{
    int i = 0, j = 0, k = 0, ret = 0;
    struct pico_socket *s, *s1 = NULL;
    struct pico_device *dev = NULL;
    union pico_address *source = NULL;
    union pico_address inaddr_dst = {
        {0}
    }, inaddr_incorrect = {
        {0}
    }, inaddr_uni = {
        {0}
    }, inaddr_null = {
        {0}
    };
    struct pico_ip6 netmask = {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};

    union pico_address inaddr_link[2] = {{0}};
    union pico_address inaddr_mcast[8] = {{0}};
    union pico_address inaddr_source[8] = {{0}};
    struct pico_ip_mreq _mreq = {{0}}, mreq[16] = {{{0}}};
    struct pico_ip_mreq_source mreq_source[128] = {{{0}}};
    struct pico_tree_node *index = NULL;

    int ttl = 64;
    int getttl = 0;
    int loop = 9;
    int getloop = 0;
    struct pico_ip6 mcast_default_link = {
        0
    };

    pico_stack_init();

    printf("START MLD SOCKOPTS TEST\n");

    pico_string_to_ipv6("ff00:0:0:0:0:0:e007:707", inaddr_dst.ip6.addr);
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:2", inaddr_uni.ip6.addr);
    pico_string_to_ipv6("ff00:0:0:0:0:0:e008:808", inaddr_incorrect.ip6.addr);
    pico_string_to_ipv6("::", inaddr_null.ip6.addr);

    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:0001", inaddr_link[0].ip6.addr); /* 0 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a32:0001", inaddr_link[1].ip6.addr); /* 1 */

    pico_string_to_ipv6("ff00:0:0:0:0:0:e801:100", inaddr_mcast[0].ip6.addr); /* 0 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e802:201", inaddr_mcast[1].ip6.addr); /* 1 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e803:302", inaddr_mcast[2].ip6.addr); /* 2 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e803:403", inaddr_mcast[3].ip6.addr); /* 3 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e803:504", inaddr_mcast[4].ip6.addr); /* 4 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e803:605", inaddr_mcast[5].ip6.addr); /* 5 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e803:706", inaddr_mcast[6].ip6.addr); /* 6 */
    pico_string_to_ipv6("ff00:0:0:0:0:0:e803:807", inaddr_mcast[7].ip6.addr); /* 7 */

    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:100", inaddr_source[0].ip6.addr); /* 0 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:101", inaddr_source[1].ip6.addr); /* 1 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:102", inaddr_source[2].ip6.addr); /* 2 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:103", inaddr_source[3].ip6.addr); /* 3 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:104", inaddr_source[4].ip6.addr); /* 4 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:105", inaddr_source[5].ip6.addr); /* 5 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:106", inaddr_source[6].ip6.addr); /* 6 */
    pico_string_to_ipv6("fe80:0:0:0:0:0:a28:107", inaddr_source[7].ip6.addr); /* 7 */

    /* 00 01 02 03 04 05 06 07 | 10 11 12 13 14 15 16 17 */
    for (i = 0; i < 16; i++) {
        mreq[i].mcast_link_addr= inaddr_link[i / 8];
        mreq[i].mcast_group_addr= inaddr_mcast[i % 8];
    }
    /* 000 001 002 003 004 005 006 007 | 010 011 012 013 014 015 016 017  */
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            /* printf(">>>>> mreq_source[%d]: link[%d] mcast[%d] source[%d]\n", (i*8)+j, i/8, i%8, j); */
            mreq_source[(i * 8) + j].mcast_link_addr = inaddr_link[i / 8];
            mreq_source[(i * 8) + j].mcast_group_addr= inaddr_mcast[i % 8];
            mreq_source[(i * 8) + j].mcast_source_addr= inaddr_source[j];
        }
    }

    dev = pico_null_create("dummy0");
    ret = pico_ipv6_link_add(dev, inaddr_link[0].ip6, netmask);
    fail_if(ret == NULL, "link add failed");
    dev = pico_null_create("dummy1");
    ret = pico_ipv6_link_add(dev, inaddr_link[1].ip6, netmask);
    fail_if(ret == NULL, "link add failed");


    s = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, NULL);
    fail_if(s == NULL, "UDP socket open failed");
    s1 = pico_socket_open(PICO_PROTO_IPV6, PICO_PROTO_UDP, NULL);
    fail_if(s1 == NULL, "UDP socket open failed");


    /* argument validation tests */
    printf("MLD SETOPTION ARGUMENT VALIDATION TEST\n");
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
    fail_if(ret < 0, "supported PICO_IP_MULTICAST_LOOP failed disabling\n");
    ret = pico_socket_getoption(s, PICO_IP_MULTICAST_LOOP, &getloop);
    fail_if(ret < 0, "supported PICO_IP_MULTICAST_LOOP failed getting value\n");
    fail_if(getloop != loop, "setoption loop != getoption loop\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_dst.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_link[0].ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
    fail_if(ret < 0, "supported PICO_IP_ADD_MEMBERSHIP failed\n");
    ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
    fail_if(ret < 0, "supported PICO_IP_DROP_MEMBERSHIP failed\n");
    memcpy(&_mreq.mcast_group_addr ,&inaddr_dst.ip6 , sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr  ,&inaddr_null.ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
    fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed with valid NULL (use default) link address\n");
    ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
    fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed with valid NULL (use default) link address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_uni.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_link[0].ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded with invalid (unicast) group address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_null.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_link[0].ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded with invalid (NULL) group address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_dst.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_uni.ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_ADD_MEMBERSHIP succeeded with invalid link address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_incorrect.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_link[0].ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (not added) group address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_uni.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_link[0].ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (unicast) group address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_null.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_link[0].ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (NULL) group address\n");
    memcpy(&_mreq.mcast_group_addr, &inaddr_dst.ip6, sizeof(struct pico_ip6));
    memcpy(&_mreq.mcast_link_addr, &inaddr_uni.ip6, sizeof(struct pico_ip6));
    ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &_mreq);
    fail_if(ret == 0, "PICO_IP_DROP_MEMBERSHIP succeeded with invalid (unicast) link address\n");
    /* flow validation tests */
    printf("MLD SETOPTION FLOW VALIDATION TEST\n");
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

    printf("MLD SETOPTION STRESS TEST\n");
    for (k = 0; k < 2; k++) {
        /* ADD for even combinations of group and link, ADD_SOURCE for uneven */
        for (i = 0; i < 16; i++) {
            if (i % 2) {
                ret = pico_socket_setoption(s, PICO_IP_ADD_MEMBERSHIP, &mreq[i]);
                fail_if(ret < 0, "PICO_IP_ADD_MEMBERSHIP failed\n");
                for (j = 0; j < 8; j++) {
                    ret = pico_socket_setoption(s, PICO_IP_BLOCK_SOURCE, &mreq_source[(i * 8) + j]);
                    fail_if(ret < 0, "PICO_IP_BLOCK_SOURCE failed\n");
                }
            } else {
                for (j = 0; j < 8; j++) {
                    ret = pico_socket_setoption(s, PICO_IP_ADD_SOURCE_MEMBERSHIP, &mreq_source[(i * 8) + j]);
                    fail_if(ret < 0, "PICO_IP_ADD_SOURCE_MEMBERSHIP failed\n");
                }
            }
        }
        /* UNBLOCK and DROP for even combinations, DROP_SOURCE for uneven */
        for (i = 0; i < 16; i++) {
            if (i % 2) {
                for (j = 0; j < 8; j++) {
                    ret = pico_socket_setoption(s, PICO_IP_UNBLOCK_SOURCE, &mreq_source[(i * 8) + j]);
                    fail_if(ret < 0, "PICO_IP_UNBLOCK_SOURCE failed\n");
                }
                ret = pico_socket_setoption(s, PICO_IP_DROP_MEMBERSHIP, &mreq[i]);
                fail_if(ret < 0, "PICO_IP_DROP_MEMBERSHIP failed\n");
            } else {
                for (j = 0; j < 8; j++) {
                    ret = pico_socket_setoption(s, PICO_IP_DROP_SOURCE_MEMBERSHIP, &mreq_source[(i * 8) + j]);
                    fail_if(ret < 0, "PICO_IP_DROP_SOURCE_MEMBERSHIP failed\n");
                }
            }
        }
        /* everything should be cleanup up, next iteration will fail if not */
    }

    /* filter validation tests */
    printf("MLD SETOPTION FILTER VALIDATION TEST\n");
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
        if (memcmp(&source->ip6,&mreq_source[0].mcast_source_addr, sizeof(struct pico_ip6))==0) { /* OK */
        }
        else if (memcmp(&source->ip6, &mreq_source[1].mcast_source_addr, sizeof(struct pico_ip6))==0) { /* OK */
        }
        else {
            fail("MCASTFilter (INCLUDE + INCLUDE) incorrect\n");
        }
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
        if (memcmp(&source->ip6, &mreq_source[2].mcast_source_addr,sizeof(struct pico_ip6)) == 0) { /* OK */
        }
        else {
            fail("MCASTFilter (INCLUDE + EXCLUDE) incorrect\n");
        }
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
        if (memcmp(&source->ip6, &mreq_source[0].mcast_source_addr, sizeof(struct pico_ip6)) == 0) { /* OK */
        }
        else if (memcmp(&source->ip6, &mreq_source[1].mcast_source_addr, sizeof(struct pico_ip6)) == 0) { /* OK */
        }
        else {
            fail("MCASTFilter (EXCLUDE + INCLUDE) incorrect\n");
        }
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
        if (memcmp(&source->ip6,&mreq_source[3].mcast_source_addr, sizeof(struct pico_ip6)==0)) { /* OK */
        }
        else if (memcmp(&source->ip6,&mreq_source[4].mcast_source_addr, sizeof(struct pico_ip6)) == 0) { /* OK */
        }
        else {
            fail("MCASTFilter (EXCLUDE + EXCLUDE) incorrect\n");
        }
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


#endif
