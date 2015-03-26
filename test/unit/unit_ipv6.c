
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
#endif
