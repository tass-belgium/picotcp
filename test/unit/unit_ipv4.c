
START_TEST (test_ipv4)
{
  #define IP_TST_SIZ 256
    uint32_t i;

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
        a[i].addr = long_be(0x0a000001u + (i << 16));
        d[i].addr = long_be(0x0a000002u + (i << 16));
        fail_if(pico_ipv4_link_add(dev[i], a[i], nm16) != 0, "Error adding link");
    }
    /*link_find + link_get + route_add*/
    for (i = 0; i < IP_TST_SIZ; i++) {
        gw[i].addr = long_be(0x0a0000f0u + (i << 16));
        r[i].addr = long_be(0x0c00001u + (i << 16));
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
    fail_if(ipaddr.addr != long_be(0xc0a80101), "Error string to ipv4");
    memset(ipstr, 0, 12);
    pico_ipv4_to_string(ipstr, ipaddr.addr);
    fail_if(strncmp(ipstr, "192.168.1.1", 11) != 0, "Error ipv4 to string");

    /*valid_netmask*/
    fail_if(pico_ipv4_valid_netmask(long_be(nm32.addr)) != 32, "Error checking netmask");

    /*is_unicast*/
    fail_if((pico_ipv4_is_unicast(long_be(0xc0a80101))) != 1, "Error checking unicast");
    fail_if((pico_ipv4_is_unicast(long_be(0xe0000001))) != 0, "Error checking unicast");

    /*rebound*/
    fail_if(pico_ipv4_rebound(f_NULL) != -1, "Error rebound frame");

    /*frame_push*/
    fail_if(pico_ipv4_frame_push(f_NULL, dst_NULL, PICO_PROTO_TCP) != -1, "Error push frame");
}
END_TEST

START_TEST (test_nat_enable_disable)
{
    struct pico_ipv4_link link = {
        .address = {.addr = long_be(0x0a320001)}
    };                                                                       /* 10.50.0.1 */
    struct pico_frame *f = pico_ipv4_alloc(&pico_proto_ipv4, NULL, PICO_UDPHDR_SIZE);
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
    struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
    const char *raw_data = "ello";

    net->vhl = 0x45; /* version = 4, hdr len = 5 (32-bit words) */
    net->tos = 0;
    net->len = short_be(32); /* hdr + data (bytes) */
    net->id = short_be(0x91c0);
    net->frag = short_be(0x4000); /* don't fragment flag, offset = 0 */
    net->ttl = 64;
    net->proto = 17; /* UDP */
    net->crc = 0;
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
    pico_ipv4_nat_table_cleanup(pico_tick, NULL);

    fail_if(pico_ipv4_nat_disable());
    fail_if(pico_ipv4_nat_is_enabled(&link.address));
}
END_TEST

START_TEST (test_nat_translation)
{
    struct pico_ipv4_link link = {
        .address = {.addr = long_be(0x0a320001)}
    };                                                                       /* 10.50.0.1 */
    struct pico_frame *f = pico_ipv4_alloc(&pico_proto_ipv4, NULL, PICO_UDPHDR_SIZE);
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
    struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
    struct pico_ip4 src_ori = {
        .addr = long_be(0x0a280008)
    };                                                      /* 10.40.0.8 */
    struct pico_ip4 dst_ori = {
        .addr = long_be(0x0a320009)
    };                                                      /* 10.50.0.9 */
    struct pico_ip4 nat = {
        .addr = long_be(0x0a320001)
    };                                                  /* 10.50.0.9 */
    const char *raw_data = "ello";
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
    pico_ipv4_nat_table_cleanup(pico_tick, NULL);

    fail_if(pico_ipv4_nat_disable());
}
END_TEST

START_TEST (test_nat_port_forwarding)
{
    struct pico_ipv4_link link = {
        .address = {.addr = long_be(0x0a320001)}
    };                                                                       /* 10.50.0.1 */
    struct pico_frame *f = pico_ipv4_alloc(&pico_proto_ipv4, NULL, PICO_UDPHDR_SIZE);
    struct pico_ipv4_hdr *net = (struct pico_ipv4_hdr *)f->net_hdr;
    struct pico_udp_hdr *udp = (struct pico_udp_hdr *)f->transport_hdr;
    struct pico_ip4 src_addr = {
        .addr = long_be(0x0a280008)
    };                                                       /* 10.40.0.8 */
    struct pico_ip4 dst_addr = {
        .addr = long_be(0x0a320009)
    };                                                       /* 10.50.0.9 */
    struct pico_ip4 nat_addr = {
        .addr = long_be(0x0a320001)
    };                                                       /* 10.50.0.9 */
    const char *raw_data = "ello";
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
    pico_ipv4_nat_table_cleanup(pico_tick, NULL);
}
END_TEST

START_TEST (test_ipfilter)
{
    struct pico_device *dev = NULL;
    uint8_t proto = 0, tos = 0;
    uint16_t sport = 0, dport = 0;
    int8_t priority = 0;
    int ret = 0;

    struct pico_ip4 src_addr = {
        0
    };
    struct pico_ip4 saddr_netmask = {
        0
    };
    struct pico_ip4 dst_addr = {
        0
    };
    struct pico_ip4 daddr_netmask = {
        0
    };

    enum filter_action action = 1;

    uint32_t filter_id1;

    /* 192.168.1.2:16415 -> 192.168.1.109:1222 [sending a TCP syn] */
    uint8_t ipv4_buf[] = {
        0x00, 0x02, 0xf7, 0xf1, 0x79, 0x33, 0xe0, 0xdb, 0x55,
        0xd4, 0xb6, 0x27, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0xf7, 0x0f, 0xc0,
        0xa8, 0x01, 0x02, 0xc0, 0xa8, 0x01, 0x6d, 0x40, 0x1f,
        0x04, 0xc6, 0x00, 0xb1, 0x56, 0x5a, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x02, 0x20, 0x00, 0x70, 0x32, 0x00, 0x00
    };

    struct pico_frame *f;

    printf("IP Filter> Adding a new filter...\n");
    filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, action);
    fail_if(filter_id1 <= 0, "Error adding filter\n");
    printf("filter_id1 = %d\n", filter_id1);

    printf("IP Filter> Trying to add the same filter...\n");
    filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, action);
    fail_if(ret > 0, "Error adding filter\n");

    printf("IP Filter> Deleting added filter...\n");
    ret = pico_ipv4_filter_del(filter_id1);
    fail_if(ret != 0, "Error deleting the filter\n");

    printf("IP Filter> Trying to delete the same filter\n");
    ret = pico_ipv4_filter_del(filter_id1);
    fail_if(ret != -1, "Deleting non existing filter failed\n");

    f = (struct pico_frame *)PICO_ZALLOC(200);
    f->buffer = PICO_ZALLOC(20);
    f->usage_count = PICO_ZALLOC(sizeof(uint32_t));
    f->buffer = ipv4_buf;
    f->net_hdr = ipv4_buf + 14u; /* shifting to IP layer */
    f->transport_hdr = ipv4_buf + 34u; /* shifting to Transport layer */

    /* adding exact filter */
    pico_string_to_ipv4("192.168.1.109", &src_addr.addr);
    pico_string_to_ipv4("255.255.255.255", &saddr_netmask.addr);
    sport = 1222u;
    filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, FILTER_REJECT);
    fail_if(filter_id1 <= 0, "Error adding exact filter\n");
    printf("Filter is added\n");
    sync();
    sleep(1);

    ret = ipfilter(f);
    fail_if(ret != 1, "Frame wasn't filtered\n");

    printf("IP Filter> Deleting added filter...\n");
    ret = pico_ipv4_filter_del(filter_id1);
    fail_if(ret != 0, "Error deleting the filter\n");

    printf("IP Filter> Adding masked filter...\n");
    pico_string_to_ipv4("192.168.1.7", &src_addr.addr);
    pico_string_to_ipv4("255.255.255.0", &saddr_netmask.addr);
    sport = 1222u;

    filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, FILTER_DROP);
    fail_if(filter_id1 <= 0, "Error adding masked filter\n");

    f = (struct pico_frame *)PICO_ZALLOC(200);
    f->buffer = PICO_ZALLOC(20);
    f->usage_count = PICO_ZALLOC(sizeof(uint32_t));
    f->buffer = ipv4_buf;
    f->net_hdr = ipv4_buf + 14u; /* shifting to IP layer */
    f->transport_hdr = ipv4_buf + 34u; /* shifting to Transport layer */
    ret = ipfilter(f);
    fail_if(ret != 1, "Mask filter failed to filter\n");

    printf("IP Filter> Deleting added filter...\n");
    ret = pico_ipv4_filter_del(filter_id1);
    fail_if(ret != 0, "Error deleting the filter\n");

    printf("IP Filter> Adding bad filter..\n");
    pico_string_to_ipv4("191.1.1.7", &src_addr.addr);
    pico_string_to_ipv4("255.255.255.0", &saddr_netmask.addr);
    sport = 1991u;
    filter_id1 = pico_ipv4_filter_add(dev, proto, &src_addr, &saddr_netmask, &dst_addr, &daddr_netmask, sport, dport, priority, tos, FILTER_DROP);
    fail_if(filter_id1 <= 0, "Error adding bad filter\n");

    f = (struct pico_frame *)PICO_ZALLOC(200);
    f->buffer = PICO_ZALLOC(20);
    f->usage_count = PICO_ZALLOC(sizeof(uint32_t));
    f->buffer = ipv4_buf;
    f->net_hdr = ipv4_buf + 14u; /* shifting to IP layer */
    f->transport_hdr = ipv4_buf + 34u; /* shifting to Transport layer */
    ret = ipfilter(f);
    fail_if(ret != 0, "Filter shouldn't have filtered this frame\n");

    printf("IP Filter> Deleting added filter...\n");
    ret = pico_ipv4_filter_del(filter_id1);
    fail_if(ret != 0, "Error deleting the filter\n");

}
END_TEST

#ifdef PICO_SUPPORT_MCAST
START_TEST (test_igmp_sockopts)
{
    int i = 0, j = 0, k = 0, ret = 0;
    struct pico_socket *s, *s1 = NULL;
    struct pico_device *dev = NULL;
    union pico_address *source = NULL;
    union pico_address inaddr_dst = {
        0
    }, inaddr_incorrect = {
        0
    }, inaddr_uni = {
        0
    }, inaddr_null = {
        0
    }, netmask = {
        0
    };
    union pico_address inaddr_link[2] = {0};
    union pico_address inaddr_mcast[8] = {0};
    union pico_address inaddr_source[8] = {0};
    struct pico_ip_mreq _mreq = {0}, mreq[16] = {0};
    struct pico_ip_mreq_source mreq_source[128] = {0};
    struct pico_tree_node *index = NULL;

    int ttl = 64;
    int getttl = 0;
    int loop = 9;
    int getloop = 0;
    union pico_address mcast_def_link = {
        0
    };

    pico_stack_init();

    printf("START IGMP SOCKOPTS TEST\n");

    pico_string_to_ipv4("224.7.7.7", &inaddr_dst.ip4.addr);
    pico_string_to_ipv4("10.40.0.2", &inaddr_uni.ip4.addr);
    pico_string_to_ipv4("224.8.8.8", &inaddr_incorrect.ip4.addr);
    pico_string_to_ipv4("0.0.0.0", &inaddr_null.ip4.addr);

    pico_string_to_ipv4("10.40.0.1", &inaddr_link[0].ip4.addr); /* 0 */
    pico_string_to_ipv4("10.50.0.1", &inaddr_link[1].ip4.addr); /* 1 */

    pico_string_to_ipv4("232.1.1.0", &inaddr_mcast[0].ip4.addr); /* 0 */
    pico_string_to_ipv4("232.2.2.1", &inaddr_mcast[1].ip4.addr); /* 1 */
    pico_string_to_ipv4("232.3.3.2", &inaddr_mcast[2].ip4.addr); /* 2 */
    pico_string_to_ipv4("232.4.4.3", &inaddr_mcast[3].ip4.addr); /* 3 */
    pico_string_to_ipv4("232.5.5.4", &inaddr_mcast[4].ip4.addr); /* 4 */
    pico_string_to_ipv4("232.6.6.5", &inaddr_mcast[5].ip4.addr); /* 5 */
    pico_string_to_ipv4("232.7.7.6", &inaddr_mcast[6].ip4.addr); /* 6 */
    pico_string_to_ipv4("232.8.8.7", &inaddr_mcast[7].ip4.addr); /* 7 */

    pico_string_to_ipv4("10.40.1.0", &inaddr_source[0].ip4.addr); /* 0 */
    pico_string_to_ipv4("10.40.1.1", &inaddr_source[1].ip4.addr); /* 1 */
    pico_string_to_ipv4("10.40.1.2", &inaddr_source[2].ip4.addr); /* 2 */
    pico_string_to_ipv4("10.40.1.3", &inaddr_source[3].ip4.addr); /* 3 */
    pico_string_to_ipv4("10.40.1.4", &inaddr_source[4].ip4.addr); /* 4 */
    pico_string_to_ipv4("10.40.1.5", &inaddr_source[5].ip4.addr); /* 5 */
    pico_string_to_ipv4("10.40.1.6", &inaddr_source[6].ip4.addr); /* 6 */
    pico_string_to_ipv4("10.40.1.7", &inaddr_source[7].ip4.addr); /* 7 */

    /* 00 01 02 03 04 05 06 07 | 10 11 12 13 14 15 16 17 */
    for (i = 0; i < 16; i++) {
        mreq[i].mcast_link_addr = inaddr_link[i / 8];
        mreq[i].mcast_group_addr = inaddr_mcast[i % 8];
    }
    /* 000 001 002 003 004 005 006 007 | 010 011 012 013 014 015 016 017  */
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            /* printf(">>>>> mreq_source[%d]: link[%d] mcast[%d] source[%d]\n", (i*8)+j, i/8, i%8, j); */
            mreq_source[(i * 8) + j].mcast_link_addr = inaddr_link[i / 8];
            mreq_source[(i * 8) + j].mcast_group_addr = inaddr_mcast[i % 8];
            mreq_source[(i * 8) + j].mcast_source_addr = inaddr_source[j];
        }
    }
    dev = pico_null_create("dummy0");
    netmask.ip4.addr = long_be(0xFFFF0000);
    ret = pico_ipv4_link_add(dev, inaddr_link[0].ip4, netmask.ip4);
    fail_if(ret < 0, "link add failed");

    dev = pico_null_create("dummy1");
    netmask.ip4.addr = long_be(0xFFFF0000);
    ret = pico_ipv4_link_add(dev, inaddr_link[1].ip4, netmask.ip4);
    fail_if(ret < 0, "link add failed");

    s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
    fail_if(s == NULL, "UDP socket open failed");
    s1 = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, NULL);
    fail_if(s1 == NULL, "UDP socket open failed");

    /* argument validation tests */
    printf("IGMP SETOPTION ARGUMENT VALIDATION TEST\n");
    ret = pico_socket_setoption(s, PICO_IP_MULTICAST_IF, &mcast_def_link);
    fail_if(ret == 0, "unsupported PICO_IP_MULTICAST_IF succeeded\n");
    ret = pico_socket_getoption(s, PICO_IP_MULTICAST_IF, &mcast_def_link);
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
        if (source->ip4.addr == mreq_source[0].mcast_source_addr.ip4.addr) { /* OK */
        }
        else if (source->ip4.addr == mreq_source[1].mcast_source_addr.ip4.addr) { /* OK */
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
        if (source->ip4.addr == mreq_source[2].mcast_source_addr.ip4.addr) { /* OK */
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
        if (source->ip4.addr == mreq_source[0].mcast_source_addr.ip4.addr) { /* OK */
        }
        else if (source->ip4.addr == mreq_source[1].mcast_source_addr.ip4.addr) { /* OK */
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
        if (source->ip4.addr == mreq_source[3].mcast_source_addr.ip4.addr) { /* OK */
        }
        else if (source->ip4.addr == mreq_source[4].mcast_source_addr.ip4.addr) { /* OK */
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

START_TEST (test_slaacv4)
{
    uint32_t tmp;
    struct pico_device *dev;
    struct mock_device *mock;
    char ip_addr[20];
    uint8_t macaddr1[6] = {
        0xc3, 0, 0, 0xa, 0xc, 0xf
    };



    /* verify min boundary*/
    tmp = SLAACV4_CREATE_IPV4(0);
    pico_ipv4_to_string(ip_addr, tmp);
    printf("IP address generated by slaac: %s\n", ip_addr);

    fail_if(long_be(tmp) < (long_be(SLAACV4_NETWORK) | SLAACV4_MINRANGE));

    /* verify max boundary*/
    tmp = SLAACV4_CREATE_IPV4(0x00FD);
    fail_if(long_be(tmp) > (long_be(SLAACV4_NETWORK) | 0x0000FEFF));

    /* verify case where dev->eth is NULL */
    dev = pico_null_create("dummy");
    tmp = pico_slaacv4_getip(dev, 0);
    fail_if(long_be(tmp) != (long_be(SLAACV4_NETWORK) | SLAACV4_MINRANGE));
    /* verify nominal case; two runs of slaacv4_get_ip need to return same value */
    mock = pico_mock_create(macaddr1);
    tmp = pico_slaacv4_getip(mock->dev, 0);
    fail_if(tmp != pico_slaacv4_getip(mock->dev, 0));

}
END_TEST
