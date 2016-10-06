void cb_dns(char *ip, void *arg);

void cb_dns(char *ip, void *arg)
{
    if (!ip) {
        /* Error occured */
        printf("DNS error getaddr\n");
        return;
    }

    /* Do something */
    printf("DNS -> %s\n", ip);
    PICO_FREE(ip);
    if (arg)
        PICO_FREE(arg);
}


START_TEST (test_dns)
{
    int ret;
    char url[] = "www.google.com";
    char ip[]  = "8.8.4.4";
    struct pico_ip4 ns;

    ns.addr = long_be(0x0a00280a); /* 10.40.0.10 */

    pico_stack_init();

    printf("START DNS TEST\n");

    /* testing nameserver API */
    ret = pico_dns_client_nameserver(NULL, PICO_DNS_NS_ADD);
    fail_if(ret == 0, "dns> dns_client_nameserver add error");

    ret = pico_dns_client_nameserver(NULL, PICO_DNS_NS_DEL);
    fail_if(ret == 0, "dns> dns_client_nameserver del error");

    ret = pico_dns_client_nameserver(NULL, 99);
    fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

    ret = pico_dns_client_nameserver(NULL, 0xFF);
    fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

    ret = pico_dns_client_nameserver(&ns, PICO_DNS_NS_DEL); /* delete non added ns */
    fail_if(ret == 0, "dns> dns_client_nameserver del error");

    ret = pico_dns_client_nameserver(&ns, 99);
    fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

    ret = pico_dns_client_nameserver(&ns, PICO_DNS_NS_ADD); /* add correct one */
    fail_if(ret < 0, "dns> dns_client_nameserver add error: %s", strerror(pico_err));

    ret = pico_dns_client_nameserver(&ns, 99);
    fail_if(ret == 0, "dns> dns_client_nameserver wrong code");

    ret = pico_dns_client_nameserver(&ns, PICO_DNS_NS_DEL);
    fail_if(ret < 0, "dns> dns_client_nameserver del error: %s", strerror(pico_err));

    ret = pico_dns_client_nameserver(&ns, PICO_DNS_NS_ADD); /* add correct one */
    fail_if(ret < 0, "dns> dns_client_nameserver add error: %s", strerror(pico_err));

    ret = pico_dns_client_nameserver(&ns, PICO_DNS_NS_ADD); /* add correct one again */
    fail_if(ret < 0, "dns> dns_client_nameserver add double failed");

    /* testing getaddr API */
    /* not testable since we do not have a stub for the pico_socket_send */
    /* ret = pico_dns_client_getaddr(url, cb_dns, NULL); / * ask correct one * / */
    /* fail_if(ret < 0, "dns> dns_client_getaddr: %s",strerror(pico_err)); */

    ret = pico_dns_client_getaddr(NULL, cb_dns, NULL);
    fail_if(ret == 0, "dns> dns_client_getaddr: no url");

    ret = pico_dns_client_getaddr(url, NULL, NULL);
    fail_if(ret == 0, "dns> dns_client_getaddr: no cb");

    /* testing getname API */
    /* not testable since we do not have a stub for the pico_socket_send */
    /* ret = pico_dns_client_getname(ip, cb_dns, NULL); / * ask correct one * / */
    /* fail_if(ret < 0, "dns> dns_client_getname: %s",strerror(pico_err)); */

    ret = pico_dns_client_getname(NULL, cb_dns, NULL);
    fail_if(ret == 0, "dns> dns_client_getname: no ip");

    ret = pico_dns_client_getname(ip, NULL, NULL);
    fail_if(ret == 0, "dns> dns_client_getname: no cb");
}
END_TEST
