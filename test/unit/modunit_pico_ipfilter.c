#include "pico_ipv4.h"
#include "pico_config.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_ipfilter.h"
#include "pico_tcp.h"
#include "pico_udp.h"
#include "pico_tree.h"
#include "modules/pico_ipfilter.c"
#include "check.h"

Suite *pico_suite(void);
int pico_icmp4_packet_filtered(struct pico_frame *f)
{
    (void)f;
    return 0;
}

void pico_frame_discard(struct pico_frame *f)
{
    (void)f;
}

volatile pico_err_t pico_err;



START_TEST(tc_ipfilter)
{
    uint32_t r;
    struct filter_node a = {
        0
    }, b = {
        0
    };
    fail_if(filter_compare(&a, &b) != 0);


    /* a is rule, matching packet b */
    a.filter_id = 1;

    /* check that rule is matched properly */
    fail_if(filter_match_packet_find_rule(&a, &b) != &a);

    /* a has a out port that does not match packet */
    b.out_port = 8;
    a.out_port = 7;
    fail_if(filter_compare(&a, &b) == 0);

    /* a matches all ports */
    a.out_port = 0;
    fail_if(filter_compare(&a, &b) != 0);

    /*** NEXT TEST ***/


    /* a has a in port that does not match packet */
    b.in_port = 8;
    a.in_port = 7;
    fail_if(filter_compare(&a, &b) == 0);

    /* a matches all ports */
    a.in_port = 0;
    fail_if(filter_compare(&a, &b) != 0);

    /* a matches port exactly */
    a.in_port = 0;
    fail_if(filter_compare(&a, &b) != 0);

    /*** NEXT TEST ***/

    /* a matches all out addresses */
    b.out_addr = 0x010000a0;
    fail_if(filter_compare(&a, &b) != 0);

    /* a does not match b via 8-bit netmask */
    a.out_addr = 0x000000c0;
    a.out_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&a, &b) == 0);

    /* a does not match b at all*/
    a.out_addr = 0x020000b0;
    a.out_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&a, &b) == 0);

    /* a matches b via 8-bit netmask */
    a.out_addr = 0x000000a0;
    a.out_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&a, &b) != 0);

    /* a matches b exactly */
    a.out_addr = 0x010000a0;
    a.out_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&a, &b) != 0);

    /*** NEXT TEST ***/

    /* a matches all in addresses */
    b.in_addr = 0x010000a0;
    fail_if(filter_compare(&a, &b) != 0);

    /* a does not match b via 8-bit netmask */
    a.in_addr = 0x000000c0;
    a.in_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&a, &b) == 0);

    /* a does not match b at all*/
    a.in_addr = 0x020000b0;
    a.in_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&a, &b) == 0);

    /* a matches b via 8-bit netmask */
    a.in_addr = 0x000000a0;
    a.in_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&a, &b) != 0);

    /* a matches b exactly */
    a.in_addr = 0x010000a0;
    a.in_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&a, &b) != 0);

    /*** NEXT TEST ***/

    /* a matches all protocols */
    b.proto = 4u;
    fail_if(filter_compare(&a, &b) != 0);

    /* a does not match protocol */
    a.proto = 5u;
    fail_if(filter_compare(&a, &b) == 0);

    /* a matches b's protocol */
    a.proto = b.proto;
    fail_if(filter_compare(&a, &b) != 0);

    /*** NEXT TEST ***/

    /* a matches all devices */
    b.fdev = (struct pico_device *) &b;
    fail_if(filter_compare(&a, &b) != 0);

    /* a does not match device */
    a.fdev = (struct pico_device *)&a;
    fail_if(filter_compare(&a, &b) == 0);

    /* a matches b's device */
    a.fdev = b.fdev;
    fail_if(filter_compare(&a, &b) != 0);


    /*** SAME TEST DUPLICATED WITH INVERTED ORDER OF PARAMETERS ***/

    memset(&a, 0, sizeof(struct filter_node));
    memset(&b, 0, sizeof(struct filter_node));

    a.filter_id = 2;


    /* check that rule is matched properly */
    fail_if(filter_match_packet_find_rule(&b, &a) != &a);

    /* a has a out port that does not match packet */
    b.out_port = 8;
    a.out_port = 7;
    fail_if(filter_compare(&b, &a) == 0);

    /* a matches all ports */
    a.out_port = 0;
    fail_if(filter_compare(&b, &a) != 0);

    /*** NEXT TEST ***/


    /* a has a in port that does not match packet */
    b.in_port = 8;
    a.in_port = 7;
    fail_if(filter_compare(&b, &a) == 0);

    /* a matches all ports */
    a.in_port = 0;
    fail_if(filter_compare(&b, &a) != 0);

    /* a matches port exactly */
    a.in_port = 0;
    fail_if(filter_compare(&b, &a) != 0);

    /*** NEXT TEST ***/

    /* a matches all out addresses */
    b.out_addr = 0x010000a0;
    fail_if(filter_compare(&b, &a) != 0);

    /* a does not match b via 8-bit netmask */
    a.out_addr = 0x000000c0;
    a.out_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&b, &a) == 0);

    /* a does not match b at all*/
    a.out_addr = 0x020000b0;
    a.out_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&b, &a) == 0);

    /* a matches b via 8-bit netmask */
    a.out_addr = 0x000000a0;
    a.out_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&b, &a) != 0);

    /* a matches b exactly */
    a.out_addr = 0x010000a0;
    a.out_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&b, &a) != 0);

    /*** NEXT TEST ***/

    /* a matches all in addresses */
    b.in_addr = 0x010000a0;
    fail_if(filter_compare(&b, &a) != 0);

    /* a does not match b via 8-bit netmask */
    a.in_addr = 0x000000c0;
    a.in_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&b, &a) == 0);

    /* a does not match b at all*/
    a.in_addr = 0x020000b0;
    a.in_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&b, &a) == 0);

    /* a matches b via 8-bit netmask */
    a.in_addr = 0x000000a0;
    a.in_addr_netmask = 0x000000ff;
    fail_if(filter_compare(&b, &a) != 0);

    /* a matches b exactly */
    a.in_addr = 0x010000a0;
    a.in_addr_netmask = 0xffffffff;
    fail_if(filter_compare(&b, &a) != 0);

    /*** NEXT TEST ***/

    /* a matches all protocols */
    b.proto = 4u;
    fail_if(filter_compare(&b, &a) != 0);

    /* a does not match protocol */
    a.proto = 5u;
    fail_if(filter_compare(&b, &a) == 0);

    /* a matches b's protocol */
    a.proto = b.proto;
    fail_if(filter_compare(&b, &a) != 0);

    /*** NEXT TEST ***/

    /* a matches all devices */
    b.fdev = (struct pico_device *)&b;
    fail_if(filter_compare(&b, &a) != 0);

    /* a does not match device */
    a.fdev = (struct pico_device *)&a;
    fail_if(filter_compare(&b, &a) == 0);

    /* a matches b's device */
    a.fdev = b.fdev;
    fail_if(filter_compare(&b, &a) != 0);



    /*********** TEST ADD FILTER **************/

    /*
       uint32_t pico_ipv4_filter_add(struct pico_device *dev, uint8_t proto,
        struct pico_ip4 *out_addr, struct pico_ip4 *out_addr_netmask,
        struct pico_ip4 *in_addr, struct pico_ip4 *in_addr_netmask,
        uint16_t out_port, uint16_t in_port, int8_t priority,
        uint8_t tos, enum filter_action action)
     */


    r = pico_ipv4_filter_add(NULL, 0, NULL, NULL, NULL, NULL, 0, 0, MAX_PRIORITY + 1, 0, FILTER_DROP);
    fail_if(r > 0);

    r = pico_ipv4_filter_add(NULL, 0, NULL, NULL, NULL, NULL, 0, 0, MIN_PRIORITY - 1, 0, FILTER_PRIORITY);
    fail_if(r > 0);

    r = pico_ipv4_filter_add(NULL, 0, NULL, NULL, NULL, NULL, 0, 0, 0, 0, FILTER_COUNT);
    fail_if(r > 0);

#ifdef FAULTY
    pico_set_mm_failure(1);
    r = pico_ipv4_filter_add(NULL, 0, NULL, NULL, NULL, NULL, 0, 0, 0, 0, FILTER_DROP);
    fail_if(r > 0);
    fail_if(pico_err != PICO_ERR_ENOMEM);
#endif
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("IPfilter module");

    TCase *TCase_ipfilter = tcase_create("Unit test for ipfilter");
    tcase_add_test(TCase_ipfilter, tc_ipfilter);
    suite_add_tcase(s, TCase_ipfilter);
    return s;
}

int main(void)
{
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
}
