#include "pico_dhcp6_client.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv6.h"
#include "pico_socket.h"
#include "pico_eth.h"
#include "pico_dev_mock.c"
#include "modules/pico_dhcp6_client.c"
#include "check.h"

#define PRINT_BEGIN_FUNCTION do{ printf("\n**************************************\n** starting %s\n**************************************\n", __func__);} while(0)
#define PRINT_END_FUNCTION do{ printf("\n**************************************\n** END %s\n**************************************\n", __func__);} while(0)

static inline uint16_t swap16(uint16_t value)
{
	return short_be(value);
}

static inline uint32_t swap32(uint32_t value)
{
	return long_be(value);
}

static inline uint64_t swap64(uint64_t value)
{
	return long_long_be(value);
}

/* Buffer that can be used per test to expect data that is going out to the server.
 * This buffer could be used to compare data in the compare function */
uint8_t expected_data[100];

/* Compare function pointer that holds the compare function that will be called
 * when pico_socket_sendto_mock_extended received data */
void (*compare_function)(const void *buf, const size_t len) = NULL;

/* Compare function declarations. Add one per test */
static void compare_sol(const void *buf, const size_t len);

/* Mock function */
int pico_socket_sendto_extended(struct pico_socket *s, const void *buf, const int len,
                                 void *dst, uint16_t remote_port, struct pico_msginfo *msginfo)
{
	IGNORE_PARAMETER(s); /* TODO: extend */
	IGNORE_PARAMETER(dst);
	IGNORE_PARAMETER(remote_port);
	IGNORE_PARAMETER(msginfo);
    if(compare_function)
        compare_function(buf, (size_t) len);

    return len;
}

/* Mock function */
uint32_t pico_rand(void)
{
    return 0xAABBCCDD;
}

/* Dummy function */
static void dummy_function()
{
	printf("Entered dummy function\n");
}

START_TEST(tc_generate_duid_ll)
{
   /* TODO: test this: static void generate_duid_ll(struct pico_device *dev, struct pico_dhcp6_duid_ll * client_duid_ll) */
}
END_TEST
START_TEST(tc_void)
{
   /* TODO: test this: static inline void clear_options_in_cookie(void){ */
}
END_TEST
START_TEST(tc_pico_dhcp6_parse_options)
{
	PRINT_BEGIN_FUNCTION;
	uint8_t buf[] = { /* Reply message, no.6 dhcpv6.pcap */
			0x00, 0x19, 0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x11, 0x94, 0x00, 0x00, 0x1c, 0x20, 0x40, 0x20,
			0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x26, 0x2d, 0x08, 0x00, 0x27, 0xfe, 0x8f,
			0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27,
			0xd4, 0x10, 0xbb
	};
	uint8_t trans_id[3] = {0x57, 0x19, 0x58};
	uint8_t cid_link_layer_addr[6] = {0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95};
	uint8_t sid_link_layer_addr[6] = {0x08, 0x00, 0x27, 0xd4, 0x10, 0xbb};

	uint8_t buf2[] = { /* Reply message, no.8 dhcpv6.pcap */
			0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x26, 0x2d, 0x08, 0x00,
			0x27, 0xfe, 0x8f, 0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8,
			0x08, 0x00, 0x27, 0xd4, 0x10, 0xbb, 0x00, 0x0d, 0x00, 0x13, 0x00, 0x00, 0x52, 0x65, 0x6c, 0x65,
			0x61, 0x73, 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x2e
	};
	uint8_t trans_id2[3] = {0x8d, 0xdc, 0x95};
	init_cookie();
	memcpy(cookie.transaction_id, trans_id, sizeof(trans_id));

	pico_dhcp6_parse_options((struct pico_dhcp6_opt *)buf, sizeof(buf));

	ck_assert(cookie.cid_rec != NULL);
	ck_assert_msg(swap16(cookie.cid_rec->base_opts.option_code) == 1, "found 0x%04x, expected: 00 01", swap16(cookie.cid_rec->base_opts.option_code));
	ck_assert_msg(swap16(cookie.cid_rec->base_opts.option_len) == 14, "found 0x%04x, expected: 00 0e", swap16(cookie.cid_rec->base_opts.option_len));
	ck_assert_msg(swap16(cookie.cid_rec->duid->type) == PICO_DHCP6_DUID_LLT, "found 0x%04x, expected: 00 01", swap16(cookie.cid_rec->duid->type));
	struct pico_dhcp6_duid_llt* duid_cid = (struct pico_dhcp6_duid_llt *)&cookie.cid_rec->duid;
	ck_assert_msg(swap16(duid_cid->hw_type) == 1, "found 0x%04x, expected: 00 01");
	ck_assert_msg(swap32(duid_cid->time) == 0x1c38262d, "found 0x%04x, expected: 0x1c38262d", swap32(duid_cid->time));
	ck_assert(memcmp(&duid_cid->link_layer_address, cid_link_layer_addr, sizeof(cid_link_layer_addr)) == 0);

	ck_assert(cookie.sid != NULL);
	ck_assert_msg(swap16(cookie.sid->base_opts.option_code) == 2, "found 0x%04x, expected: 00 02", swap16(cookie.sid->base_opts.option_code));
	ck_assert_msg(swap16(cookie.sid->base_opts.option_len) == 14, "found 0x%04x, expected: 00 0e", swap16(cookie.sid->base_opts.option_len));
	ck_assert_msg(swap16(cookie.sid->duid.type) == PICO_DHCP6_DUID_LLT, "found 0x%04x, expected: 00 01", swap16(cookie.sid->duid.type));
	struct pico_dhcp6_duid_llt* duid_sid = (struct pico_dhcp6_duid_llt *)&cookie.sid->duid;
	ck_assert_msg(swap16(duid_sid->hw_type) == 1, "found 0x%04x, expected: 00 01");
	ck_assert_msg(swap32(duid_sid->time) == 0x1c3825e8, "found 0x%04x, expected: 0x1c3825e8", swap32(duid_sid->time));
	ck_assert(memcmp(&duid_sid->link_layer_address, sid_link_layer_addr, sizeof(sid_link_layer_addr)) == 0);

	memcpy(cookie.transaction_id, trans_id2, sizeof(trans_id2));
	pico_dhcp6_parse_options((struct pico_dhcp6_opt *)buf2, sizeof(buf2));
	ck_assert(cookie.cid_rec != NULL); // TODO: check message type
	ck_assert(cookie.sid != NULL); // TODO: check message type
	ck_assert(cookie.status_code_field != NULL);
	pico_dhcp6_client_clear_options_in_cookie();
	PRINT_END_FUNCTION;
}
END_TEST
START_TEST(tc_pico_dhcp6_add_addr)
{
   /* TODO: test this: static void pico_dhcp6_add_addr() */
}
END_TEST
START_TEST(tc_pico_dhcp6_send_msg)
{
   /* TODO: test this: static void pico_dhcp6_send_msg(struct pico_dhcp6_hdr *msg, size_t len) */
}
END_TEST
START_TEST(tc_pico_dhcp6_fill_msg_with_options)
{
   /* TODO: test this: static void pico_dhcp6_fill_msg_with_options(struct pico_dhcp6_hdr *msg) */
}
END_TEST

static void compare_req(const void *buf, const size_t len)
{
    ck_assert_msg(memcmp(buf, expected_data, (size_t) len) == 0, "DHCPv6 req message wrong");
}
START_TEST(tc_pico_dhcp6_send_req)
{
    unsigned char client_mac[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    unsigned char server_mac[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    uint8_t req_msg[] = {
        0x03, /* Request message type */
        0xdd, 0xcc, 0xbb, /* Random Transaction ID. Should not be compared */

        0x00, 0x01, /* CID option */
        0x00, 0x0a, /* CID len */
            0x00, 0x03, /* DUID type is LL */
            0x00, 0x01, /* HW type is ethernet */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Client MAC address */

        0x00, 0x02, /* SID option */
        0x00, 0x0e, /* SID len */
            0x00, 0x01, /* DUID type is LLT */
            0x00, 0x01, /* HW type is ethernet */
            0x00, 0x01, 0x02, 0x03, /* DUID time */
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, /* Server MAC address */

        0x00, 0x03, /* IANA option */
        0x00, 0x28, /* IANA len */
            0x55, 0x55, 0x55, 0x55, /* IAID */
            0x00, 0x00, 0x00, 0x00, /* T1 */
            0x00, 0x00, 0x00, 0x00, /* T2 */
            0x00, 0x05, /* Address option */
            0x00, 0x18, /* Address len */
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, /*  IPv6   */
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, /* address */
                0x00, 0x00, 0x00, 0x12, /* Preferred lifetime */
                0x00, 0x00, 0x00, 0x1e, /* Valid lifetime */
    };

    /* Set test compare function and compare data */
    memcpy(expected_data, req_msg, sizeof(req_msg));
    compare_function = &compare_req;

    /* Use a DUID-LL for the CID */
    cookie.cid_client = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt) + 10);
    cookie.cid_client->base_opts.option_code = short_be(PICO_DHCP6_OPT_CLIENTID);
    cookie.cid_client->base_opts.option_len = short_be(10);
    ((struct pico_dhcp6_duid_ll *)cookie.cid_client->duid)->type = short_be(PICO_DHCP6_DUID_LL);
    ((struct pico_dhcp6_duid_ll *)cookie.cid_client->duid)->hw_type = short_be(PICO_DHCP6_HW_TYPE_ETHERNET);
    memcpy(&((struct pico_dhcp6_duid_ll *)cookie.cid_client->duid)->link_layer_address, client_mac, sizeof(client_mac));

    /* Use a DUID-LLT for the SID */
    cookie.sid = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt) + 14);
    cookie.sid->base_opts.option_code = short_be(PICO_DHCP6_OPT_SERVERID);
    cookie.sid->base_opts.option_len = short_be(14);
    ((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->type = short_be(PICO_DHCP6_DUID_LLT);
    ((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->hw_type = short_be(PICO_DHCP6_HW_TYPE_ETHERNET);
    ((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->time = long_be(0x00010203);
    memcpy(&((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->link_layer_address, server_mac, sizeof(server_mac));

    /* Fill in IANA with IADDR option */
    cookie.iana = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt) + 40);
    cookie.iana->base_opts.option_code = short_be(PICO_DHCP6_OPT_IA_NA);
    cookie.iana->base_opts.option_len = short_be(40);
    cookie.iana->iaid = 0x55555555;
    cookie.iana->t1 = 0;
    cookie.iana->t2 = 0;
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->base_opts.option_code = short_be(PICO_DHCP6_OPT_IADDR);
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->base_opts.option_len = short_be(24);
    if(pico_string_to_ipv6("2001:0db8:0000:0001:0000:0000:0000:2000", (uint8_t *) &((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->addr) != 0)
        ck_assert_msg(0 == 1, "ipv6 converion failed!");
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->preferred_lt = long_be(18);
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->valid_lt = long_be(30);

    pico_dhcp6_send_req();

    compare_function = NULL;
}
END_TEST
static void compare_renew(const void *buf, const size_t len)
{
    ck_assert_msg(memcmp(buf, expected_data, (size_t) len) == 0, "DHCPv6 renew message wrong");
}
START_TEST(tc_pico_dhcp6_renew_timeout)
{
    unsigned char client_mac[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    unsigned char server_mac[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    uint8_t req_msg[] = {
        0x05, /* Renew message type */
        0xdd, 0xcc, 0xbb, /* Random Transaction ID. Should not be compared */

        0x00, 0x01, /* CID option */
        0x00, 0x0a, /* CID len */
            0x00, 0x03, /* DUID type is LL */
            0x00, 0x01, /* HW type is ethernet */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* Client MAC address */

        0x00, 0x02, /* SID option */
        0x00, 0x0e, /* SID len */
            0x00, 0x01, /* DUID type is LLT */
            0x00, 0x01, /* HW type is ethernet */
            0x00, 0x01, 0x02, 0x03, /* DUID time */
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, /* Server MAC address */

        0x00, 0x03, /* IANA option */
        0x00, 0x28, /* IANA len */
            0x55, 0x55, 0x55, 0x55, /* IAID */
            0x00, 0x00, 0x00, 0x00, /* T1 */
            0x00, 0x00, 0x00, 0x00, /* T2 */
            0x00, 0x05, /* Address option */
            0x00, 0x18, /* Address len */
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, /*  IPv6   */
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, /* address */
                0x00, 0x00, 0x00, 0x12, /* Preferred lifetime */
                0x00, 0x00, 0x00, 0x1e, /* Valid lifetime */
    };

    /* Set test compare function and compare data */
    memcpy(expected_data, req_msg, sizeof(req_msg));
    compare_function = &compare_renew;

    /* Use a DUID-LL for the CID */
    cookie.cid_client = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt) + 10);
    cookie.cid_client->base_opts.option_code = short_be(PICO_DHCP6_OPT_CLIENTID);
    cookie.cid_client->base_opts.option_len = short_be(10);
    ((struct pico_dhcp6_duid_ll *)cookie.cid_client->duid)->type = short_be(PICO_DHCP6_DUID_LL);
    ((struct pico_dhcp6_duid_ll *)cookie.cid_client->duid)->hw_type = short_be(PICO_DHCP6_HW_TYPE_ETHERNET);
    memcpy(&((struct pico_dhcp6_duid_ll *)cookie.cid_client->duid)->link_layer_address, client_mac, sizeof(client_mac));

    /* Use a DUID-LLT for the SID */
    cookie.sid = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt) + 14);
    cookie.sid->base_opts.option_code = short_be(PICO_DHCP6_OPT_SERVERID);
    cookie.sid->base_opts.option_len = short_be(14);
    ((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->type = short_be(PICO_DHCP6_DUID_LLT);
    ((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->hw_type = short_be(PICO_DHCP6_HW_TYPE_ETHERNET);
    ((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->time = long_be(0x00010203);
    memcpy(&((struct pico_dhcp6_duid_llt *)&cookie.sid->duid)->link_layer_address, server_mac, sizeof(server_mac));

    /* Fill in IANA with IADDR option */
    cookie.iana = PICO_ZALLOC(sizeof(struct pico_dhcp6_opt) + 40);
    cookie.iana->base_opts.option_code = short_be(PICO_DHCP6_OPT_IA_NA);
    cookie.iana->base_opts.option_len = short_be(40);
    cookie.iana->iaid = 0x55555555;
    cookie.iana->t1 = 0;
    cookie.iana->t2 = 0;
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->base_opts.option_code = short_be(PICO_DHCP6_OPT_IADDR);
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->base_opts.option_len = short_be(24);
    if(pico_string_to_ipv6("2001:0db8:0000:0001:0000:0000:0000:2000", (uint8_t *) &((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->addr) != 0)
        ck_assert_msg(0 == 1, "ipv6 converion failed!");
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->preferred_lt = long_be(18);
    ((struct pico_dhcp6_opt_ia_addr *)&cookie.iana->options)->valid_lt = long_be(30);

    pico_dhcp6_renew_timeout(0, NULL);

    compare_function = NULL;
}
END_TEST
START_TEST(tc_check_adv_message)
{
   /* TODO: test this: static int check_adv_message(struct pico_dhcp6_hdr *msg, size_t len){ */
}
END_TEST
START_TEST(tc_recv_adv)
{
   /* TODO: test this: static void recv_adv(struct pico_dhcp6_hdr *msg, size_t len) */
}
END_TEST
START_TEST(tc_record_t1_t2)
{
   /* TODO: test this: static void record_t1_t2(void) */
}
END_TEST
START_TEST(tc_update_lifetimes)
{
   /* TODO: test this: static void update_lifetimes(void) */
}
END_TEST
START_TEST(tc_recv_reply)
{
   /* TODO: test this: static void recv_reply(struct pico_dhcp6_hdr *msg, size_t len) */
}
END_TEST
START_TEST(tc_int)
{
   /* TODO: test this: static inline int is_valid_reconf_option(uint8_t msg_type){ */
}
END_TEST
START_TEST(tc_passes_validation_test)
{
   /* TODO: test this: static int passes_validation_test(struct pico_dhcp6_hdr *msg, size_t len){ */
}
END_TEST
START_TEST(tc_check_reconfigure_message)
{
   /* TODO: test this: static int check_reconfigure_message(struct pico_dhcp6_hdr *msg, size_t len){ */
}
END_TEST
START_TEST(tc_respond_to_reconfigure_message)
{
   /* TODO: test this: static int respond_to_reconfigure_message(){ */
}
END_TEST
START_TEST(tc_recv_reconfigure)
{
   /* TODO: test this: static int recv_reconfigure(struct pico_dhcp6_hdr *msg, size_t len) */
}
END_TEST
START_TEST(tc_dhcp6c_cb)
{
   /* TODO: test this: static void dhcp6c_cb(uint16_t ev, struct pico_socket *s) */
}
END_TEST
START_TEST(tc_pico_dhcp6_sol_timeout)
{
   /* TODO: test this: static void pico_dhcp6_sol_timeout(pico_time t, void * arg) */
}
END_TEST

static void compare_sol(const void *buf, const size_t len)
{
    ck_assert_msg(memcmp(buf, expected_data, (size_t) len) == 0, "DHCPv6 sol message wrong");
}
START_TEST(tc_pico_dhcp6_send_sol)
{
    struct mock_device *mock;
    unsigned char mac[6] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    uint8_t sol_msg[] = {
        0x01, /* Solicit message type */ 
        0xdd, 0xcc, 0xbb, /* Random Transaction ID. Should not be compared */

        0x00, 0x01, /* CID option */
        0x00, 0x0a, /* CID len */
            0x00, 0x03, /* DUID type is LL */
            0x00, 0x01, /* HW type is ethernet */
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, /* MAC address */

        0x00, 0x06, /* ORO option */
        0x00, 0x00, /* ORO len */

        0x00, 0x08, /* Elapsed time option */
        0x00, 0x02, /* Elapsed time len */
            0x00, 0x00, /* Elapsed time */

        0x00, 0x03, /* IANA option */
        0x00, 0x0c, /* IANA len */
            0x02, 0x03, 0x04, 0x05, /* IAID */
            0x00, 0x00, 0x00, 0x00, /* T1 */
            0x00, 0x00, 0x00, 0x00  /* T2 */
    };

    /* Set test compare function and compare data */
    compare_function = &compare_sol;
    memcpy(expected_data, sol_msg, sizeof(sol_msg));

    pico_stack_init();

    /* Create mock device and add mac address to ethernet device*/
    mock = pico_mock_create(mac);
    memcpy(mock->dev->name, "dummy device", sizeof("dummy device"));
    fail_if(!mock, "MOCK DEVICE creation failed");

    cookie.dev = mock->dev;

    pico_dhcp6_send_sol(); /* Check implemented in compare_sol function */

    compare_function = NULL;
}
END_TEST

START_TEST(tc_sm_process_msg_adv)
{
	PRINT_BEGIN_FUNCTION;
	uint8_t buf[] = { /* Advertise message, no.5 DHCPv6.pcap */
			0x02, 0x10,
			0x08, 0x74, 0x00, 0x19, 0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x11, 0x94, 0x00, 0x00, 0x1c, 0x20, 0x40, 0x20,
			0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f,
			0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27,
			0xd4, 0x10, 0xbb
	};
	uint8_t trans_id[3] = {0x10, 0x08, 0x74};
	uint8_t client_duid[6] = {0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95}; /* /08:00:27:fe:8f:95 */
	struct pico_dhcp6_opt_cid* cid;

	printf("allocating %lu bytes\n", sizeof(struct pico_dhcp6_opt_cid) + sizeof(struct pico_dhcp6_duid_ll) + sizeof(client_duid));
	printf("pico_dhcp6_opt_cid: %lu bytes\n", sizeof(struct pico_dhcp6_opt_cid) );
	printf("pico_dhcp6_duid_ll: %lu bytes\n", sizeof(struct pico_dhcp6_duid_ll) );
	printf("pico_dhcp6_opt: %lu bytes\n", sizeof(struct pico_dhcp6_opt) );
	printf("client_duid: %lu bytes\n", sizeof(client_duid) );

	cid = PICO_ZALLOC( sizeof(struct pico_dhcp6_opt_cid) + sizeof(struct pico_dhcp6_duid_ll) + sizeof(client_duid));
	cid->base_opts.option_code = PICO_DHCP6_DUID_LL;
	cid->base_opts.option_len = sizeof(client_duid);
	memcpy(&cid->duid, client_duid, sizeof(client_duid));
	cid->base_opts.option_len = short_be(cid->base_opts.option_len);
	cookie.cid_client = cid;

    /*Initiate test setup*/
    pico_stack_init();
    init_cookie();

    cookie.rto_timer = pico_timer_add(300000, &dummy_function, NULL); /* init timer */
	cookie.state = DHCP6_CLIENT_STATE_SOLICITING;
	memcpy(cookie.transaction_id, trans_id, sizeof(trans_id));
	sm_process_msg((struct pico_dhcp6_hdr *)buf, sizeof(buf));
	ck_assert(cookie.cid_rec != NULL); // TODO: check message type
	ck_assert(cookie.sid != NULL); // TODO: check output, should be omitted later on
	PICO_FREE(cid);
	pico_dhcp6_client_clear_options_in_cookie();
	PRINT_END_FUNCTION;
}
END_TEST
START_TEST(tc_sm_process_msg_reply)
{
	PRINT_BEGIN_FUNCTION;
	uint8_t buf[] = { /* Reply message, no.6 dhcpv6.pcap */
			0x07, 0x57,
			0x19, 0x58, 0x00, 0x19, 0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x11, 0x94, 0x00, 0x00, 0x1c, 0x20, 0x40, 0x20,
			0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x26, 0x2d, 0x08, 0x00, 0x27, 0xfe, 0x8f,
			0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27,
			0xd4, 0x10, 0xbb
	};
	uint8_t trans_id[3] = {0x57, 0x19, 0x58};
	uint8_t buf2[] = { /* Reply message, no.8 dhcpv6.pcap */
			0x07, 0x8d,
			0xdc, 0x95, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x26, 0x2d, 0x08, 0x00,
			0x27, 0xfe, 0x8f, 0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8,
			0x08, 0x00, 0x27, 0xd4, 0x10, 0xbb, 0x00, 0x0d, 0x00, 0x13, 0x00, 0x00, 0x52, 0x65, 0x6c, 0x65,
			0x61, 0x73, 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x2e
	};
	uint8_t trans_id2[3] = {0x8d, 0xdc, 0x95};

    /*Initiate test setup*/
    pico_stack_init();
    init_cookie();

    cookie.rto_timer = pico_timer_add(300000, &dummy_function, NULL); /* init timer */
	cookie.state = DHCP6_CLIENT_STATE_SOLICITING; /* Force client to accept the reply message */
	memcpy(cookie.transaction_id, trans_id, sizeof(trans_id));

	printf("cookie.transacation_id in unit test: ");

	sm_process_msg((struct pico_dhcp6_hdr *)buf, sizeof(buf));
	ck_assert(cookie.cid_rec != NULL); // TODO: check message type
	ck_assert(cookie.sid != NULL);

	cookie.state = DHCP6_CLIENT_STATE_SOLICITING;
	memcpy(cookie.transaction_id, trans_id2, sizeof(trans_id2));
	sm_process_msg((struct pico_dhcp6_hdr *)buf2, sizeof(buf2));
	ck_assert(cookie.cid_rec != NULL); // TODO: check message type
	ck_assert(cookie.sid != NULL); // TODO: check message type
	ck_assert(cookie.status_code_field != NULL);

	/* Cleanup */
	pico_dhcp6_client_clear_options_in_cookie();

	PRINT_END_FUNCTION;
}
END_TEST
START_TEST(tc_sm_process_msg_reconfigure)
{
   /* TODO: test this: static void sm_process_msg(struct pico_dhcp6_hdr *msg, size_t len) */
//	uint8_t buf[] = { /* TODO */
//
//	};
}
END_TEST
START_TEST(tc_pico_dhcp6_client_msg)
{
   /* TODO: test this: static int8_t pico_dhcp6_client_msg(struct pico_dhcp6_client_cookie *dhcp6, uint8_t msg_type) */
}
END_TEST


Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_generate_duid_ll = tcase_create("Unit test for generate_duid_ll");
    TCase *TCase_void = tcase_create("Unit test for void");
    TCase *TCase_pico_dhcp6_parse_options = tcase_create("Unit test for pico_dhcp6_parse_options");
    TCase *TCase_pico_dhcp6_add_addr = tcase_create("Unit test for pico_dhcp6_add_addr");
    TCase *TCase_pico_dhcp6_send_msg = tcase_create("Unit test for pico_dhcp6_send_msg");
    TCase *TCase_pico_dhcp6_fill_msg_with_options = tcase_create("Unit test for pico_dhcp6_fill_msg_with_options");
    TCase *TCase_pico_dhcp6_send_req = tcase_create("Unit test for pico_dhcp6_send_req");
    TCase *TCase_pico_dhcp6_renew_timeout = tcase_create("Unit test for pico_dhcp6_renew_timeout");
    TCase *TCase_check_adv_message = tcase_create("Unit test for check_adv_message");
    TCase *TCase_recv_adv = tcase_create("Unit test for recv_adv");
    TCase *TCase_record_t1_t2 = tcase_create("Unit test for record_t1_t2");
    TCase *TCase_update_lifetimes = tcase_create("Unit test for update_lifetimes");
    TCase *TCase_recv_reply = tcase_create("Unit test for recv_reply");
    TCase *TCase_int = tcase_create("Unit test for int");
    TCase *TCase_passes_validation_test = tcase_create("Unit test for passes_validation_test");
    TCase *TCase_check_reconfigure_message = tcase_create("Unit test for check_reconfigure_message");
    TCase *TCase_respond_to_reconfigure_message = tcase_create("Unit test for respond_to_reconfigure_message");
    TCase *TCase_recv_reconfigure = tcase_create("Unit test for recv_reconfigure");
    TCase *TCase_dhcp6c_cb = tcase_create("Unit test for dhcp6c_cb");
    TCase *TCase_pico_dhcp6_sol_timeout = tcase_create("Unit test for pico_dhcp6_sol_timeout");
    TCase *TCase_pico_dhcp6_send_sol = tcase_create("Unit test for pico_dhcp6_send_sol");
    TCase *TCase_sm_process_msg_adv = tcase_create("Unit test for sm_process_msg Advertise");
    TCase *TCase_sm_process_msg_reply = tcase_create("Unit test for sm_process_msg Reply");
    TCase *TCase_sm_process_msg_reconfigure = tcase_create("Unit test for sm_process_msg Reconfigure");
    TCase *TCase_pico_dhcp6_client_msg = tcase_create("Unit test for pico_dhcp6_client_msg");


    tcase_add_test(TCase_generate_duid_ll, tc_generate_duid_ll);
    suite_add_tcase(s, TCase_generate_duid_ll);
    tcase_add_test(TCase_void, tc_void);
    suite_add_tcase(s, TCase_void);
    tcase_add_test(TCase_pico_dhcp6_parse_options, tc_pico_dhcp6_parse_options);
    suite_add_tcase(s, TCase_pico_dhcp6_parse_options);
    tcase_add_test(TCase_pico_dhcp6_add_addr, tc_pico_dhcp6_add_addr);
    suite_add_tcase(s, TCase_pico_dhcp6_add_addr);
    tcase_add_test(TCase_pico_dhcp6_send_msg, tc_pico_dhcp6_send_msg);
    suite_add_tcase(s, TCase_pico_dhcp6_send_msg);
    tcase_add_test(TCase_pico_dhcp6_fill_msg_with_options, tc_pico_dhcp6_fill_msg_with_options);
    suite_add_tcase(s, TCase_pico_dhcp6_fill_msg_with_options);
    tcase_add_test(TCase_pico_dhcp6_send_req, tc_pico_dhcp6_send_req);
    suite_add_tcase(s, TCase_pico_dhcp6_send_req);
    tcase_add_test(TCase_pico_dhcp6_renew_timeout, tc_pico_dhcp6_renew_timeout);
    suite_add_tcase(s, TCase_pico_dhcp6_renew_timeout);
    tcase_add_test(TCase_check_adv_message, tc_check_adv_message);
    suite_add_tcase(s, TCase_check_adv_message);
    tcase_add_test(TCase_recv_adv, tc_recv_adv);
    suite_add_tcase(s, TCase_recv_adv);
    tcase_add_test(TCase_record_t1_t2, tc_record_t1_t2);
    suite_add_tcase(s, TCase_record_t1_t2);
    tcase_add_test(TCase_update_lifetimes, tc_update_lifetimes);
    suite_add_tcase(s, TCase_update_lifetimes);
    tcase_add_test(TCase_recv_reply, tc_recv_reply);
    suite_add_tcase(s, TCase_recv_reply);
    tcase_add_test(TCase_int, tc_int);
    suite_add_tcase(s, TCase_int);
    tcase_add_test(TCase_passes_validation_test, tc_passes_validation_test);
    suite_add_tcase(s, TCase_passes_validation_test);
    tcase_add_test(TCase_check_reconfigure_message, tc_check_reconfigure_message);
    suite_add_tcase(s, TCase_check_reconfigure_message);
    tcase_add_test(TCase_respond_to_reconfigure_message, tc_respond_to_reconfigure_message);
    suite_add_tcase(s, TCase_respond_to_reconfigure_message);
    tcase_add_test(TCase_recv_reconfigure, tc_recv_reconfigure);
    suite_add_tcase(s, TCase_recv_reconfigure);
    tcase_add_test(TCase_dhcp6c_cb, tc_dhcp6c_cb);
    suite_add_tcase(s, TCase_dhcp6c_cb);
    tcase_add_test(TCase_pico_dhcp6_sol_timeout, tc_pico_dhcp6_sol_timeout);
    suite_add_tcase(s, TCase_pico_dhcp6_sol_timeout);
    tcase_add_test(TCase_pico_dhcp6_send_sol, tc_pico_dhcp6_send_sol);
    suite_add_tcase(s, TCase_pico_dhcp6_send_sol);
    tcase_add_test(TCase_sm_process_msg_adv, tc_sm_process_msg_adv);
    suite_add_tcase(s, TCase_sm_process_msg_adv);
    tcase_add_test(TCase_sm_process_msg_reply, tc_sm_process_msg_reply);
    suite_add_tcase(s, TCase_sm_process_msg_reply);
    tcase_add_test(TCase_sm_process_msg_reconfigure, tc_sm_process_msg_reconfigure);
    suite_add_tcase(s, TCase_sm_process_msg_reconfigure);
    tcase_add_test(TCase_pico_dhcp6_client_msg, tc_pico_dhcp6_client_msg);
    suite_add_tcase(s, TCase_pico_dhcp6_client_msg);
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
