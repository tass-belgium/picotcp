#include "pico_dhcp6_client.h"
#include "pico_stack.h"
#include "pico_config.h"
#include "pico_device.h"
#include "pico_ipv6.h"
#include "pico_socket.h"
#include "pico_eth.h"
#include "modules/pico_dhcp6_client.c"
#include "check.h"

#define PRINT_BEGIN_FUNCTION do{ printf("\n**************************************\n** starting %s\n**************************************\n", __func__);} while(0)
#define PRINT_END_FUNCTION do{ printf("\n**************************************\n** END %s\n**************************************\n", __func__);} while(0)


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
	uint8_t buf2[] = { /* Reply message, no.8 dhcpv6.pcap */
			0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x26, 0x2d, 0x08, 0x00,
			0x27, 0xfe, 0x8f, 0x95, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8,
			0x08, 0x00, 0x27, 0xd4, 0x10, 0xbb, 0x00, 0x0d, 0x00, 0x13, 0x00, 0x00, 0x52, 0x65, 0x6c, 0x65,
			0x61, 0x73, 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x2e
	};
	uint8_t trans_id2[3] = {0x8d, 0xdc, 0x95};
	init_cookie();
	memcpy(cookie.transaction_id, trans_id, sizeof(trans_id));

	pico_dhcp6_parse_options((struct pico_dhcp6_hdr *)buf, sizeof(buf));
	ck_assert(cookie.cid_rec != NULL); // TODO: check message type
	ck_assert(cookie.sid != NULL);

	memcpy(cookie.transaction_id, trans_id2, sizeof(trans_id2));
	pico_dhcp6_parse_options((struct pico_dhcp6_hdr *)buf2, sizeof(buf2));
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
START_TEST(tc_pico_dhcp6_send_req)
{
   /* TODO: test this: static void pico_dhcp6_send_req() */
}
END_TEST
START_TEST(tc_pico_dhcp6_renew_timeout)
{
   /* TODO: test this: static void pico_dhcp6_renew_timeout(pico_time t, void * arg) */
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
START_TEST(tc_pico_dhcp6_send_sol)
{
   /* TODO: test this: static void pico_dhcp6_send_sol(void) */
}
END_TEST

void dummy_function(){
	printf("Entered dummy function\n");
}

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

	printf("allocating %d bytes\n", sizeof(struct pico_dhcp6_opt_cid) + sizeof(struct pico_dhcp6_duid_ll) + sizeof(client_duid));
	printf("pico_dhcp6_opt_cid: %d bytes\n", sizeof(struct pico_dhcp6_opt_cid) );
	printf("pico_dhcp6_duid_ll: %d bytes\n", sizeof(struct pico_dhcp6_duid_ll) );
	printf("pico_dhcp6_opt: %d bytes\n", sizeof(struct pico_dhcp6_opt) );
	printf("client_duid: %d bytes\n", sizeof(client_duid) );

	cid = PICO_ZALLOC( sizeof(struct pico_dhcp6_opt_cid) + sizeof(struct pico_dhcp6_duid_ll) + sizeof(client_duid));
	cid->base_opts.option_code = PICO_DHCP6_DUID_LL;
	cid->base_opts.option_len = sizeof(client_duid);
	memcpy(cid->duid, client_duid, sizeof(client_duid));
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
	pico_timer_cancel(cookie.rto_timer);
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
	print_hex_array(cookie.transaction_id,sizeof(trans_id));

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
	PICO_FREE(cookie.rto_timer);

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
