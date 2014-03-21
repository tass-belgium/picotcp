#include "pico_sntp_client.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"
#include "modules/pico_sntp_client.c"
#include "check.h"


START_TEST(tc_timestamp_convert)
{
   /* TODO: test this: static int timestamp_convert(struct pico_sntp_ts *ts, struct pico_timeval *tv) */
    struct pico_sntp_ts ts;
    struct pico_timeval tv;  
    int ret = 0;

    ts.sec = 0;
    ts.frac = 0;
    ret = timestamp_convert(&ts, &tv);
    ck_assert(ret == -1);
    ck_assert(tv.tv_sec == 0);
    ck_assert(tv.tv_msec == 0);

    ts.sec = SNTP_UNIX_OFFSET+1395408816ull;
    ts.frac = 1000000ull;
    ret = timestamp_convert(&ts, &tv);
    ck_assert(ret == 0);
    ck_assert(tv.tv_sec == 0);  //TO CHANGE
    ck_assert(tv.tv_msec == 0); //TO CHANGE
}
END_TEST
START_TEST(tc_pico_sntp_send)
{
   /* TODO: test this: static void pico_sntp_send(struct pico_socket *sock, union pico_address *dst) */
    
}
END_TEST
START_TEST(tc_pico_sntp_parse)
{
   /* TODO: test this: static void pico_sntp_parse(char *buf, struct sntp_server_ns_cookie *ck) */
}
END_TEST
START_TEST(tc_pico_sntp_client_wakeup)
{
   /* TODO: test this: static void pico_sntp_client_wakeup(uint16_t ev, struct pico_socket *s) */
}
END_TEST
START_TEST(tc_dnsCallback)
{
   /* TODO: test this: static void dnsCallback(char *ip, void *arg) */
}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_pico_timeval = tcase_create("Unit test for pico_timeval");
    TCase *TCase_pico_sntp_send = tcase_create("Unit test for pico_sntp_send");
    TCase *TCase_pico_sntp_parse = tcase_create("Unit test for pico_sntp_parse");
    TCase *TCase_pico_sntp_client_wakeup = tcase_create("Unit test for pico_sntp_client_wakeup");
    TCase *TCase_dnsCallback = tcase_create("Unit test for dnsCallback");


    tcase_add_test(TCase_pico_timeval, tc_pico_timeval);
    suite_add_tcase(s, TCase_pico_timeval);
    tcase_add_test(TCase_pico_sntp_send, tc_pico_sntp_send);
    suite_add_tcase(s, TCase_pico_sntp_send);
    tcase_add_test(TCase_pico_sntp_parse, tc_pico_sntp_parse);
    suite_add_tcase(s, TCase_pico_sntp_parse);
    tcase_add_test(TCase_pico_sntp_client_wakeup, tc_pico_sntp_client_wakeup);
    suite_add_tcase(s, TCase_pico_sntp_client_wakeup);
    tcase_add_test(TCase_dnsCallback, tc_dnsCallback);
    suite_add_tcase(s, TCase_dnsCallback);
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
