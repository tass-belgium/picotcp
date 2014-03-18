#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_tree.h"
#include "modules/pico_ntp_client.c"
#include "check.h"


START_TEST(tc_pico_ntp_parse)
{
   /* TODO: test this: static void pico_ntp_parse(char *buf, int len) */
}
END_TEST
START_TEST(tc_pico_ntp_client_wakeup)
{
   /* TODO: test this: static void pico_ntp_client_wakeup(uint16_t ev, struct pico_socket *s) */
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

    TCase *TCase_pico_ntp_parse = tcase_create("Unit test for pico_ntp_parse");
    TCase *TCase_pico_ntp_client_wakeup = tcase_create("Unit test for pico_ntp_client_wakeup");
    TCase *TCase_dnsCallback = tcase_create("Unit test for dnsCallback");


    tcase_add_test(TCase_pico_ntp_parse, tc_pico_ntp_parse);
    suite_add_tcase(s, TCase_pico_ntp_parse);
    tcase_add_test(TCase_pico_ntp_client_wakeup, tc_pico_ntp_client_wakeup);
    suite_add_tcase(s, TCase_pico_ntp_client_wakeup);
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
