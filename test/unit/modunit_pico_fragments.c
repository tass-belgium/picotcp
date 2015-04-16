#include "pico_config.h"
#include "pico_ipv6.h"
#include "pico_icmp6.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"
#include "pico_constants.h"
#include "modules/pico_fragments.c"
#include "check.h"


START_TEST(tc_fragments_compare)
{
   /* TODO: test this: static int fragments_compare(void *fa, void *fb);   */
}
END_TEST
START_TEST(tc_hole_compare)
{
   /* TODO: test this: static int hole_compare(void *a, void *b);          */
}
END_TEST
START_TEST(tc_pico_fragment_alloc)
{
   /* TODO: test this: static pico_fragment_t *pico_fragment_alloc( uint16_t iphdrsize, uint16_t bufsize); */
}
END_TEST
START_TEST(tc_pico_fragment_free)
{
   /* TODO: test this: static pico_fragment_t *pico_fragment_free(pico_fragment_t * fragment); */
}
END_TEST
START_TEST(tc_pico_fragment_arrived)
{
   /* TODO: test this: static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame, uint16_t byte_offset, uint16_t more_flag ); */
}
END_TEST
START_TEST(tc_pico_hole_free)
{
   /* TODO: test this: static pico_hole_t* pico_hole_free(pico_hole_t *hole); */
}
END_TEST
START_TEST(tc_pico_hole_alloc)
{
   /* TODO: test this: static pico_hole_t* pico_hole_alloc(uint16_t first,uint16_t last); */
}
END_TEST
START_TEST(tc_pico_ip_frag_expired)
{
   /* TODO: test this: static void pico_ip_frag_expired(pico_time now, void *arg) */
}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_fragments_compare = tcase_create("Unit test for fragments_compare");
    TCase *TCase_hole_compare = tcase_create("Unit test for hole_compare");
    TCase *TCase_pico_fragment_alloc = tcase_create("Unit test for *pico_fragment_alloc");
    TCase *TCase_pico_fragment_free = tcase_create("Unit test for *pico_fragment_free");
    TCase *TCase_pico_fragment_arrived = tcase_create("Unit test for pico_fragment_arrived");
    TCase *TCase_pico_hole_free = tcase_create("Unit test for pico_hole_free");
    TCase *TCase_pico_hole_alloc = tcase_create("Unit test for pico_hole_alloc");
    TCase *TCase_pico_ip_frag_expired = tcase_create("Unit test for pico_ip_frag_expired");


    tcase_add_test(TCase_fragments_compare, tc_fragments_compare);
    suite_add_tcase(s, TCase_fragments_compare);
    tcase_add_test(TCase_hole_compare, tc_hole_compare);
    suite_add_tcase(s, TCase_hole_compare);
    tcase_add_test(TCase_pico_fragment_alloc, tc_pico_fragment_alloc);
    suite_add_tcase(s, TCase_pico_fragment_alloc);
    tcase_add_test(TCase_pico_fragment_free, tc_pico_fragment_free);
    suite_add_tcase(s, TCase_pico_fragment_free);
    tcase_add_test(TCase_pico_fragment_arrived, tc_pico_fragment_arrived);
    suite_add_tcase(s, TCase_pico_fragment_arrived);
    tcase_add_test(TCase_pico_hole_free, tc_pico_hole_free);
    suite_add_tcase(s, TCase_pico_hole_free);
    tcase_add_test(TCase_pico_hole_alloc, tc_pico_hole_alloc);
    suite_add_tcase(s, TCase_pico_hole_alloc);
    tcase_add_test(TCase_pico_ip_frag_expired, tc_pico_ip_frag_expired);
    suite_add_tcase(s, TCase_pico_ip_frag_expired);
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
