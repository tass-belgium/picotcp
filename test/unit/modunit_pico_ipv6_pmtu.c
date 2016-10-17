#include "pico_config.h"
#include "pico_tree.h"
#include "pico_ipv6.h"
#include "pico_ipv6_pmtu.h"
#include "modules/pico_ipv6_pmtu.c"
#include "check.h"

Suite *pico_suite(void);

START_TEST(pico_ipv6_path)
{
	uint8_t i;
	const uint32_t min_mtu = PICO_IPV6_MIN_MTU;
	const uint32_t mtu = 1500;
	struct pico_ipv6_path_id path_id = {{{
        0x20, 0x01, 0x0d, 0xb8, 0x13, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc0, 0x87, 0x6a, 0x13, 0x0b
    }}};
	/* Updating non-existing should not be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_update(&path_id, mtu)!=PICO_PMTU_ERROR);
	}
	/* Adding paths should be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_add(&path_id, mtu+i)!=PICO_PMTU_OK);
	}
	/* Retrieved PMTU should be the same */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_pmtu_get(&path_id)!=mtu+i);
	}
	/* Adding existing paths should be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_add(&path_id, mtu+i+1)!=PICO_PMTU_OK);
	}
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_pmtu_get(&path_id)!=mtu+i+1);
	}
	/* Updating existing paths should be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_add(&path_id, min_mtu+i)!=PICO_PMTU_OK);
	}
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_pmtu_get(&path_id)!=min_mtu+i);
	}
	/* Updating existing paths to higher MTU value should not be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_update(&path_id, min_mtu+i+1)!=PICO_PMTU_ERROR);
	}
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_pmtu_get(&path_id)!=min_mtu+i);
	}
	/* Deleting existing paths should be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_del(&path_id)!=PICO_PMTU_OK);
	}
	/* Updating non-existing should not be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_update(&path_id, mtu)!=PICO_PMTU_ERROR);
	}
	/* Deleting non-existing paths should  not be OK */
	for (i=0;i<0xff;i++){
		path_id.dst.addr[10] = i;
		fail_if(pico_ipv6_path_del(&path_id)!=PICO_PMTU_ERROR);
	}
	fail_if(pico_ipv6_path_add(&path_id, min_mtu-1)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_path_add(&path_id, 0)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_path_add(NULL, min_mtu)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_path_update(&path_id, min_mtu-1)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_path_update(&path_id, 0)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_path_update(NULL, min_mtu)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_path_del(NULL)!=PICO_PMTU_ERROR);
	fail_if(pico_ipv6_pmtu_get(NULL)!=PICO_IPV6_MIN_MTU);
}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("PicoTCP");             

    TCase *TCase_pico_ipv6_path = tcase_create("Unit test for pico_ipv6_path manipulation");
    tcase_add_test(TCase_pico_ipv6_path, pico_ipv6_path);
    suite_add_tcase(s, TCase_pico_ipv6_path);

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
