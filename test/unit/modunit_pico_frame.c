#include "pico_config.h"
#include "pico_protocol.h"
#include "pico_frame.h"
#include "stack/pico_frame.c"
#include "check.h"

volatile pico_err_t pico_err;


#define FRAME_SIZE 1000

START_TEST(tc_pico_frame_alloc_discard)
{
    struct pico_frame *f = pico_frame_alloc(FRAME_SIZE);

    /* Test consistency */
    fail_if(!f);
    fail_if(!f->buffer);
    fail_if(!f->usage_count);
    fail_if(*f->usage_count != 1);
    fail_if(f->start != f->buffer);
    fail_if(f->len != f->buffer_len);
    fail_if(f->len != FRAME_SIZE);
    pico_frame_discard(f);
}
END_TEST

START_TEST(tc_pico_frame_copy)
{
    struct pico_frame *f = pico_frame_alloc(FRAME_SIZE);
    struct pico_frame *c1, *c2;
    fail_if(!f);
    fail_if(!f->buffer);
    fail_if(*f->usage_count != 1);

    /* First copy */
    c1 = pico_frame_copy(f);
    fail_if(!c1);
    fail_if(!c1->buffer);
    fail_if(!c1->usage_count);

    fail_if (c1->buffer != f->buffer);
    fail_if(c1->usage_count != f->usage_count);
    fail_if(*c1->usage_count != 2);
    fail_if(*f->usage_count != 2);
    fail_if(c1->start != c1->buffer);
    fail_if(c1->len != c1->buffer_len);
    fail_if(c1->len != FRAME_SIZE);
    
    /* Second copy */
    c2 = pico_frame_copy(f);
    fail_if (c2->buffer != f->buffer);
    fail_if(c2->usage_count != f->usage_count);
    fail_if(*c2->usage_count != 3);
    fail_if(*f->usage_count != 3);
    fail_if(c2->start != c2->buffer);
    fail_if(c2->len != c2->buffer_len);
    fail_if(c2->len != FRAME_SIZE);
   
    /* Discard 1 */ 
    pico_frame_discard(c1);
    fail_if(*f->usage_count != 2);

    /* Discard 2 */ 
    pico_frame_discard(c2);
    fail_if(*f->usage_count != 1);

    pico_frame_discard(f);

}
END_TEST

START_TEST(tc_pico_frame_deepcopy)
{


}
END_TEST


Suite *pico_suite(void)                       
{
    Suite *s = suite_create("pico_frame.c");             
    TCase *TCase_pico_frame_alloc_discard = tcase_create("Unit test for pico_frame_alloc_discard");
    TCase *TCase_pico_frame_copy = tcase_create("Unit test for pico_frame_copy");
    TCase *TCase_pico_frame_deepcopy = tcase_create("Unit test for pico_frame_deepcopy");
    tcase_add_test(TCase_pico_frame_alloc_discard, tc_pico_frame_alloc_discard);
    tcase_add_test(TCase_pico_frame_copy, tc_pico_frame_copy);
    tcase_add_test(TCase_pico_frame_deepcopy, tc_pico_frame_deepcopy);
    suite_add_tcase(s, TCase_pico_frame_alloc_discard);
    suite_add_tcase(s, TCase_pico_frame_copy);
    suite_add_tcase(s, TCase_pico_frame_deepcopy);
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
