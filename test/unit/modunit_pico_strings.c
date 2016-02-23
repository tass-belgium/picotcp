#include "modules/pico_strings.c"
#include "check.h"

Suite *pico_suite(void);

START_TEST(tc_get_string_terminator_position)
{
    char buf[6] = "unit";
    get_string_terminator_position(NULL,0);
    fail_if(get_string_terminator_position(buf,2) != 0);
    fail_if(get_string_terminator_position(buf,6) != &buf[4]);
}
END_TEST
START_TEST(tc_pico_strncasecmp)
{
    fail_if(pico_strncasecmp("unit","UNIT",4) != 0);
    fail_if(pico_strncasecmp("unit1","UNIT2",5) != -1);
    fail_if(pico_strncasecmp("unit2","UNIT1",5) != 1);
}
END_TEST
START_TEST(tc_num2string)
{
    char buf[20];
    fail_if(num2string(-1,NULL,1) != -1);
    fail_if(num2string(1,NULL,1) != -1);
    fail_if(num2string(1,buf,1) != -1);
    fail_if(num2string(1,buf,3) != 2);
    fail_if(num2string(11,buf,3) != 3);
    fail_if(num2string(112,buf,4) != 4);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_get_string_terminator_position = tcase_create("Unit test for get_string_terminator_position");
    TCase *TCase_num2string = tcase_create("Unit test for num2string");
    TCase *TCase_pico_strncasecmp = tcase_create("Unit test for pico_strncasecmp");

    tcase_add_test(TCase_get_string_terminator_position, tc_get_string_terminator_position);
    suite_add_tcase(s, TCase_get_string_terminator_position);
    tcase_add_test(TCase_num2string,tc_num2string);
    suite_add_tcase(s, TCase_num2string);
    tcase_add_test(TCase_pico_strncasecmp,tc_pico_strncasecmp);
    suite_add_tcase(s, TCase_pico_strncasecmp);

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
