#include "pico_hotplug_detection.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "modules/pico_hotplug_detection.c"
#include "check.h"
#include "pico_dev_null.c"

/* stubs for timer */
static int8_t timer_active = 0;
void (*timer_cb_function)(pico_time, void *);
uint32_t pico_timer_add(pico_time expire, void (*timer)(pico_time, void *), void *arg) {
  timer_active++;
  timer_cb_function = timer;

  return 123;
}

void pico_timer_cancel(uint32_t id){
  timer_active--;
  fail_if(id != 123);
}

/* callbacks for testing */
uint32_t cb_one_cntr = 0;
int cb_one_last_event = 0;
void cb_one(struct pico_device *dev, int event)
{
    cb_one_cntr++;
    cb_one_last_event = event;
}
uint32_t cb_two_cntr = 0;
int cb_two_last_event = 0;
void cb_two(struct pico_device *dev, int event)
{
    cb_two_cntr++;
    cb_two_last_event = event;
}

/* link state functions for the testing devices */
int state_a = 0;
int link_state_a(struct pico_device *self)
{
  return state_a;
}

int state_b = 0;
int link_state_b(struct pico_device *self)
{
  return state_b;
}


START_TEST(tc_pico_hotplug_reg_dereg)
{
  //create some devices
  struct pico_device *dev_a , *dev_b;
  dev_a = pico_null_create("dummy1");
  dev_b = pico_null_create("dummy2");

  dev_a->link_state = &link_state_a;
  dev_b->link_state = &link_state_b;

  //add some function pointers to be called
  pico_hotplug_register(dev_a, &cb_one);
  fail_unless(timer_active == 1);
  pico_hotplug_register(dev_a, &cb_two);
  pico_hotplug_register(dev_b, &cb_two);
  fail_unless(timer_active == 1);

  //remove function pointers
  pico_hotplug_deregister(dev_a, &cb_one);
  pico_hotplug_deregister(dev_a, &cb_two);
  pico_hotplug_deregister(dev_b, &cb_two);

  //check that our tree is empty at the end
  fail_unless(pico_tree_empty(&Hotplug_device_tree));

  //register functions multiple times
  pico_hotplug_register(dev_a, &cb_one);
  pico_hotplug_register(dev_a, &cb_one);
  pico_hotplug_register(dev_a, &cb_two);
  pico_hotplug_register(dev_a, &cb_two);
  pico_hotplug_register(dev_b, &cb_two);
  pico_hotplug_register(dev_b, &cb_two);

  //remove function pointers once
  pico_hotplug_deregister(dev_a, &cb_one);
  pico_hotplug_deregister(dev_a, &cb_two);
  fail_unless(timer_active == 1);
  pico_hotplug_deregister(dev_b, &cb_two);
  fail_unless(timer_active == 0);

  //check that our tree is empty at the end
  fail_unless(pico_tree_empty(&Hotplug_device_tree));
}
END_TEST

START_TEST(tc_pico_hotplug_callbacks)
{
  //create some devices
  struct pico_device *dev_a , *dev_b;
  dev_a = pico_null_create("dummy1");
  dev_b = pico_null_create("dummy2");

  dev_a->link_state = &link_state_a;
  dev_b->link_state = &link_state_b;

  //add some function pointers to be called
  pico_hotplug_register(dev_a, &cb_one);
  pico_hotplug_register(dev_a, &cb_two);
  pico_hotplug_register(dev_b, &cb_two);

  fail_unless(timer_active == 1);

  timer_active = 0;
  timer_cb_function(0, NULL);
  fail_unless(timer_active == 1);
  fail_unless(cb_one_cntr == 0);
  fail_unless(cb_two_cntr == 0);

  state_a = 1;
  timer_active = 0;
  timer_cb_function(0, NULL);
  fail_unless(timer_active == 1);
  fail_unless(cb_one_cntr == 1);
  fail_unless(cb_one_last_event == PICO_HOTPLUG_EVENT_UP );
  fail_unless(cb_two_cntr == 1);
  fail_unless(cb_two_last_event == PICO_HOTPLUG_EVENT_UP );

  state_b = 1;
  timer_active = 0;
  timer_cb_function(0, NULL);
  fail_unless(timer_active == 1);
  fail_unless(cb_one_cntr == 1);
  fail_unless(cb_one_last_event == PICO_HOTPLUG_EVENT_UP );
  fail_unless(cb_two_cntr == 2);
  fail_unless(cb_two_last_event == PICO_HOTPLUG_EVENT_UP );

  state_a = 0;
  state_b = 0;
  timer_active = 0;
  timer_cb_function(0, NULL);
  fail_unless(timer_active == 1);
  fail_unless(cb_one_cntr == 2);
  fail_unless(cb_one_last_event == PICO_HOTPLUG_EVENT_DOWN );
  fail_unless(cb_two_cntr == 4);
  fail_unless(cb_two_last_event == PICO_HOTPLUG_EVENT_DOWN );
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_pico_hotplug_reg_dereg = tcase_create("Unit test for pico_hotplug_reg_dereg");
    TCase *TCase_pico_hotplug_callbacks = tcase_create("Unit test for pico_hotplug_callbacks");

    tcase_add_test(TCase_pico_hotplug_reg_dereg, tc_pico_hotplug_reg_dereg);
    suite_add_tcase(s, TCase_pico_hotplug_reg_dereg);
    tcase_add_test(TCase_pico_hotplug_callbacks, tc_pico_hotplug_callbacks);
    suite_add_tcase(s, TCase_pico_hotplug_callbacks);
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
