#define EXISTING_TIMERS 5


START_TEST (test_timers)
{
    uint32_t T[128];
    int i;
    pico_stack_init();
    for (i = 0; i < 128; i++) {
        T[i] = pico_timer_add(999999 + i, 0xff00 + i, 0xaa00 + i);
        printf("New timer %lu\n", T[i]);
    }
    for (i = 0; i < 128; i++) {
        fail_if(i + 1 > Timers->n);
        fail_unless(Timers->top[i + EXISTING_TIMERS].id == T[i]);
        fail_unless(Timers->top[i + EXISTING_TIMERS].tmr->timer == (0xff00 + i));
        fail_unless(Timers->top[i + EXISTING_TIMERS].tmr->arg == (0xaa00 + i));
    }
    for (i = 127; i >= 0; i--) {
        printf("Deleting timer %d \n", i );
        pico_timer_cancel(T[i]);
        printf("Deleted timer %d \n", i );
        fail_unless(Timers->top[i + EXISTING_TIMERS].tmr == NULL);
    }
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
}
END_TEST
