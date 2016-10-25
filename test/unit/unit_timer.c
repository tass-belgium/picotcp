#define EXISTING_TIMERS 7


START_TEST (test_timers)
{
    uint32_t T[128];
    int i;
    pico_stack_init();
    for (i = 0; i < 128; i++) {
        pico_time expire = (pico_time)(999999 + i);
        void (*timer)(pico_time, void *) =(void (*)(pico_time, void *))0xff00 + i;
        void *arg = ((void*)0xaa00 + i);

        T[i] = pico_timer_add(expire, timer, arg);
        printf("New timer %u\n", T[i]);
    }
    for (i = 0; i < 128; i++) {
        void (*timer)(pico_time, void *) =(void (*)(pico_time, void *))0xff00 + i;
        void *arg = ((void*)0xaa00 + i);

        fail_if((uint32_t)(i + 1) > Timers->n);
        fail_unless(Timers->top[i + EXISTING_TIMERS].id == T[i]);
        fail_unless(Timers->top[i + EXISTING_TIMERS].tmr->timer == timer);
        fail_unless(Timers->top[i + EXISTING_TIMERS].tmr->arg == arg);
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
