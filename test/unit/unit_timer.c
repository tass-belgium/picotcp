

START_TEST (test_timers)
{
    struct pico_timer *T[128];
    int i;
    pico_stack_init();
    for (i = 0; i < 128; i++) {
        T[i] = pico_timer_add(999999 + i, 0xff00 + i, 0xaa00 + i);
        printf("New timer @ %p (%x-%x)\n", T[i], T[i]->timer, T[i]->arg);
    }
    for (i = 0; i < 128; i++) {
        fail_if(i + 1 > Timers->n);
        fail_unless(Timers->top[i + 3].tmr == T[i]);
        fail_unless(T[i]->timer == (0xff00 + i));
        fail_unless(T[i]->arg == (0xaa00 + i));
    }
    for (i = 0; i < 128; i++) {
        printf("Deleting timer %d \n", i );
        pico_timer_cancel(T[i]);
        printf("Deleted timer %d \n", i );
        fail_unless(Timers->top[i + 3].tmr == NULL);
    }
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
    pico_stack_tick();
}
END_TEST
