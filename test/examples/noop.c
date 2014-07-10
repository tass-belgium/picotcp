/* NOOP */
void app_noop(void)
{
    while(1) {
        pico_stack_tick();
        usleep(2000);
    }
}

/* END NOOP */
