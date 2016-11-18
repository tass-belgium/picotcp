#include "pico_stack.h"

#if defined(PICO_SUPPORT_RTOS) || defined (PICO_SUPPORT_PTHREAD)
volatile uint32_t pico_ms_tick;
#endif

int main(void)
{
    pico_stack_init();
    pico_stack_tick();
    return 0;
}
