#include "pico_stack.h"
int main(void)
{
    pico_stack_init();
    pico_stack_tick();
    return 0;
}
