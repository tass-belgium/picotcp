#ifndef PICO_JOBS_H
#define PICO_JOBS_H
#include "pico_defines.h"
#include "pico_stack.h"

void pico_schedule_job(void (*exe)(void*), void *arg);
void pico_execute_pending_jobs(void);


#endif
