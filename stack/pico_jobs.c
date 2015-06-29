#include "pico_jobs.h"
struct pico_job 
{
    void (*exe)(void *);
    void *arg;
    struct pico_job *next;
};



struct pico_job *pico_jobs_backlog = NULL;
struct pico_job *pico_jobs_backlog_tail = NULL;

/* static int max_jobs; */

void pico_schedule_job(void (*exe)(void*), void *arg)
{
    struct pico_job *job = PICO_ZALLOC(sizeof(struct pico_job));
    if  (!job)
        return;
    job->exe = exe;
    job->arg = arg;
    if (!pico_jobs_backlog) {
       pico_jobs_backlog = job;
       pico_jobs_backlog_tail = job;  
    } else {
        pico_jobs_backlog_tail->next = job;
        pico_jobs_backlog_tail = job;
    }
}

void pico_execute_pending_jobs(void)
{
    struct pico_job *job;
    /* int count = 0; */
    while(pico_jobs_backlog) {
        job = pico_jobs_backlog;
        if (job->exe) {
            job->exe(job->arg);
        }
        pico_jobs_backlog = job->next;
        PICO_FREE(job);
        /* count++; */
        if (!pico_jobs_backlog)
            pico_jobs_backlog_tail = NULL;
    }
    /*
    if (count > max_jobs) {
        printf("Max jobs = %d\n", count);
        max_jobs = count;
    }
    */
}
