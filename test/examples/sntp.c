#include "utils.h"
#include <pico_sntp_client.h>
/*** START SNTP ***/

#ifdef PICO_SUPPORT_SNTP_CLIENT

void sntp_timeout(pico_time __attribute__((unused)) now, void *arg)
{
    struct pico_timeval ptv;
    struct timeval tv;
    pico_sntp_gettimeofday(&ptv);
    gettimeofday(&tv, NULL);
    printf("Linux   sec: %u, msec: %u\n", (unsigned int)tv.tv_sec, (unsigned int)tv.tv_usec / 1000);
    printf("Picotcp sec: %u, msec: %u\n", (unsigned int)ptv.tv_sec, (unsigned int)ptv.tv_msec);
    printf("SNTP test succesfull!\n");
    exit(0);
}

void cb_synced(pico_err_t status)
{
    if(status == PICO_ERR_ENETDOWN) {
        printf("SNTP: Cannot resolve ntp server name\n");
        exit(1);
    } else if (status == PICO_ERR_ETIMEDOUT) {
        printf("SNTP: Timed out, did not receive ntp packet from server\n");
        exit(1);
    } else if (status == PICO_ERR_EINVAL) {
        printf("SNTP: Conversion error\n");
        exit(1);
    } else if (status == PICO_ERR_ENOTCONN) {
        printf("SNTP: Socket error\n");
        exit(1);
    } else if (status == PICO_ERR_NOERR) {
        if (!pico_timer_add(2000, sntp_timeout, NULL)) {
            printf("SNTP: Failed to start timeout timer, exiting program \n");
            exit(1);
        }
    } else {
        printf("SNTP: Invalid status received in cb_synced\n");
        exit(1);
    }
}

void app_sntp(char *servername)
{
    struct pico_timeval tv;
    printf("Starting SNTP query towards %s\n", servername);
    if(pico_sntp_gettimeofday(&tv) == 0)
        printf("Wrongly succesfull gettimeofday\n");
    else
        printf("Unsuccesfull gettimeofday (not synced)\n");

    if(pico_sntp_sync(servername, &cb_synced) == 0)
        printf("Succesfull sync call!\n");
    else
        printf("Error in  sync\n");
}
#endif
/*** END SNTP ***/
