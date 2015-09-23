#include "utils.h"
#include <pico_slaacv4.h>
#include <pico_icmp4.h>
/*** START SLAACV4 ***/

void ping_callback_slaacv4(struct pico_icmp4_stats *s)
{
    char host[30] = { };

    pico_ipv4_to_string(host, s->dst.addr);
    if (s->err == 0) {
        dbg("SLAACV4: %lu bytes from %s: icmp_req=%lu ttl=64 time=%lu ms\n", s->size, host,
            s->seq, (long unsigned int)s->time);
        if (s->seq >= 3) {
            dbg("SLAACV4: TEST SUCCESS!\n");
            pico_slaacv4_unregisterip();
            exit(0);
        }
    } else {
        dbg("SLAACV4: ping %lu to %s error %d\n", s->seq, host, s->err);
        dbg("SLAACV4: TEST FAILED!\n");
        exit(1);
    }
}

void slaacv4_cb(struct pico_ip4 *ip, uint8_t code)
{
    char dst[16] = "169.254.22.5";
    printf("SLAACV4 CALLBACK ip:0x%X code:%d \n", ip->addr, code);
    if (code == 0)
    {
#ifdef PICO_SUPPORT_PING
        pico_icmp4_ping(dst, 3, 1000, 5000, 32, ping_callback_slaacv4);
#else
        exit(0);
#endif
    }
    else
    {
        exit(255);
    }

}


void app_slaacv4(char *arg)
{
    char *sdev = NULL;
    char *nxt = arg;
    struct pico_device *dev = NULL;

    if (!nxt)
        exit(255);

    while (nxt) {
        if (nxt) {
            nxt = cpy_arg(&sdev, nxt);
            if(!sdev) {
                exit(255);
            }
        }
    }
    dev = pico_get_device(sdev);
    free(sdev);
    if(dev == NULL) {
        printf("%s: error getting device %s: %s\n", __FUNCTION__, dev->name, strerror(pico_err));
        exit(255);
    }

    pico_slaacv4_claimip(dev, slaacv4_cb);
}
/*** END SLAACv4 ***/
