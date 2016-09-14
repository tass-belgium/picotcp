#include "utils.h"
#include <pico_ipv4.h>
#include <pico_device.h>
#include <pico_dhcp_server.h>

/*** START DHCP Server ***/
#ifdef PICO_SUPPORT_DHCPD
/* ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.1:255.255.0.0: -a dhcpserver:pic0:10.40.0.1:255.255.255.0:64:128
 * ./build/test/picoapp.elf --vde pic0:/tmp/pic0.ctl:10.40.0.10:255.255.255.0: --vde pic1:/tmp/pic1.ctl:10.50.0.10:255.255.255.0: \
 * -a dhcpserver:pic0:10.40.0.10:255.255.255.0:64:128:pic1:10.50.0.10:255.255.255.0:64:128
 */
void app_dhcp_server(char *arg)
{
    struct pico_device *dev = NULL;
    struct pico_dhcp_server_setting s = {
        0
    };
    int pool_start = 0, pool_end = 0;
    char *s_name = NULL, *s_addr = NULL, *s_netm = NULL, *s_pool_start = NULL, *s_pool_end = NULL;
    char *nxt = arg;

    if (!nxt)
        goto out;

    while (nxt) {
        if (nxt) {
            nxt = cpy_arg(&s_name, nxt);
            if (!s_name) {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_addr, nxt);
            if (s_addr) {
                pico_string_to_ipv4(s_addr, &s.server_ip.addr);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_netm, nxt);
            if (s_netm) {
                pico_string_to_ipv4(s_netm, &s.netmask.addr);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_pool_start, nxt);
            if (s_pool_start && atoi(s_pool_start)) {
                pool_start = atoi(s_pool_start);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        if (nxt) {
            nxt = cpy_arg(&s_pool_end, nxt);
            if (s_pool_end && atoi(s_pool_end)) {
                pool_end = atoi(s_pool_end);
            } else {
                goto out;
            }
        } else {
            goto out;
        }

        dev = (struct pico_device *)pico_get_device(s_name);
        if (dev == NULL) {
            fprintf(stderr, "No device with name %s found\n", s_name);
            exit(255);
        }

        s.dev = dev;
        s.pool_start = (s.server_ip.addr & s.netmask.addr) | long_be(pool_start);
        s.pool_end = (s.server_ip.addr & s.netmask.addr) | long_be(pool_end);

        pico_dhcp_server_initiate(&s);
    }
    return;

out:
    fprintf(stderr, "dhcpserver expects the following format: dhcpserver:dev_name:dev_addr:dev_netm:pool_start:pool_end\n");
    exit(255);

}
#endif
/*** END DHCP Server ***/
