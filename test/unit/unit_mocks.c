#define BUFLEN (576 + 14 + 20 + 8)

int mock_print_protocol(uint8_t *buf);
int printbuf(uint8_t *buf, uint32_t len, const char *str, uint8_t printbufactive);
int tick_it(uint32_t nticks);

int mock_print_protocol(uint8_t *buf)
{
    uint8_t pnr = buf[0x17]; /* protocol number */

    printf("transport protocol: %s\n",
           (pnr == PICO_PROTO_ICMP4 ? "icmp4" :
            (pnr == PICO_PROTO_IGMP ? "igmp" :
             (pnr == PICO_PROTO_TCP   ? "tcp" :
              (pnr == PICO_PROTO_UDP   ? "udp" :
               (pnr == PICO_PROTO_ICMP6 ? "icmp6" :
                "unknown proto"))))));
    return 0;
}

int printbuf(uint8_t *buf, uint32_t len, const char *str, uint8_t printbufactive)
{
    uint8_t printMethod = 0;
    uint32_t cntr = 0;
    uint32_t cntr2 = 0;
    if((printbufactive) && (printMethod == 0)) {
        printf("\n%s:\n", str);
        for(cntr = 0; cntr < len; cntr++) {
            if((cntr % 8) == 0 && cntr != 0)
                printf(" ");

            if((cntr % 16) == 0 && cntr != 0)
                printf("\n");

            if((cntr % 16) == 0)
                printf("%03x0  ", cntr2++);

            printf("%02x ", buf[cntr]);
        }
        printf("\n");
    }else if((printbufactive) && (printMethod == 1)) {
        printf("\n%s:\n", str);
        printf("Buf = {");
        for(cntr = 0; cntr < len; cntr++) {
            if(cntr != 0)
                printf(",");

            if((cntr % 16 == 0) && (cntr != 0))
                printf("\n");

            printf("0x%02x", buf[cntr]);
        }
        printf("}\n");
    }

    return 0;
}

#define BUFLEN (576 + 14 + 20 + 8)
#define DHCP_MSG_TYPE_DISCOVER (1)
#define DHCP_MSG_TYPE_OFFER    (2)
#define DHCP_MSG_TYPE_REQUEST  (3)
#define DHCP_MSG_TYPE_ACK      (4)
int tick_it(uint32_t nticks)
{
    uint32_t i = 0;
    for (i = 0; i < nticks; i++) {
        pico_stack_tick();
    }
    return 0;
}
