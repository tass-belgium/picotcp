/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera, Kristof Roelants
 *********************************************************************/


#include "pico_ipv6.h"
#include "pico_icmp6.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"

#ifdef PICO_SUPPORT_IPV6

#define PICO_IPV6_EXTHDR_HOPBYHOP 0
#define PICO_IPV6_EXTHDR_ROUTING 43
#define PICO_IPV6_EXTHDR_FRAG 44
#define PICO_IPV6_EXTHDR_ESP 50
#define PICO_IPV6_EXTHDR_AUTH 51
#define PICO_IPV6_EXTHDR_NONE 59
#define PICO_IPV6_EXTHDR_DESTOPT 60

#define PICO_IPV6_EXTHDR_OPT_PAD1 0
#define PICO_IPV6_EXTHDR_OPT_PADN 1
#define PICO_IPV6_EXTHDR_OPT_SRCADDR 201

#define PICO_IPV6_EXTHDR_OPT_ACTION_MASK 0xC0 /* highest-order two bits */
#define PICO_IPV6_EXTHDR_OPT_ACTION_SKIP 0x00 /* skip and continue processing */
#define PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD 0x40 /* discard packet */
#define PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SI 0x80 /* discard and send ICMP parameter problem */
#define PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SINM 0xC0 /* discard and send ICMP parameter problem if not multicast */

#define PICO_IPV6_MAX_RTR_SOLICITATION_DELAY 1000

#define ipv6_dbg(...) do {} while(0)
/* #define ipv6_dbg dbg   */

/* queues */
static struct pico_queue ipv6_in;
static struct pico_queue ipv6_out;

const uint8_t PICO_IP6_ANY[PICO_SIZE_IP6] = {
    0
};

struct pico_ipv6_hbhoption {
    uint8_t type;
    uint8_t len;
    uint8_t options[0];
};

struct pico_ipv6_destoption {
    uint8_t type;
    uint8_t len;
    uint8_t options[0];
};

struct pico_ipv6_route
{
    struct pico_ip6 dest;
    struct pico_ip6 netmask;
    struct pico_ip6 gateway;
    struct pico_ipv6_link *link;
    uint32_t metric;
};

int pico_ipv6_compare(struct pico_ip6 *a, struct pico_ip6 *b)
{
    uint32_t i;
    for (i = 0; i < sizeof(struct pico_ip6); i++) {
        if (a->addr[i] < b->addr[i])
            return -1;

        if (a->addr[i] > b->addr[i])
            return 1;
    }
    return 0;
}

static int ipv6_link_compare(void *ka, void *kb)
{
    struct pico_ipv6_link *a = ka, *b = kb;
    struct pico_ip6 *a_addr, *b_addr;
    int ret;
    a_addr = &a->address;
    b_addr = &b->address;

    ret = pico_ipv6_compare(a_addr, b_addr);
    if (ret)
        return ret;

    /* zero can be assigned multiple times (e.g. for DHCP) */
    if (a->dev != NULL && b->dev != NULL && !memcmp(a->address.addr, PICO_IP6_ANY, PICO_SIZE_IP6) && !memcmp(b->address.addr, PICO_IP6_ANY, PICO_SIZE_IP6)) {
        /* XXX change PICO_IP6_ANY */
        if (a->dev < b->dev)
            return -1;

        if (a->dev > b->dev)
            return 1;
    }

    return 0;
}

static inline int ipv6_compare_metric(struct pico_ipv6_route *a, struct pico_ipv6_route *b)
{
    if (a->metric < b->metric)
        return -1;

    if (a->metric > b->metric)
        return 1;

    return 0;
}

static int ipv6_route_compare(void *ka, void *kb)
{
    struct pico_ipv6_route *a = ka, *b = kb;
    int ret;

    /* Routes are sorted by (host side) netmask len, then by addr, then by metric. */
    ret = pico_ipv6_compare(&a->netmask, &b->netmask);
    if (ret)
        return ret;

    ret = pico_ipv6_compare(&a->dest, &b->dest);
    if (ret)
        return ret;

    return ipv6_compare_metric(a, b);

}
PICO_TREE_DECLARE(IPV6Routes, ipv6_route_compare);
PICO_TREE_DECLARE(IPV6Links, ipv6_link_compare);

static char pico_ipv6_dec_to_char(uint8_t u)
{
    if (u < 10)
        return (char)('0' + u);
    else if (u < 16)
        return (char)('a' + (u - 10));
    else
        return '0';
}

static int pico_ipv6_hex_to_dec(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');

    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');

    return 0;
}

int pico_ipv6_to_string(char *ipbuf, const uint8_t ip[PICO_SIZE_IP6])
{
    uint8_t dec = 0, i = 0;

    if (!ipbuf) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* every nibble is one char */
    for (i = 0; i < ((uint8_t)PICO_SIZE_IP6) * 2u; ++i) {
        if (i % 4 == 0 && i != 0)
            *ipbuf++ = ':';

        if (i % 2 == 0) { /* upper nibble */
            dec = ip[i / 2] >> 4;
        } else { /* lower nibble */
            dec = ip[i / 2] & 0x0F;
        }

        *ipbuf++ = pico_ipv6_dec_to_char(dec);
    }
    *ipbuf = '\0';

    return 0;
}

int pico_string_to_ipv6(const char *ipstr, uint8_t *ip)
{
    uint8_t buf[PICO_SIZE_IP6] = {
        0
    };
    uint8_t doublecolon = 0, byte = 0;
    char p = 0;
    int i = 0, diff = 0, nibble = 0, hex = 0, colons = 0;
    int zeros = 0, shift = 0;

    pico_err = PICO_ERR_EINVAL;
    if (!ipstr || !ip)
        return -1;

    memset(ip, 0, PICO_SIZE_IP6);

    while((p = *ipstr++) != 0)
    {
        if (pico_is_hex(p) || (p == ':') || *ipstr == '\0') { /* valid signs */
            if (pico_is_hex(p)) {
                buf[byte] = (uint8_t)((buf[byte] << 4) + pico_ipv6_hex_to_dec(p));
                if (++nibble % 2 == 0)
                    ++byte;
            }

            if (p == ':' || *ipstr == '\0') { /* account for leftout leading zeros */
                ++hex;
                if (p == ':')
                    ++colons;

                diff = (hex * 4) - nibble;
                nibble += diff;
                switch (diff) {
                case 0:
                    /* 16-bit hex block ok f.e. 1db8 */
                    break;
                case 1:
                    /* one zero f.e. db8: byte = 1, buf[byte-1] = 0xdb, buf[byte] = 0x08 */
                    buf[byte] |= (uint8_t)(buf[byte - 1] << 4);
                    buf[byte - 1] >>= 4;
                    byte++;
                    break;
                case 2:
                    /* two zeros f.e. b8: byte = 1, buf[byte] = 0x00, buf[byte-1] = 0xb8 */
                    buf[byte] = buf[byte - 1];
                    buf[byte - 1] = 0x00;
                    byte++;
                    break;
                case 3:
                    /* three zeros f.e. 8: byte = 0, buf[byte] = 0x08, buf[byte+1] = 0x00 */
                    buf[byte + 1] = buf[byte];
                    buf[byte] = 0x00;
                    byte = (uint8_t)(byte + 2);
                    break;
                case 4:
                    /* case of :: */
                    if (doublecolon && colons != 2) /* catch case x::x::x but not ::x */
                        return -1;
                    else
                        doublecolon = byte;

                    break;
                default:
                    /* case of missing colons f.e. 20011db8 instead of 2001:1db8 */
                    return -1;
                }
            }
        } else {
            return -1;
        }
    }
    if (colons < 2) /* valid IPv6 has atleast two colons */
        return -1;

    /* account for leftout :: zeros */
    zeros = PICO_SIZE_IP6 - byte;
    if (zeros) {
        shift = PICO_SIZE_IP6 - zeros - doublecolon;
        for (i = shift; i >= 0; --i) {
            /* (i-1) as arrays are indexed from 0 onwards */
            buf[doublecolon + zeros + (i - 1)] = buf[doublecolon + (i - 1)];
        }
        memset(&buf[doublecolon], 0, (size_t)zeros);
    }

    memcpy(ip, buf, 16);
    pico_err = PICO_ERR_NOERR;
    return 0;
}

int pico_ipv6_is_linklocal(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: fe80::/10 */
    if ((addr[0] == 0xfe) && ((addr[1] >> 6) == 0x02))
        return 1;

    return 0;
}

int pico_ipv6_is_sitelocal(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: fec0::/10 */
    if ((addr[0] == 0xfe) && ((addr[1] >> 6) == 0x03))
        return 1;

    return 0;
}

int pico_ipv6_is_uniquelocal(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: fc00::/7 */
    if (((addr[0] >> 1) == 0x7e))
        return 1;

    return 0;
}

int pico_ipv6_is_global(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: 2000::/3 */
    if (((addr[0] >> 5) == 0x01))
        return 1;

    return 0;
}

int pico_ipv6_is_localhost(const uint8_t addr[PICO_SIZE_IP6])
{
    const uint8_t localhost[PICO_SIZE_IP6] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    if (memcmp(addr, localhost, PICO_SIZE_IP6) == 0)
        return 1;

    return 0;

}

int pico_ipv6_is_unicast(struct pico_ip6 *a)
{
    if (pico_ipv6_is_global(a->addr))
        return 1;
    else if (pico_ipv6_is_uniquelocal(a->addr))
        return 1;
    else if (pico_ipv6_is_sitelocal(a->addr))
        return 1;
    else if (pico_ipv6_is_linklocal(a->addr))
        return 1;
    else if (pico_ipv6_is_localhost(a->addr))
        return 1;
    else if(pico_ipv6_link_get(a))
        return 1;
    else
        return 0;
}

int pico_ipv6_is_multicast(const uint8_t addr[PICO_SIZE_IP6])
{
    /* prefix: ff00::/8 */
    if ((addr[0] == 0xff))
        return 1;

    return 0;
}

int pico_ipv6_is_solicited(const uint8_t addr[PICO_SIZE_IP6])
{
    struct pico_ip6 solicited_node = {{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00 }};
    return !memcmp(solicited_node.addr, addr, 13);
}

int pico_ipv6_is_unspecified(const uint8_t addr[PICO_SIZE_IP6])
{
    return !memcmp(PICO_IP6_ANY, addr, PICO_SIZE_IP6);
}

int pico_ipv6_rebound(struct pico_frame *f)
{
    struct pico_ip6 dst = {{0}};
    struct pico_ipv6_hdr *hdr = NULL;

    if(!f)
        return -1;

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    if (!hdr)
        return -1;

    dst = hdr->src;

    return pico_ipv6_frame_push(f, &dst, hdr->nxthdr);
}

static struct pico_ipv6_route *pico_ipv6_route_find(const struct pico_ip6 *addr)
{
    struct pico_ipv6_route *r = NULL;
    struct pico_tree_node *index = NULL;
    int i = 0;

    pico_tree_foreach_reverse(index, &IPV6Routes)
    {
        r = index->keyValue;
        for (i = 0; i < PICO_SIZE_IP6; ++i) {
            if ((addr->addr[i] & (r->netmask.addr[i])) != ((r->dest.addr[i]) & (r->netmask.addr[i]))) {
                break;
            }

            if (i + 1 == PICO_SIZE_IP6) {
                return r;
            }
        }
    }
    return NULL;
}

struct pico_ip6 *pico_ipv6_source_find(const struct pico_ip6 *dst)
{
    struct pico_ip6 *myself = NULL;
    struct pico_ipv6_route *rt;

    if(!dst) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    rt = pico_ipv6_route_find(dst);
    if (rt) {
        myself = &rt->link->address;
    } else
        pico_err = PICO_ERR_EHOSTUNREACH;

    return myself;
}

static int pico_ipv6_forward(struct pico_frame *f)
{
    pico_frame_discard(f);
    return 0;
}

int pico_ipv6_process_hopbyhop(struct pico_ipv6_exthdr *hbh, struct pico_frame *f)
{
    uint8_t *option = NULL;
    uint8_t len = 0, optlen = 0;
    uint32_t ptr = sizeof(struct pico_ipv6_hdr);
    uint8_t *extensions_start = (uint8_t *)hbh;

    IGNORE_PARAMETER(f);

    option = hbh->ext.hopbyhop.options;
    len = (uint8_t)(((hbh->ext.hopbyhop.len + 1) << 3) - 2); /* len in bytes, minus nxthdr and len byte */
    ipv6_dbg("IPv6: hop by hop extension header length %u\n", len + 2);
    while (len) {
        switch (*option)
        {
        case PICO_IPV6_EXTHDR_OPT_PAD1:
            ++option;
            --len;
            break;

        case PICO_IPV6_EXTHDR_OPT_PADN:
            optlen = (uint8_t)((*(option + 1)) + 2); /* plus type and len byte */
            option += optlen;
            len = (uint8_t)(len - optlen);
            break;

        default:
            /* unknown option */
            optlen = (uint8_t)(*(option + 1) + 2); /* plus type and len byte */
            switch ((*option) & PICO_IPV6_EXTHDR_OPT_ACTION_MASK) {
            case PICO_IPV6_EXTHDR_OPT_ACTION_SKIP:
                break;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD:
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SI:
                pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_IPV6OPT, ptr + (uint32_t)(option - extensions_start));
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SINM:
                /* TODO DLA: check if not multicast */
                pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_IPV6OPT, ptr + (uint32_t)(option - extensions_start));
                return -1;
            }
            ipv6_dbg("IPv6: option with type %u and length %u\n", *option, optlen);
            option += optlen;
            len = (uint8_t)(len - optlen);
        }
    }
    return 0;
}


int pico_ipv6_process_routing(struct pico_ipv6_exthdr *routing, struct pico_frame *f)
{
    IGNORE_PARAMETER(f);

    ipv6_dbg("IPv6: routing extension header with len %u\n", routing->ext.routing.len + 2);
    switch (routing->ext.routing.routtype) {
    case 0x00:
        /* deprecated */
        break;
    case 0x02:
        /* routing type for MIPv6: not supported yet */
        break;
    default:
        /* XXX: ICMP parameter problem (code 0) */
        return -1;
    }
    return 0;
}

int pico_ipv6_process_frag(struct pico_ipv6_exthdr *fragm, struct pico_frame *f)
{
    IGNORE_PARAMETER(fragm);
    IGNORE_PARAMETER(f);

    ipv6_dbg("IPv6: fragmentation extension header\n");
    return 0;
}

int pico_ipv6_process_destopt(struct pico_ipv6_exthdr *destopt, struct pico_frame *f)
{
    uint8_t *option = NULL;
    uint8_t len = 0, optlen = 0;

    IGNORE_PARAMETER(f);

    option = destopt->ext.destopt.options;
    len = (uint8_t)(((destopt->ext.destopt.len + 1) << 3) - 2); /* len in bytes, minus nxthdr and len byte */
    ipv6_dbg("IPv6: destination option extension header length %u\n", len + 2);
    while (len) {
        switch (*option)
        {
        case PICO_IPV6_EXTHDR_OPT_PAD1:
            ++option;
            --len;
            break;

        case PICO_IPV6_EXTHDR_OPT_PADN:
            optlen = (uint8_t)(*(option + 1) + 2); /* plus type and len byte */
            option += optlen;
            len = (uint8_t)(len - optlen);
            break;

        case PICO_IPV6_EXTHDR_OPT_SRCADDR:
            optlen = (uint8_t)(*(option + 1) + 2); /* plus type and len byte */
            option += optlen;
            len = (uint8_t)(len - optlen); /* 2 = 1 byte for option type and 1 byte for option length */
            ipv6_dbg("IPv6: home address option with length %u\n", optlen);
            break;

        default:
            optlen = *(option + 1);
            ipv6_dbg("IPv6: option with type %u and length %u\n", *option, optlen + 2);
            switch ((*option) & PICO_IPV6_EXTHDR_OPT_ACTION_MASK) {
            case PICO_IPV6_EXTHDR_OPT_ACTION_SKIP:
                break;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD:
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SI:
                /* XXX: send ICMP parameter problem (code 2), pointing to the unrecognized option type */
                return -1;
            case PICO_IPV6_EXTHDR_OPT_ACTION_DISCARD_SINM:
                /* XXX: if destination address was not a multicast address, send an ICMP parameter problem (code 2) */
                return -1;
            }
            option += optlen + 2;
            len = (uint8_t)(len - optlen + 2); /* 2 = 1 byte for option type and 1 byte for option length */
            break;
        }
    }
    return 0;
}

static int pico_ipv6_extension_headers(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    uint8_t nxthdr = hdr->nxthdr;
    struct pico_ipv6_exthdr *exthdr = NULL;
    uint32_t ptr = sizeof(struct pico_ipv6_hdr);
    int is_ipv6_hdr = 1; /* ==1 indicates that the option being parsed is in the header,
                          * rather than in an extension.
                          */

    f->net_len = sizeof(struct pico_ipv6_hdr);
    for (;; ) {
        exthdr = (struct pico_ipv6_exthdr *)(f->net_hdr + f->net_len);
        switch (nxthdr) {
        case PICO_IPV6_EXTHDR_HOPBYHOP:
            /* The Hop-by-Hop Options header,
             * when present, must immediately follow the IPv6 header.
             */
            if (!is_ipv6_hdr) {
                pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_NXTHDR, ptr);
                return -1;
            }

            f->net_len = (uint16_t)(f->net_len + ((exthdr->ext.hopbyhop.len + 1) << 3));
            if (pico_ipv6_process_hopbyhop(exthdr, f) < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_ROUTING:
            f->net_len = (uint16_t)(f->net_len + ((exthdr->ext.routing.len + 1) << 3));
            if (pico_ipv6_process_routing(exthdr, f) < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_FRAG:
            f->net_len = (uint16_t)(f->net_len + 8); /* fixed length */
            if (pico_ipv6_process_frag(exthdr, f) < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_DESTOPT:
            f->net_len = (uint16_t)(f->net_len + ((exthdr->ext.destopt.len + 1) << 3));
            if (pico_ipv6_process_destopt(exthdr, f) < 0)
                return -1;

            break;
        case PICO_IPV6_EXTHDR_ESP:
            /* not supported, ignored. */
            return 0;
        case PICO_IPV6_EXTHDR_AUTH:
            /* not supported, ignored */
            return 0;
        case PICO_IPV6_EXTHDR_NONE:
            /* no next header */
            return 0;

        case PICO_PROTO_TCP:
        case PICO_PROTO_UDP:
        case PICO_PROTO_ICMP6:
            f->transport_hdr = f->net_hdr + f->net_len;
            f->transport_len = (uint16_t)(short_be(hdr->len) - (f->net_len - sizeof(struct pico_ipv6_hdr)));
            return nxthdr;
        default:
            if (is_ipv6_hdr)
                pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_NXTHDR, 6); /* 6 is the pos of next hdr field */
            else
                pico_icmp6_parameter_problem(f, PICO_ICMP6_PARAMPROB_NXTHDR, ptr);

            return -1;
        }
        nxthdr = exthdr->nxthdr;
        if (!is_ipv6_hdr)
            ptr += (uint32_t)sizeof(struct pico_ipv6_exthdr);

        is_ipv6_hdr = 0;
    }
}

int pico_ipv6_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    int proto = 0;
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;

    IGNORE_PARAMETER(self);

    proto = pico_ipv6_extension_headers(f);
    if (proto <= 0) {
        pico_frame_discard(f);
        return 0;
    }

    f->proto = (uint8_t)proto;
    ipv6_dbg("IPv6: payload %u net_len %u nxthdr %u\n", short_be(hdr->len), f->net_len, proto);


    if (0) {
    } else if (pico_ipv6_is_unicast(&hdr->dst)) {
        pico_transport_receive(f, f->proto);
    } else if (pico_ipv6_is_multicast(hdr->dst.addr)) {
        /* XXX perform multicast filtering: solicited-node multicast address MUST BE allowed! */
        pico_transport_receive(f, f->proto);
    } else {
        /* not local, try to forward. */
        pico_ipv6_forward(f);
    }

    return 0;
}

int pico_ipv6_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);

    f->start = (uint8_t*)f->net_hdr;
    return pico_sendto_dev(f);
}

/* allocates an IPv6 packet without extension headers. If extension headers are needed,
 * include the len of the extension headers in the size parameter. Once a frame acquired
 * increment net_len and transport_hdr with the len of the extension headers, decrement
 * transport_len with this value.
 */
static struct pico_frame *pico_ipv6_alloc(struct pico_protocol *self, uint16_t size)
{
    struct pico_frame *f =  pico_frame_alloc((uint32_t)(size + PICO_SIZE_IP6HDR + PICO_SIZE_ETHHDR));

    IGNORE_PARAMETER(self);

    if (!f)
        return NULL;

    f->datalink_hdr = f->buffer;
    f->net_hdr = f->buffer + PICO_SIZE_ETHHDR;
    f->net_len = PICO_SIZE_IP6HDR;
    f->transport_hdr = f->net_hdr + PICO_SIZE_IP6HDR;
    f->transport_len = (uint16_t)size;
    /* PICO_SIZE_ETHHDR is accounted for in pico_ethernet_send */
    f->len =  (uint32_t)(size + PICO_SIZE_IP6HDR);
    return f;
}

static inline int ipv6_pushed_frame_valid(struct pico_frame *f, struct pico_ip6 *dst)
{
    struct pico_ipv6_hdr *hdr = NULL;
    if(!f || !dst)
        return -1;

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    if (!hdr) {
        dbg("IPv6: IP header error\n");
        return -1;
    }

    return 0;
}

static inline struct pico_ipv6_route *ipv6_pushed_frame_checks(struct pico_frame *f, struct pico_ip6 *dst)
{
    struct pico_ipv6_route *route = NULL;

    if (ipv6_pushed_frame_valid(f, dst) < 0)
        return NULL;

    if (memcmp(dst->addr, PICO_IP6_ANY, PICO_SIZE_IP6) == 0) {
        dbg("IPv6: IP destination address error\n");
        return NULL;
    }

    route = pico_ipv6_route_find(dst);
    if (!route) {
        dbg("IPv6: route not found.\n");
        pico_err = PICO_ERR_EHOSTUNREACH;
        return NULL;
    }

    return route;
}

static inline void ipv6_push_hdr_adjust(struct pico_frame *f, struct pico_ipv6_link *link, struct pico_ip6 *dst,  uint8_t proto)
{
    struct pico_icmp6_hdr *icmp6_hdr = NULL;
    struct pico_ipv6_hdr *hdr = NULL;
    const uint8_t vtf = (uint8_t)long_be(0x60000000); /* version 6, traffic class 0, flow label 0 */

    hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    hdr->vtf = vtf;
    hdr->len = short_be((uint16_t)(f->transport_len + f->net_len - (uint16_t)sizeof(struct pico_ipv6_hdr)));
    hdr->nxthdr = proto;
    hdr->hop = f->dev->hostvars.hoplimit;
    hdr->src = link->address;
    hdr->dst = *dst;

    /* make adjustments to defaults according to proto */
    switch (proto)
    {
    case PICO_PROTO_ICMP6:
    {
        icmp6_hdr = (struct pico_icmp6_hdr *)f->transport_hdr;
        if (icmp6_hdr->type == PICO_ICMP6_NEIGH_SOL || icmp6_hdr->type == PICO_ICMP6_NEIGH_ADV)
            hdr->hop = 255;

        if (icmp6_hdr->type == PICO_ICMP6_NEIGH_SOL && link->istentative)
            memcpy(hdr->src.addr, PICO_IP6_ANY, PICO_SIZE_IP6);

        icmp6_hdr->crc = 0;
        icmp6_hdr->crc = short_be(pico_icmp6_checksum(f));
        break;
    }
    case PICO_PROTO_UDP:
    {
        struct pico_udp_hdr *udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
        udp_hdr->crc = pico_udp_checksum_ipv6(f);
        break;
    }

    default:
        break;
    }

}

static int ipv6_frame_push_final(struct pico_frame *f)
{
    struct pico_ipv6_hdr *hdr = NULL;
    hdr = (struct pico_ipv6_hdr *)f->net_hdr;

    if(pico_ipv6_link_get(&hdr->dst)) {
        return pico_enqueue(&ipv6_in, f);
    }
    else {
        return pico_enqueue(&ipv6_out, f);
    }


}

int pico_ipv6_frame_push(struct pico_frame *f, struct pico_ip6 *dst, uint8_t proto)
{
    struct pico_ipv6_route *route = NULL;
    struct pico_ipv6_link *link = NULL;


    route = ipv6_pushed_frame_checks(f, dst);
    if (!route) {
        pico_frame_discard(f);
        return -1;
    }

    link = route->link;

    if (f->sock && f->sock->dev)
        f->dev = f->sock->dev;
    else
        f->dev = link->dev;


    #if 0
    if (pico_ipv6_is_multicast(hdr->dst.addr)) {
        /* XXX: reimplement loopback */
    }

    #endif

    ipv6_push_hdr_adjust(f, link, dst, proto);

    return ipv6_frame_push_final(f);

}

static int pico_ipv6_frame_sock_push(struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_ip6 *dst = NULL;
    struct pico_remote_endpoint *remote_endpoint = NULL;

    IGNORE_PARAMETER(self);

    if (!f->sock) {
        pico_frame_discard(f);
        return -1;
    }

    remote_endpoint = (struct pico_remote_endpoint *)f->info;
    if (remote_endpoint) {
        dst = &remote_endpoint->remote_addr.ip6;
    } else {
        dst = &f->sock->remote_addr.ip6;
    }

    return pico_ipv6_frame_push(f, dst, (uint8_t)f->sock->proto->proto_number);
}

/* interface: protocol definition */
struct pico_protocol pico_proto_ipv6 = {
    .name = "ipv6",
    .proto_number = PICO_PROTO_IPV6,
    .layer = PICO_LAYER_NETWORK,
    .alloc = pico_ipv6_alloc,
    .process_in = pico_ipv6_process_in,
    .process_out = pico_ipv6_process_out,
    .push = pico_ipv6_frame_sock_push,
    .q_in = &ipv6_in,
    .q_out = &ipv6_out,
};

#ifdef DEBUG_ROUTE
static void pico_ipv6_dbg_route(void)
{
    struct pico_ipv6_route *r;
    struct pico_tree_node *index;
    pico_tree_foreach(index, &Routes){
        r = index->keyValue;
        dbg("Route to %08x/%08x, gw %08x, dev: %s, metric: %d\n", r->dest.addr, r->netmask.addr, r->gateway.addr, r->link->dev->name, r->metric);
    }
}
#else
#define pico_ipv6_dbg_route() do { } while(0)
#endif

static inline struct pico_ipv6_route *ipv6_route_add_link(struct pico_ip6 gateway)
{
    struct pico_ip6 zerogateway = {{0}};
    struct pico_ipv6_route *r = pico_ipv6_route_find(&gateway);
    if (!r ) { /* Specified Gateway is unreachable */
        pico_err = PICO_ERR_EHOSTUNREACH;
        return NULL;
    }

    if (memcmp(r->gateway.addr, zerogateway.addr, PICO_SIZE_IP6) != 0) { /* Specified Gateway is not a neighbor */
        pico_err = PICO_ERR_ENETUNREACH;
        return NULL;
    }

    return r;
}

int pico_ipv6_route_add(struct pico_ip6 address, struct pico_ip6 netmask, struct pico_ip6 gateway, int metric, struct pico_ipv6_link *link)
{
    struct pico_ip6 zerogateway = {{0}};
    struct pico_ipv6_route test, *new = NULL;
    char ipstr[40];
    test.dest = address;
    test.netmask = netmask;
    test.metric = (uint32_t)metric;
    pico_ipv6_to_string(ipstr, address.addr);
    if (pico_tree_findKey(&IPV6Routes, &test)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    new = PICO_ZALLOC(sizeof(struct pico_ipv6_route));
    if (!new) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    ipv6_dbg("Adding IPV6 static route\n");

    new->dest = address;
    new->netmask = netmask;
    new->gateway = gateway;
    new->metric = (uint32_t)metric;
    if (memcmp(gateway.addr, zerogateway.addr, PICO_SIZE_IP6) == 0) {
        /* No gateway provided, use the link */
        new->link = link;
    } else {
        struct pico_ipv6_route *r = ipv6_route_add_link(gateway);
        if (!r) {
            PICO_FREE(new);
            return -1;
        }

        new->link = r->link;
    }

    if (!new->link) {
        pico_err = PICO_ERR_EINVAL;
        PICO_FREE(new);
        return -1;
    }

    pico_tree_insert(&IPV6Routes, new);
    pico_ipv6_dbg_route();
    return 0;
}

int pico_ipv6_route_del(struct pico_ip6 address, struct pico_ip6 netmask, struct pico_ip6 gateway, int metric, struct pico_ipv6_link *link)
{
    struct pico_ipv6_route test, *found = NULL;

    IGNORE_PARAMETER(gateway);

    if (!link) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.dest = address;
    test.netmask = netmask;
    test.metric = (uint32_t)metric;

    found = pico_tree_findKey(&IPV6Routes, &test);
    if (found) {
        pico_tree_delete(&IPV6Routes, found);
        PICO_FREE(found);
        pico_ipv6_dbg_route();
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}

void pico_ipv6_nd_dad(unsigned long now, void *arg)
{
    struct pico_ip6 address = *(struct pico_ip6 *)arg;
    struct pico_ipv6_link *l = NULL;

    IGNORE_PARAMETER(now);

    l = pico_ipv6_link_istentative(&address);
    if (l->isduplicate) {
        dbg("IPv6: duplicate address.\n");
        if (pico_ipv6_is_linklocal(address.addr)) {
            address.addr[8] = ((uint8_t)(pico_rand() & 0xff) & (uint8_t)(~0x03));
            address.addr[9] = pico_rand() & 0xff;
            address.addr[10] = pico_rand() & 0xff;
            address.addr[11] = pico_rand() & 0xff;
            address.addr[12] = pico_rand() & 0xff;
            address.addr[13] = pico_rand() & 0xff;
            address.addr[14] = pico_rand() & 0xff;
            address.addr[15] = pico_rand() & 0xff;
            pico_ipv6_link_add(l->dev, address, l->netmask);
        }

        pico_ipv6_link_del(l->dev, l->address);
    }
    else {
        dbg("IPv6: non duplicate address.\n");
        l->istentative = 0;
    }
}


int pico_ipv6_link_add(struct pico_device *dev, struct pico_ip6 address, struct pico_ip6 netmask)
{
    struct pico_ipv6_link test = {
        0
    }, *new = NULL;
    struct pico_ip6 network = {{0}}, gateway = {{0}};
    struct pico_ip6 mcast_addr = {{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    struct pico_ip6 mcast_nm = {{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    struct pico_ip6 mcast_gw = {{0}};
    char ipstr[40] = {
        0
    };
    int i = 0;

    if (!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.address = address;
    test.dev = dev;
    /** XXX: Valid netmask / unicast address test **/

    if (pico_tree_findKey(&IPV6Links, &test)) {
        dbg("IPv6: trying to assign an invalid address (in use)\n");
        pico_err = PICO_ERR_EADDRINUSE;
        return -1;
    }

    /** XXX: Check for network already in use (e.g. trying to assign 10.0.0.1/24 where 10.1.0.1/8 is in use) **/
    new = PICO_ZALLOC(sizeof(struct pico_ipv6_link));
    if (!new) {
        dbg("IPv6: out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->address = address;
    new->netmask = netmask;
    new->dev = dev;
    new->istentative = 0;
    new->isduplicate = 0;

    pico_tree_insert(&IPV6Links, new);

    for (i = 0; i < PICO_SIZE_IP6; ++i) {
        network.addr[i] = address.addr[i] & netmask.addr[i];
    }
    pico_ipv6_route_add(network, netmask, gateway, 1, new);
    pico_ipv6_route_add(mcast_addr, mcast_nm, mcast_gw, 1, new);
    /* XXX MUST join the all-nodes multicast address on that interface, as well as
     *     the solicited-node multicast address corresponding to each of the IP
     *     addresses assigned to the interface. (RFC 4861 $7.2.1)
     */
#if 0
    /* Duplicate Address Detection */
    if (!pico_ipv6_is_unspecified(address.addr)) {
        new->istentative = 1;
        pico_icmp6_neighbor_solicitation(dev, &address, PICO_ICMP6_ND_DAD);
        pico_timer_add(pico_rand() % PICO_ICMP6_MAX_RTR_SOL_DELAY, &pico_ipv6_nd_dad, &new->address);
    }

#endif
    pico_ipv6_to_string(ipstr, new->address.addr);
    dbg("Assigned ipv6 %s to device %s\n", ipstr, new->dev->name);
    return 0;
}

int pico_ipv6_cleanup_routes(struct pico_ipv6_link *link)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv6_route *route = NULL;

    pico_tree_foreach_safe(index, &IPV6Routes, _tmp)
    {
        route = index->keyValue;
        if (link == route->link)
            pico_ipv6_route_del(route->dest, route->netmask, route->gateway, (int)route->metric, route->link);
    }
    return 0;
}

int pico_ipv6_cleanup_links(struct pico_device *dev)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv6_link *link = NULL;

    pico_tree_foreach_safe(index, &IPV6Links, _tmp)
    {
        link = index->keyValue;
        if (dev == link->dev)
            pico_ipv6_link_del(dev, link->address);
    }
    return 0;
}

int pico_ipv6_link_del(struct pico_device *dev, struct pico_ip6 address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;

    if (!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.address = address;
    test.dev = dev;
    found = pico_tree_findKey(&IPV6Links, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return -1;
    }

    pico_ipv6_cleanup_routes(found);
    pico_tree_delete(&IPV6Links, found);
    /* XXX MUST leave the solicited-node multicast address corresponding to the address (RFC 4861 $7.2.1) */
    PICO_FREE(found);
    return 0;
}

struct pico_ipv6_link *pico_ipv6_link_istentative(struct pico_ip6 *address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
    test.address = *address;

    found = pico_tree_findKey(&IPV6Links, &test);
    if (!found)
        return NULL;

    if (found->istentative)
        return found;

    return NULL;
}

struct pico_ipv6_link *pico_ipv6_link_get(struct pico_ip6 *address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
    test.address = *address;

    found = pico_tree_findKey(&IPV6Links, &test);
    if (!found)
        return NULL;

    if (found->istentative)
        return NULL;

    return found;
}

struct pico_device *pico_ipv6_link_find(struct pico_ip6 *address)
{
    struct pico_ipv6_link test = {
        0
    }, *found = NULL;
    if(!address) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    test.dev = NULL;
    memcpy(test.address.addr, address->addr, PICO_SIZE_IP6);
    found = pico_tree_findKey(&IPV6Links, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return NULL;
    }

    if (found->istentative)
        return NULL;

    return found->dev;
}

struct pico_ip6 pico_ipv6_route_get_gateway(struct pico_ip6 *addr)
{
    struct pico_ip6 nullip = {{0}};
    struct pico_ipv6_route *route = NULL;

    if (!addr) {
        pico_err = PICO_ERR_EINVAL;
        return nullip;
    }

    route = pico_ipv6_route_find(addr);
    if (!route) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return nullip;
    }
    else
        return route->gateway;
}


struct pico_ipv6_link *pico_ipv6_link_by_dev(struct pico_device *dev)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_link *link = NULL;

    pico_tree_foreach(index, &IPV6Links)
    {
        link = index->keyValue;
        if (dev == link->dev)
            return link;
    }
    return NULL;
}

struct pico_ipv6_link *pico_ipv6_link_by_dev_next(struct pico_device *dev, struct pico_ipv6_link *last)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv6_link *link = NULL;
    int valid = 0;

    if (last == NULL)
        valid = 1;

    pico_tree_foreach(index, &IPV6Links)
    {
        link = index->keyValue;
        if (link->dev == dev) {
            if (last == link)
                valid = 1;
            else if (valid > 0)
                return link;
        }
    }
    return NULL;
}

void pico_ipv6_unreachable(struct pico_frame *f, uint8_t code)
{
    struct pico_ipv6_hdr *hdr = (struct pico_ipv6_hdr *)f->net_hdr;
#if defined PICO_SUPPORT_TCP || defined PICO_SUPPORT_UDP
    pico_transport_error(f, hdr->nxthdr, code);
#endif
}

#endif
