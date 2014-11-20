/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Daniele Lacamera, Markian Yskout
 *********************************************************************/


#include "pico_config.h"
#include "pico_ipfilter.h"
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_nat.h"
#include "pico_igmp.h"
#include "pico_tree.h"
#include "pico_socket_multicast.h"

#ifdef PICO_SUPPORT_IPV4

#ifdef PICO_SUPPORT_MCAST
# define ip_mcast_dbg(...) do {} while(0) /* so_mcast_dbg in pico_socket.c */
/* #define ip_mcast_dbg dbg */
# define PICO_MCAST_ALL_HOSTS long_be(0xE0000001) /* 224.0.0.1 */
/* Default network interface for multicast transmission */
static struct pico_ipv4_link *mcast_default_link = NULL;
#endif
#ifdef PICO_SUPPORT_IPFRAG
/* # define reassembly_dbg dbg */
# define reassembly_dbg(...) do {} while(0)
#endif

/* Queues */
static struct pico_queue in = {
    0
};
static struct pico_queue out = {
    0
};

/* Functions */
static int ipv4_route_compare(void *ka, void *kb);
static struct pico_frame *pico_ipv4_alloc(struct pico_protocol *self, uint16_t size);


int pico_ipv4_compare(struct pico_ip4 *a, struct pico_ip4 *b)
{
    if (a->addr < b->addr)
        return -1;

    if (a->addr > b->addr)
        return 1;

    return 0;
}

int pico_ipv4_to_string(char *ipbuf, const uint32_t ip)
{
    const unsigned char *addr = (const unsigned char *) &ip;
    int i;

    if (!ipbuf) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    for(i = 0; i < 4; i++)
    {
        if(addr[i] > 99) {
            *ipbuf++ = (char)('0' + (addr[i] / 100));
            *ipbuf++ = (char)('0' + ((addr[i] % 100) / 10));
            *ipbuf++ = (char)('0' + ((addr[i] % 100) % 10));
        }else if(addr[i] > 9) {
            *ipbuf++ = (char)('0' + (addr[i] / 10));
            *ipbuf++ = (char)('0' + (addr[i] % 10));
        }else{
            *ipbuf++ = (char)('0' + addr[i]);
        }

        if(i < 3)
            *ipbuf++ = '.';
    }
    *ipbuf = '\0';

    return 0;
}

static int pico_string_check_null_args(const char *ipstr, uint32_t *ip)
{

    if(!ipstr || !ip) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;

}

int pico_string_to_ipv4(const char *ipstr, uint32_t *ip)
{
    unsigned char buf[4] = {
        0
    };
    int cnt = 0;
    char p;

    if (pico_string_check_null_args(ipstr, ip) < 0)
        return -1;


    while((p = *ipstr++) != 0)
    {
        if(pico_is_digit(p)) {
            buf[cnt] = (uint8_t)((10 * buf[cnt]) + (p - '0'));
        }else if(p == '.') {
            cnt++;
        }else{
            return -1;
        }
    }
    /* Handle short notation */
    if(cnt == 1) {
        buf[3] = buf[1];
        buf[1] = 0;
        buf[2] = 0;
    }else if (cnt == 2) {
        buf[3] = buf[2];
        buf[2] = 0;
    }else if(cnt != 3) {
        /* String could not be parsed, return error */
        return -1;
    }

    *ip = long_from(buf);

    return 0;

}

int pico_ipv4_valid_netmask(uint32_t mask)
{
    int cnt = 0;
    int end = 0;
    int i;
    uint32_t mask_swap = long_be(mask);

    /*
     * Swap bytes for convenient parsing
     * e.g. 0x..f8ff will become 0xfff8..
     * Then, we count the consecutive bits
     *
     * */

    for(i = 0; i < 32; i++) {
        if((mask_swap << i) & 0x80000000) {
            if(end) {
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }

            cnt++;
        }else{
            end = 1;
        }
    }
    return cnt;
}

int pico_ipv4_is_unicast(uint32_t address)
{
    const unsigned char *addr = (unsigned char *) &address;
    if((addr[0] & 0xe0) == 0xe0)
        return 0; /* multicast */

    return 1;
}

int pico_ipv4_is_multicast(uint32_t address)
{
    const unsigned char *addr = (unsigned char *) &address;
    if((addr[0] != 0xff) && ((addr[0] & 0xe0) == 0xe0))
        return 1; /* multicast */

    return 0;
}

int pico_ipv4_is_loopback(uint32_t address)
{
    const unsigned char *addr = (unsigned char *) &address;
    if(addr[0] == 0x7f)
        return 1;

    return 0;
}

static int pico_ipv4_is_invalid_loopback(uint32_t address, struct pico_device *dev)
{
    return pico_ipv4_is_loopback(address) && ((!dev) || strcmp(dev->name, "loop"));
}

int pico_ipv4_is_valid_src(uint32_t address, struct pico_device *dev)
{
    if (pico_ipv4_is_broadcast(address)) {
        dbg("Source is a broadcast address, discard packet\n");
        return 0;
    }
    else if( pico_ipv4_is_multicast(address)) {
        dbg("Source is a multicast address, discard packet\n");
        return 0;
    }
    else if (pico_ipv4_is_invalid_loopback(address, dev)) {
        dbg("Source is a loopback address, discard packet\n");
        return 0;
    }
    else {
        return 1;
    }
}

static int pico_ipv4_checksum(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (!hdr)
        return -1;

    hdr->crc = 0;
    hdr->crc = short_be(pico_checksum(hdr, f->net_len));
    return 0;
}

#ifdef PICO_SUPPORT_IPFRAG
struct pico_ipv4_fragmented_packet {
    uint16_t id;
    uint8_t proto;
    struct pico_ip4 src;
    struct pico_ip4 dst;
    uint16_t total_len;
    struct pico_tree *t;
};

static inline int pico_ipv4_cmp_frag_id(struct pico_ipv4_fragmented_packet *a, struct pico_ipv4_fragmented_packet *b)
{
    if (a->id < b->id)
        return -1;

    if (a->id > b->id)
        return 1;

    return 0;
}

static inline int pico_ipv4_cmp_frag_proto(struct pico_ipv4_fragmented_packet *a, struct pico_ipv4_fragmented_packet *b)
{
    if (a->proto < b->proto)
        return -1;

    if (a->proto > b->proto)
        return 1;

    return 0;
}

static int pico_ipv4_fragmented_packet_cmp(void *ka, void *kb)
{
    struct pico_ipv4_fragmented_packet *a = ka, *b = kb;
    int cmp = 0;

    cmp = pico_ipv4_cmp_frag_id(a, b);
    if (cmp)
        return cmp;

    cmp = pico_ipv4_cmp_frag_proto(a, b);
    if (cmp)
        return cmp;

    cmp = pico_ipv4_compare(&a->src, &b->src);
    if (cmp)
        return cmp;

    cmp = pico_ipv4_compare(&a->dst, &b->dst);
    return cmp;
}

static int pico_ipv4_fragmented_element_cmp(void *ka, void *kb)
{
    struct pico_frame *frame_a = ka, *frame_b = kb;
    struct pico_ipv4_hdr *a, *b;
    uint16_t a_frag, b_frag;
    a = (struct pico_ipv4_hdr *) frame_a->net_hdr;
    b = (struct pico_ipv4_hdr *) frame_b->net_hdr;
    a_frag = short_be(a->frag & PICO_IPV4_FRAG_MASK);
    b_frag = short_be(b->frag & PICO_IPV4_FRAG_MASK);

    if (a_frag < b_frag)
        return -1;

    if (b_frag < a_frag)
        return 1;
    else
        return 0;
}

PICO_TREE_DECLARE(pico_ipv4_fragmented_tree, pico_ipv4_fragmented_packet_cmp);

static inline void pico_ipv4_fragmented_cleanup(struct pico_ipv4_fragmented_packet *pfrag)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_frame *f_frag = NULL;

    pico_tree_foreach_safe(index, pfrag->t, _tmp) {
        f_frag = index->keyValue;
        reassembly_dbg("REASSEMBLY: remove packet with offset %u\n", short_be(((struct pico_ipv4_hdr *)f_frag->net_hdr)->frag) & PICO_IPV4_FRAG_MASK);
        pico_tree_delete(pfrag->t, f_frag);
        pico_frame_discard(f_frag);
    }
    pico_tree_delete(&pico_ipv4_fragmented_tree, pfrag);
    PICO_FREE(pfrag->t);
    PICO_FREE(pfrag);
}
#endif /* PICO_SUPPORT_IPFRAG */

#ifdef PICO_SUPPORT_IPFRAG

static inline struct pico_ipv4_fragmented_packet *fragment_find_by_hdr(struct pico_ipv4_hdr *hdr)
{
    struct pico_ipv4_fragmented_packet frag = {
        0
    };
    frag.id = short_be(hdr->id);
    frag.proto = hdr->proto;
    frag.src.addr = long_be(hdr->src.addr);
    frag.dst.addr = long_be(hdr->dst.addr);
    return pico_tree_findKey(&pico_ipv4_fragmented_tree, &frag);
}


static inline int8_t fragmented_check_has_morefrags(struct pico_frame **f)
{
    uint16_t offset = 0;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) (*f)->net_hdr;
    struct pico_ipv4_fragmented_packet *pfrag = NULL;

    offset = short_be(hdr->frag) & PICO_IPV4_FRAG_MASK;
    if (!offset) {
        reassembly_dbg("REASSEMBLY: first element of a fragmented packet with id %X and offset %u\n", short_be(hdr->id), offset);
        if (!pico_tree_empty(&pico_ipv4_fragmented_tree)) {
            reassembly_dbg("REASSEMBLY: cleanup tree\n");
            /* only one entry allowed in this tree */
            pfrag = pico_tree_first(&pico_ipv4_fragmented_tree);
            pico_ipv4_fragmented_cleanup(pfrag);
        }

        /* add entry in tree for this ID and create secondary tree to contain fragmented elements */
        pfrag = PICO_ZALLOC(sizeof(struct pico_ipv4_fragmented_packet));
        if (!pfrag) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        pfrag->id = short_be(hdr->id);
        pfrag->proto = hdr->proto;
        pfrag->src.addr = long_be(hdr->src.addr);
        pfrag->dst.addr = long_be(hdr->dst.addr);
        pfrag->total_len = (uint16_t)(short_be(hdr->len) - (*f)->net_len);
        pfrag->t = PICO_ZALLOC(sizeof(struct pico_tree));
        if (!pfrag->t) {
            PICO_FREE(pfrag);
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        pfrag->t->root = &LEAF;
        pfrag->t->compare = pico_ipv4_fragmented_element_cmp;

        pico_tree_insert(pfrag->t, *f);
        pico_tree_insert(&pico_ipv4_fragmented_tree, pfrag);
        return 0;
    }
    else {
        reassembly_dbg("REASSEMBLY: intermediate element of a fragmented packet with id %X and offset %u\n", short_be(hdr->id), offset);
        pfrag = fragment_find_by_hdr(hdr);
        if (pfrag) {
            pfrag->total_len = (uint16_t)(pfrag->total_len + (short_be(hdr->len) - (*f)->net_len));
            if (pfrag->total_len > PICO_IPV4_FRAG_MAX_SIZE) {
                reassembly_dbg("BIG frame!!!\n");
                pfrag = pico_tree_first(&pico_ipv4_fragmented_tree);
                pico_ipv4_fragmented_cleanup(pfrag);
                pico_frame_discard(*f);
                return 0;
            }

            pico_tree_insert(pfrag->t, *f);
            return 0;
        } else {
            reassembly_dbg("REASSEMBLY: silently discard intermediate frame, first packet was lost or disallowed (one fragmented packet at a time)\n");
            pico_frame_discard(*f);
            return 0;
        }
    }
}

static inline int8_t fragmented_check_is_lastfrag(struct pico_frame **f)
{
    uint8_t *running_pointer = NULL;
    uint16_t running_offset = 0;
    uint16_t offset = 0;
    uint16_t data_len = 0;
    struct pico_ipv4_hdr *f_frag_hdr = NULL, *hdr = (struct pico_ipv4_hdr *) (*f)->net_hdr;
    struct pico_ipv4_fragmented_packet *pfrag = NULL;
    struct pico_frame *f_new = NULL, *f_frag = NULL;
    struct pico_tree_node *index, *_tmp;

    data_len = (uint16_t)(short_be(hdr->len) - (*f)->net_len);
    offset = short_be(hdr->frag) & PICO_IPV4_FRAG_MASK;
    reassembly_dbg("REASSEMBLY: last element of a fragmented packet with id %X and offset %u\n", short_be(hdr->id), offset);
    pfrag = fragment_find_by_hdr(hdr);
    if (pfrag) {
        pfrag->total_len = (uint16_t)(pfrag->total_len + (short_be(hdr->len) - (*f)->net_len));
        reassembly_dbg("REASSEMBLY: fragmented packet in tree, reassemble packet of %u data bytes\n", pfrag->total_len);
        if (pfrag->total_len > PICO_IPV4_FRAG_MAX_SIZE) {
            reassembly_dbg("BIG frame!!!\n");
            pfrag = pico_tree_first(&pico_ipv4_fragmented_tree);
            pico_ipv4_fragmented_cleanup(pfrag);
            pico_frame_discard(*f);
            return 0;
        }

        f_new = pico_proto_ipv4.alloc(&pico_proto_ipv4, pfrag->total_len);
        if (!f_new){
            pico_ipv4_fragmented_cleanup(pfrag);
            pico_frame_discard(*f);
            return -1;
        }

        f_frag = pico_tree_first(pfrag->t);
        reassembly_dbg("REASSEMBLY: copy IP header information len = %lu\n", f_frag->net_len);
        f_frag_hdr = (struct pico_ipv4_hdr *)f_frag->net_hdr;
        data_len = (uint16_t)(short_be(f_frag_hdr->len) - f_frag->net_len);
        memcpy(f_new->net_hdr, f_frag->net_hdr, f_frag->net_len);
        memcpy(f_new->transport_hdr, f_frag->transport_hdr, data_len);
        f_new->dev = f_frag->dev;
        running_pointer = f_new->transport_hdr + data_len;
        offset = short_be(f_frag_hdr->frag) & PICO_IPV4_FRAG_MASK;
        running_offset = data_len / 8;
        pico_tree_delete(pfrag->t, f_frag);
        pico_frame_discard(f_frag);
        reassembly_dbg("REASSEMBLY: reassembled first packet of %u data bytes, offset = %u next expected offset = %u\n", data_len, offset, running_offset);

        pico_tree_foreach_safe(index, pfrag->t, _tmp)
        {
            f_frag = index->keyValue;
            f_frag_hdr = (struct pico_ipv4_hdr *)f_frag->net_hdr;
            data_len = (uint16_t)(short_be(f_frag_hdr->len) - f_frag->net_len);
            memcpy(running_pointer, f_frag->transport_hdr, data_len);
            running_pointer += data_len;
            offset = short_be(f_frag_hdr->frag) & PICO_IPV4_FRAG_MASK;
            if (offset != running_offset) {
                reassembly_dbg("REASSEMBLY: error reassembling intermediate packet: offset %u != expected offset %u (missing fragment)\n", offset, running_offset);
                pico_ipv4_fragmented_cleanup(pfrag);
                return -1;
            }

            running_offset = (uint16_t)(running_offset + (data_len / 8));
            pico_tree_delete(pfrag->t, f_frag);
            pico_frame_discard(f_frag);
            reassembly_dbg("REASSEMBLY: reassembled intermediate packet of %u data bytes, offset = %u next expected offset = %u\n", data_len, offset, running_offset);
        }
        pico_tree_delete(&pico_ipv4_fragmented_tree, pfrag);
        PICO_FREE(pfrag);

        data_len = (uint16_t)(short_be(hdr->len) - (*f)->net_len);
        memcpy(running_pointer, (*f)->transport_hdr, data_len);
        offset = short_be(hdr->frag) & PICO_IPV4_FRAG_MASK;
        pico_frame_discard(*f);
        reassembly_dbg("REASSEMBLY: reassembled last packet of %u data bytes, offset = %u\n", data_len, offset);

        hdr = (struct pico_ipv4_hdr *)f_new->net_hdr;
        hdr->len = pfrag->total_len;
        hdr->frag = 0; /* flags cleared and no offset */
        hdr->crc = 0;
        hdr->crc = short_be(pico_checksum(hdr, f_new->net_len));
        /* Optional, the UDP/TCP CRC should already be correct */
        if (0) {
#ifdef PICO_SUPPORT_TCP
        } else if (hdr->proto == PICO_PROTO_TCP) {
            struct pico_tcp_hdr *tcp_hdr = NULL;
            tcp_hdr = (struct pico_tcp_hdr *) f_new->transport_hdr;
            tcp_hdr->crc = 0;
            tcp_hdr->crc = short_be(pico_tcp_checksum(f_new));
#endif
#ifdef PICO_SUPPORT_UDP
        } else if (hdr->proto == PICO_PROTO_UDP) {
            struct pico_udp_hdr *udp_hdr = NULL;
            udp_hdr = (struct pico_udp_hdr *) f_new->transport_hdr;
            udp_hdr->crc = 0;
            udp_hdr->crc = short_be(pico_udp_checksum_ipv4(f_new));
#endif
        }

        reassembly_dbg("REASSEMBLY: packet with id %X reassembled correctly\n", short_be(hdr->id));
        *f = f_new;
        return 1;
    } else {
        reassembly_dbg("REASSEMBLY: silently discard last frame, first packet was lost or disallowed (one fragmented packet at a time)\n");
        pico_frame_discard(*f);
        return 0;
    }
}


static inline int8_t pico_ipv4_fragmented_check(struct pico_protocol *self, struct pico_frame **f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) (*f)->net_hdr;
    uint16_t offset = short_be(hdr->frag) & PICO_IPV4_FRAG_MASK;
    (void)self;
    if (short_be(hdr->frag) & PICO_IPV4_MOREFRAG) {
        return fragmented_check_has_morefrags(f);
    } else if (offset) {
        return fragmented_check_is_lastfrag(f);
    } else {
        return 1;
    }
}
#else
static inline int8_t pico_ipv4_fragmented_check(struct pico_protocol *self, struct pico_frame **f)
{
    (void)self;
    (void)f;
    return 1;
}
#endif /* PICO_SUPPORT_IPFRAG */

#ifdef PICO_SUPPORT_CRC
static inline int pico_ipv4_crc_check(struct pico_frame *f)
{
    uint16_t checksum_invalid = 1;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

    checksum_invalid = short_be(pico_checksum(hdr, f->net_len));
    if (checksum_invalid) {
        dbg("IP: checksum failed!\n");
        pico_frame_discard(f);
        return 0;
    }

    return 1;
}
#else
static inline int pico_ipv4_crc_check(struct pico_frame *f)
{
    IGNORE_PARAMETER(f);
    return 1;
}
#endif /* PICO_SUPPORT_CRC */

static int pico_ipv4_forward(struct pico_frame *f);
#ifdef PICO_SUPPORT_MCAST
static int pico_ipv4_mcast_filter(struct pico_frame *f);
#endif

static int ipv4_link_compare(void *ka, void *kb)
{
    struct pico_ipv4_link *a = ka, *b = kb;
    int cmp = pico_ipv4_compare(&a->address, &b->address);
    if (cmp)
        return cmp;

    /* zero can be assigned multiple times (e.g. for DHCP) */
    if (a->dev != NULL && b->dev != NULL && a->address.addr == PICO_IP4_ANY && b->address.addr == PICO_IP4_ANY) {
        if (a->dev < b->dev)
            return -1;

        if (a->dev > b->dev)
            return 1;
    }

    return 0;
}

PICO_TREE_DECLARE(Tree_dev_link, ipv4_link_compare);

static int pico_ipv4_process_bcast_in(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
#ifdef PICO_SUPPORT_UDP
    if (pico_ipv4_is_broadcast(hdr->dst.addr) && (hdr->proto == PICO_PROTO_UDP)) {
        /* Receiving UDP broadcast datagram */
        f->flags |= PICO_FRAME_FLAG_BCAST;
        pico_enqueue(pico_proto_udp.q_in, f);
        return 1;
    }
#endif

#ifdef PICO_SUPPORT_ICMP4
    if (pico_ipv4_is_broadcast(hdr->dst.addr) && (hdr->proto == PICO_PROTO_ICMP4)) {
        /* Receiving ICMP4 bcast packet */
        f->flags |= PICO_FRAME_FLAG_BCAST;
        pico_enqueue(pico_proto_icmp4.q_in, f);
        return 1;
    }
#endif
    return 0;
}

static int pico_ipv4_process_mcast_in(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (pico_ipv4_is_multicast(hdr->dst.addr)) {
#ifdef PICO_SUPPORT_MCAST
        /* Receiving UDP multicast datagram TODO set f->flags? */
        if (hdr->proto == PICO_PROTO_IGMP) {
            ip_mcast_dbg("MCAST: received IGMP message\n");
            pico_transport_receive(f, PICO_PROTO_IGMP);
            return 1;
        } else if ((pico_ipv4_mcast_filter(f) == 0) && (hdr->proto == PICO_PROTO_UDP)) {
            pico_enqueue(pico_proto_udp.q_in, f);
            return 1;
        }

#endif
        pico_frame_discard(f);
        return 1;
    }

    return 0;
}

static int pico_ipv4_process_local_unicast_in(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_ipv4_link test = {
        .address = {.addr = PICO_IP4_ANY}, .dev = NULL
    };
    if (pico_ipv4_link_find(&hdr->dst)) {
        if (pico_ipv4_nat_inbound(f, &hdr->dst) == 0)
            pico_enqueue(pico_proto_ipv4.q_in, f); /* dst changed, reprocess */
        else
            pico_transport_receive(f, hdr->proto);

        return 1;
    } else if (pico_tree_findKey(&Tree_dev_link, &test)) {
#ifdef PICO_SUPPORT_UDP
        /* address of this device is apparently 0.0.0.0; might be a DHCP packet */
        /* XXX KRO: is obsolete. Broadcast flag is set on outgoing DHCP messages.
         * incomming DHCP messages are to be broadcasted. Our current DHCP server
         * implementation does not take this flag into account yet though ... */
        pico_enqueue(pico_proto_udp.q_in, f);
        return 1;
#endif
    }

    return 0;
}

static void pico_ipv4_process_finally_try_forward(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if((pico_ipv4_is_broadcast(hdr->dst.addr)))
    {
        /* don't forward broadcast frame, discard! */
        pico_frame_discard(f);
    } else if (pico_ipv4_forward(f) != 0) {
        pico_frame_discard(f);
        /* dbg("Forward failed.\n"); */
    }
}



static int pico_ipv4_process_in(struct pico_protocol *self, struct pico_frame *f)
{
    uint8_t option_len = 0;
    int ret = 0;
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

    /* NAT needs transport header information */
    if(((hdr->vhl) & 0x0F) > 5) {
        option_len =  (uint8_t)(4 * (((hdr->vhl) & 0x0F) - 5));
    }

    f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR + option_len;
    f->transport_len = (uint16_t)(short_be(hdr->len) - PICO_SIZE_IP4HDR - option_len);
    f->net_len = (uint16_t)(PICO_SIZE_IP4HDR + option_len);

#ifdef PICO_SUPPORT_IPFILTER
    if (ipfilter(f)) {
        /*pico_frame is discarded as result of the filtering*/
        return 0;
    }

#endif

    /* ret == 1 indicates to continue the function */
    ret = pico_ipv4_crc_check(f);
    if (ret < 1)
        return ret;

    ret = pico_ipv4_fragmented_check(self, &f);
    if (ret < 1)
        return ret;

    /* Validate source IP address. Discard quietly if invalid */
    if (!pico_ipv4_is_valid_src(hdr->src.addr, f->dev)) {
        pico_frame_discard(f);
        return 0;
    }

    if (hdr->frag & 0x80) {
        (void)pico_icmp4_param_problem(f, 0);
        pico_frame_discard(f); /* RFC 3514 */
        return 0;
    }

    if ((hdr->vhl & 0x0f) < 5) {
        /* RFC 791: IHL minimum value is 5 */
        (void)pico_icmp4_param_problem(f, 0);
        pico_frame_discard(f);
        return 0;
    }

    if (pico_ipv4_process_bcast_in(f) > 0)
        return 0;

    if (pico_ipv4_process_mcast_in(f) > 0)
        return 0;

    if (pico_ipv4_process_local_unicast_in(f) > 0)
        return 0;

    pico_ipv4_process_finally_try_forward(f);

    return 0;
}

PICO_TREE_DECLARE(Routes, ipv4_route_compare);


static int pico_ipv4_process_out(struct pico_protocol *self, struct pico_frame *f)
{
    IGNORE_PARAMETER(self);
    f->start = (uint8_t*) f->net_hdr;
  #ifdef PICO_SUPPORT_IPFILTER
    if (ipfilter(f)) {
        /*pico_frame is discarded as result of the filtering*/
        return 0;
    }

  #endif
    return pico_sendto_dev(f);
}


static struct pico_frame *pico_ipv4_alloc(struct pico_protocol *self, uint16_t size)
{
    struct pico_frame *f =  pico_frame_alloc(size + PICO_SIZE_IP4HDR + PICO_SIZE_ETHHDR);
    IGNORE_PARAMETER(self);

    if (!f)
        return NULL;

    f->datalink_hdr = f->buffer;
    f->net_hdr = f->buffer + PICO_SIZE_ETHHDR;
    f->net_len = PICO_SIZE_IP4HDR;
    f->transport_hdr = f->net_hdr + PICO_SIZE_IP4HDR;
    f->transport_len = size;
    f->len =  size + PICO_SIZE_IP4HDR;
    return f;
}

static int pico_ipv4_frame_sock_push(struct pico_protocol *self, struct pico_frame *f);

/* Interface: protocol definition */
struct pico_protocol pico_proto_ipv4 = {
    .name = "ipv4",
    .proto_number = PICO_PROTO_IPV4,
    .layer = PICO_LAYER_NETWORK,
    .alloc = pico_ipv4_alloc,
    .process_in = pico_ipv4_process_in,
    .process_out = pico_ipv4_process_out,
    .push = pico_ipv4_frame_sock_push,
    .q_in = &in,
    .q_out = &out,
};


static int ipv4_route_compare(void *ka, void *kb)
{
    struct pico_ipv4_route *a = ka, *b = kb;
    uint32_t a_nm, b_nm;
    int cmp;

    a_nm = long_be(a->netmask.addr);
    b_nm = long_be(b->netmask.addr);

    /* Routes are sorted by (host side) netmask len, then by addr, then by metric. */
    if (a_nm < b_nm)
        return -1;

    if (b_nm < a_nm)
        return 1;

    cmp = pico_ipv4_compare(&a->dest, &b->dest);
    if (cmp)
        return cmp;

    if (a->metric < b->metric)
        return -1;

    if (a->metric > b->metric)
        return 1;

    return 0;
}


static struct pico_ipv4_route default_bcast_route = {
    .dest = {PICO_IP4_BCAST},
    .netmask = {PICO_IP4_BCAST},
    .gateway  = { 0 },
    .link = NULL,
    .metric = 1000
};

static struct pico_ipv4_route *route_find_default_bcast(void)
{
    return &default_bcast_route;
}


static struct pico_ipv4_route *route_find(const struct pico_ip4 *addr)
{
    struct pico_ipv4_route *r;
    struct pico_tree_node *index;

    if(addr->addr != PICO_IP4_BCAST)
    {
        pico_tree_foreach_reverse(index, &Routes) {
            r = index->keyValue;
            if ((addr->addr & (r->netmask.addr)) == (r->dest.addr)) {
                return r;
            }
        }
        return NULL;
    }

    return route_find_default_bcast();
}

struct pico_ip4 pico_ipv4_route_get_gateway(struct pico_ip4 *addr)
{
    struct pico_ip4 nullip;
    struct pico_ipv4_route *route;
    nullip.addr = 0U;

    if(!addr) {
        pico_err = PICO_ERR_EINVAL;
        return nullip;
    }

    route = route_find(addr);
    if (!route) {
        pico_err = PICO_ERR_EHOSTUNREACH;
        return nullip;
    }
    else
        return route->gateway;
}

struct pico_ip4 *pico_ipv4_source_find(const struct pico_ip4 *dst)
{
    struct pico_ip4 *myself = NULL;
    struct pico_ipv4_route *rt;

    if(!dst) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    rt = route_find(dst);
    if (rt && rt->link) {
        myself = &rt->link->address;
    } else
        pico_err = PICO_ERR_EHOSTUNREACH;

    return myself;
}


#ifdef PICO_SUPPORT_MCAST
/*                        link
 *                         |
 *                    MCASTGroups
 *                    |    |     |
 *         ------------    |     ------------
 *         |               |                |
 *   MCASTSources    MCASTSources     MCASTSources
 *   |  |  |  |      |  |  |  |       |  |  |  |
 *   S  S  S  S      S  S  S  S       S  S  S  S
 *
 *   MCASTGroups: RBTree(mcast_group)
 *   MCASTSources: RBTree(source)
 */
static int ipv4_mcast_groups_cmp(void *ka, void *kb)
{
    struct pico_mcast_group *a = ka, *b = kb;
    return pico_ipv4_compare(&a->mcast_addr, &b->mcast_addr);
}

static int ipv4_mcast_sources_cmp(void *ka, void *kb)
{
    struct pico_ip4 *a = ka, *b = kb;
    return pico_ipv4_compare(a, b);
}

static void pico_ipv4_mcast_print_groups(struct pico_ipv4_link *mcast_link)
{
    uint16_t i = 0;
    struct pico_mcast_group *g = NULL;
    struct pico_ip4 *source = NULL;
    struct pico_tree_node *index = NULL, *index2 = NULL;
    (void) source;

    ip_mcast_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    ip_mcast_dbg("+                           MULTICAST list interface %-16s             +\n", mcast_link->dev->name);
    ip_mcast_dbg("+---------------------------------------------------------------------------------+\n");
    ip_mcast_dbg("+  nr  |    interface     | host group | reference count | filter mode |  source  +\n");
    ip_mcast_dbg("+---------------------------------------------------------------------------------+\n");

    pico_tree_foreach(index, mcast_link->MCASTGroups)
    {
        g = index->keyValue;
        ip_mcast_dbg("+ %04d | %16s |  %08X  |      %05u      |      %u      | %8s +\n", i, mcast_link->dev->name, g->mcast_addr.addr, g->reference_count, g->filter_mode, "");
        pico_tree_foreach(index2, &g->MCASTSources)
        {
            source = index2->keyValue;
            ip_mcast_dbg("+ %4s | %16s |  %8s  |      %5s      |      %s      | %08X +\n", "", "", "", "", "", source->addr);
        }
        i++;
    }
    ip_mcast_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

static int mcast_group_update(struct pico_mcast_group *g, struct pico_tree *MCASTFilter, uint8_t filter_mode)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ip4 *source = NULL;
    /* cleanup filter */
    pico_tree_foreach_safe(index, &g->MCASTSources, _tmp)
    {
        source = index->keyValue;
        pico_tree_delete(&g->MCASTSources, source);
        PICO_FREE(source);
    }
    /* insert new filter */
    if (MCASTFilter) {
        pico_tree_foreach(index, MCASTFilter)
        {
            if (index->keyValue) {
                source = PICO_ZALLOC(sizeof(struct pico_ip4));
                if (!source) {
                    pico_err = PICO_ERR_ENOMEM;
                    return -1;
                }

                source->addr = ((struct pico_ip4 *)index->keyValue)->addr;
                pico_tree_insert(&g->MCASTSources, source);
            }
        }
    }

    g->filter_mode = filter_mode;
    return 0;
}

int pico_ipv4_mcast_join(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv4_link *link = NULL;

    if (mcast_link)
        link = pico_ipv4_link_get(mcast_link);

    if(!link)
        link = mcast_default_link;

    test.mcast_addr = *mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (g) {
        if (reference_count)
            g->reference_count++;

        pico_igmp_state_change(mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_UPDATE);
    } else {
        g = PICO_ZALLOC(sizeof(struct pico_mcast_group));
        if (!g) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        /* "non-existent" state of filter mode INCLUDE and empty source list */
        g->filter_mode = PICO_IP_MULTICAST_INCLUDE;
        g->reference_count = 1;
        g->mcast_addr = *mcast_group;
        g->MCASTSources.root = &LEAF;
        g->MCASTSources.compare = ipv4_mcast_sources_cmp;
        pico_tree_insert(link->MCASTGroups, g);
        pico_igmp_state_change(mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_CREATE);
    }

    if (mcast_group_update(g, MCASTFilter, filter_mode) < 0) {
        dbg("Error in mcast_group update\n");
        return -1;
    }

    pico_ipv4_mcast_print_groups(link);
    return 0;
}

int pico_ipv4_mcast_leave(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{

    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv4_link *link = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ip4 *source = NULL;

    if (mcast_link)
        link = pico_ipv4_link_get(mcast_link);

    if(!link)
        link = mcast_default_link;

    test.mcast_addr = *mcast_group;
    g = pico_tree_findKey(link->MCASTGroups, &test);
    if (!g) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (reference_count && (--(g->reference_count) < 1)) {
            pico_igmp_state_change(mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_DELETE);
            /* cleanup filter */
            pico_tree_foreach_safe(index, &g->MCASTSources, _tmp)
            {
                source = index->keyValue;
                pico_tree_delete(&g->MCASTSources, source);
                PICO_FREE(source);
            }
            pico_tree_delete(link->MCASTGroups, g);
            PICO_FREE(g);
        } else {
            pico_igmp_state_change(mcast_link, mcast_group, filter_mode, MCASTFilter, PICO_IGMP_STATE_UPDATE);
            if (mcast_group_update(g, MCASTFilter, filter_mode) < 0)
                return -1;
        }
    }

    pico_ipv4_mcast_print_groups(link);
    return 0;
}

struct pico_ipv4_link *pico_ipv4_get_default_mcastlink(void)
{
    return mcast_default_link;
}

static int pico_ipv4_mcast_filter(struct pico_frame *f)
{
    struct pico_ipv4_link *link = NULL;
    struct pico_tree_node *index = NULL, *index2 = NULL;
    struct pico_mcast_group *g = NULL, test = {
        0
    };
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;

    test.mcast_addr = hdr->dst;

    pico_tree_foreach(index, &Tree_dev_link)
    {
        link = index->keyValue;
        g = pico_tree_findKey(link->MCASTGroups, &test);
        if (g) {
            if (f->dev == link->dev) {
                ip_mcast_dbg("MCAST: IP %08X is group member of current link %s\n", hdr->dst.addr, f->dev->name);
                /* perform source filtering */
                switch (g->filter_mode)
                {
                case PICO_IP_MULTICAST_INCLUDE:
                    pico_tree_foreach(index2, &g->MCASTSources)
                    {
                        if (hdr->src.addr == ((struct pico_ip4 *)index2->keyValue)->addr) {
                            ip_mcast_dbg("MCAST: IP %08X in included interface source list\n", hdr->src.addr);
                            return 0;
                        }
                    }
                    ip_mcast_dbg("MCAST: IP %08X NOT in included interface source list\n", hdr->src.addr);
                    return -1;

                case PICO_IP_MULTICAST_EXCLUDE:
                    pico_tree_foreach(index2, &g->MCASTSources)
                    {
                        if (hdr->src.addr == ((struct pico_ip4 *)index2->keyValue)->addr) {
                            ip_mcast_dbg("MCAST: IP %08X in excluded interface source list\n", hdr->src.addr);
                            return -1;
                        }
                    }
                    ip_mcast_dbg("MCAST: IP %08X NOT in excluded interface source list\n", hdr->src.addr);
                    return 0;

                default:
                    return -1;
                }
            } else {
                ip_mcast_dbg("MCAST: IP %08X is group member of different link %s\n", hdr->dst.addr, link->dev->name);
            }
        } else {
            ip_mcast_dbg("MCAST: IP %08X is not a group member of link %s\n", hdr->dst.addr, f->dev->name);
        }
    }
    return -1;
}

#else

int pico_ipv4_mcast_join(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}
int pico_ipv4_mcast_leave(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group, uint8_t reference_count, uint8_t filter_mode, struct pico_tree *MCASTFilter)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}
struct pico_ipv4_link *pico_ipv4_get_default_mcastlink(void)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return NULL;
}
#endif /* PICO_SUPPORT_MCAST */
/* #define DEBUG_ROUTE */
#ifdef DEBUG_ROUTE
void dbg_route(void)
{
    struct pico_ipv4_route *r;
    struct pico_tree_node *index;
    int count_hosts = 0;
    dbg("==== ROUTING TABLE =====\n");
    pico_tree_foreach(index, &Routes){
        r = index->keyValue;
        dbg("Route to %08x/%08x, gw %08x, dev: %s, metric: %d\n", r->dest.addr, r->netmask.addr, r->gateway.addr, r->link->dev->name, r->metric);
        if (r->netmask.addr == 0xFFFFFFFF)
            count_hosts++;
    }
    dbg("================ total HOST nodes: %d ======\n\n\n", count_hosts);
}
#else
#define dbg_route() do { } while(0)
#endif

int pico_ipv4_frame_push(struct pico_frame *f, struct pico_ip4 *dst, uint8_t proto)
{

    struct pico_ipv4_route *route;
    struct pico_ipv4_link *link;
    struct pico_ipv4_hdr *hdr;
    uint8_t ttl = PICO_IPV4_DEFAULT_TTL;
    uint8_t vhl = 0x45; /* version 4, header length 20 */
    static uint16_t ipv4_progressive_id = 0x91c0;
#ifdef PICO_SUPPORT_MCAST
    struct pico_tree_node *index;
#endif

    if(!f || !dst) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (!hdr) {
        dbg("IP header error\n");
        pico_err = PICO_ERR_EINVAL;
        goto drop;
    }

    if (dst->addr == 0) {
        dbg("IP destination addr error\n");
        pico_err = PICO_ERR_EINVAL;
        goto drop;
    }

    route = route_find(dst);
    if (!route) {
        /* dbg("Route to %08x not found.\n", long_be(dst->addr)); */


        pico_err = PICO_ERR_EHOSTUNREACH;
        goto drop;
    } else {
        link = route->link;
#ifdef PICO_SUPPORT_MCAST
        if (pico_ipv4_is_multicast(dst->addr)) { /* if multicast */
            switch (proto) {
            case PICO_PROTO_UDP:
                if(pico_udp_get_mc_ttl(f->sock, &ttl) < 0)
                    ttl = PICO_IP_DEFAULT_MULTICAST_TTL;

                break;
            case PICO_PROTO_IGMP:
                vhl = 0x46; /* header length 24 */
                ttl = 1;
                /* router alert (RFC 2113) */
                hdr->options[0] = 0x94;
                hdr->options[1] = 0x04;
                hdr->options[2] = 0x00;
                hdr->options[3] = 0x00;
                if (f->dev && link->dev != f->dev) { /* default link is not requested link */
                    pico_tree_foreach(index, &Tree_dev_link) {
                        link = index->keyValue;
                        if (link->dev == f->dev)
                            break;
                    }
                }

                break;
            default:
                ttl = PICO_IPV4_DEFAULT_TTL;
            }
        }

#endif
    }

    hdr->vhl = vhl;
    hdr->len = short_be((uint16_t)(f->transport_len + f->net_len));
    if ((f->transport_hdr != f->payload)  &&
#ifdef PICO_SUPPORT_IPFRAG
        (0 == (f->frag & PICO_IPV4_MOREFRAG)) &&
#endif
        1 )
        ipv4_progressive_id++;

    hdr->id = short_be(ipv4_progressive_id);
    hdr->dst.addr = dst->addr;
    hdr->src.addr = link->address.addr;
    hdr->ttl = ttl;
    hdr->proto = proto;
    hdr->frag = short_be(PICO_IPV4_DONTFRAG);
#ifdef PICO_SUPPORT_IPFRAG
#  ifdef PICO_SUPPORT_UDP
    if (proto == PICO_PROTO_UDP) {
        /* first fragment, can not use transport_len to calculate IP length */
        if (f->transport_hdr != f->payload)
            hdr->len = short_be((uint16_t)(f->payload_len + sizeof(struct pico_udp_hdr) + f->net_len));

        /* set fragmentation flags and offset calculated in socket layer */
        hdr->frag = f->frag;
    }

    if (proto == PICO_PROTO_ICMP4)
        hdr->frag = f->frag;

#   endif
#endif /* PICO_SUPPORT_IPFRAG */
    pico_ipv4_checksum(f);

    if (f->sock && f->sock->dev) {
        /* if the socket has its device set, use that (currently used for DHCP) */
        f->dev = f->sock->dev;
    } else {
        f->dev = link->dev;
    }

#ifdef PICO_SUPPORT_MCAST
    if (pico_ipv4_is_multicast(hdr->dst.addr)) {
        struct pico_frame *cpy;
        /* Sending UDP multicast datagram, am I member? If so, loopback copy */
        if ((proto != PICO_PROTO_IGMP) && (pico_ipv4_mcast_filter(f) == 0)) {
            ip_mcast_dbg("MCAST: sender is member of group, loopback copy\n");
            cpy = pico_frame_copy(f);
            pico_enqueue(&in, cpy);
        }
    }

#endif

    if(pico_ipv4_link_get(&hdr->dst)) {
        /* it's our own IP */
        return pico_enqueue(&in, f);
    }else{
        /* TODO: Check if there are members subscribed here */
        return pico_enqueue(&out, f);
    }

drop:
    pico_frame_discard(f);
    return -1;
}


static int pico_ipv4_frame_sock_push(struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_ip4 *dst;
    struct pico_remote_endpoint *remote_endpoint = (struct pico_remote_endpoint *) f->info;
    IGNORE_PARAMETER(self);

    if (!f->sock) {
        pico_frame_discard(f);
        return -1;
    }

    if (remote_endpoint) {
        dst = &remote_endpoint->remote_addr.ip4;
    } else {
        dst = &f->sock->remote_addr.ip4;
    }

    return pico_ipv4_frame_push(f, dst, (uint8_t)f->sock->proto->proto_number);
}


int pico_ipv4_route_add(struct pico_ip4 address, struct pico_ip4 netmask, struct pico_ip4 gateway, int metric, struct pico_ipv4_link *link)
{
    struct pico_ipv4_route test, *new;
    test.dest.addr = address.addr;
    test.netmask.addr = netmask.addr;
    test.metric = (uint32_t)metric;

    if(pico_tree_findKey(&Routes, &test)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    new = PICO_ZALLOC(sizeof(struct pico_ipv4_route));
    if (!new) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->dest.addr = address.addr;
    new->netmask.addr = netmask.addr;
    new->gateway.addr = gateway.addr;
    new->metric = (uint32_t)metric;
    if (gateway.addr == 0) {
        /* No gateway provided, use the link */
        new->link = link;
    } else {
        struct pico_ipv4_route *r = route_find(&gateway);
        if (!r ) { /* Specified Gateway is unreachable */
            pico_err = PICO_ERR_EHOSTUNREACH;
            PICO_FREE(new);
            return -1;
        }

        if (r->gateway.addr) { /* Specified Gateway is not a neighbor */
            pico_err = PICO_ERR_ENETUNREACH;
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

    pico_tree_insert(&Routes, new);
    dbg_route();
    return 0;
}

int pico_ipv4_route_del(struct pico_ip4 address, struct pico_ip4 netmask, int metric)
{
    struct pico_ipv4_route test, *found;

    test.dest.addr = address.addr;
    test.netmask.addr = netmask.addr;
    test.metric = (uint32_t)metric;

    found = pico_tree_findKey(&Routes, &test);
    if (found) {

        pico_tree_delete(&Routes, found);
        PICO_FREE(found);

        dbg_route();
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}


int pico_ipv4_link_add(struct pico_device *dev, struct pico_ip4 address, struct pico_ip4 netmask)
{
    struct pico_ipv4_link test, *new;
    struct pico_ip4 network, gateway;
    char ipstr[30];

    if(!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.address.addr = address.addr;
    test.netmask.addr = netmask.addr;
    test.dev = dev;
    /** XXX: Valid netmask / unicast address test **/

    if(pico_tree_findKey(&Tree_dev_link, &test)) {
        pico_err = PICO_ERR_EADDRINUSE;
        return -1;
    }

    /** XXX: Check for network already in use (e.g. trying to assign 10.0.0.1/24 where 10.1.0.1/8 is in use) **/
    new = PICO_ZALLOC(sizeof(struct pico_ipv4_link));
    if (!new) {
        dbg("IPv4: Out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->address.addr = address.addr;
    new->netmask.addr = netmask.addr;
    new->dev = dev;
#ifdef PICO_SUPPORT_MCAST
    new->MCASTGroups = PICO_ZALLOC(sizeof(struct pico_tree));
    if (!new->MCASTGroups) {
        PICO_FREE(new);
        dbg("IPv4: Out of memory!\n");
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    new->MCASTGroups->root = &LEAF;
    new->MCASTGroups->compare = ipv4_mcast_groups_cmp;
    new->mcast_compatibility = PICO_IGMPV3; /* default RFC 3376 $7.2.1 */
    new->mcast_last_query_interval = PICO_IGMP_QUERY_INTERVAL;
#endif

    pico_tree_insert(&Tree_dev_link, new);
#ifdef PICO_SUPPORT_MCAST
    do {
        struct pico_ip4 mcast_all_hosts, mcast_addr, mcast_nm, mcast_gw;
        if (!mcast_default_link) {
            mcast_addr.addr = long_be(0xE0000000); /* 224.0.0.0 */
            mcast_nm.addr = long_be(0xF0000000); /* 15.0.0.0 */
            mcast_gw.addr = long_be(0x00000000);
            mcast_default_link = new;
            pico_ipv4_route_add(mcast_addr, mcast_nm, mcast_gw, 1, new);
        }

        mcast_all_hosts.addr = PICO_MCAST_ALL_HOSTS;
        pico_ipv4_mcast_join(&address, &mcast_all_hosts, 1, PICO_IP_MULTICAST_EXCLUDE, NULL);
    } while(0);
#endif

    network.addr = address.addr & netmask.addr;
    gateway.addr = 0U;
    pico_ipv4_route_add(network, netmask, gateway, 1, new);
    pico_ipv4_to_string(ipstr, new->address.addr);
    dbg("Assigned ipv4 %s to device %s\n", ipstr, new->dev->name);
    return 0;
}

static int pico_ipv4_cleanup_routes(struct pico_ipv4_link *link)
{
    struct pico_tree_node *index = NULL, *tmp = NULL;
    struct pico_ipv4_route *route = NULL;

    pico_tree_foreach_safe(index, &Routes, tmp)
    {
        route = index->keyValue;
        if (link == route->link)
            pico_ipv4_route_del(route->dest, route->netmask, (int)route->metric);
    }
    return 0;
}

void pico_ipv4_route_set_bcast_link(struct pico_ipv4_link *link)
{
    if (link)
        default_bcast_route.link = link;
}

int pico_ipv4_link_del(struct pico_device *dev, struct pico_ip4 address)
{
    struct pico_ipv4_link test, *found;

    if(!dev) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    test.address.addr = address.addr;
    test.dev = dev;
    found = pico_tree_findKey(&Tree_dev_link, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return -1;
    }

#ifdef PICO_SUPPORT_MCAST
    do {
        struct pico_ip4 mcast_all_hosts, mcast_addr, mcast_nm;
        struct pico_mcast_group *g = NULL;
        struct pico_tree_node *index, *_tmp;
        if (found == mcast_default_link) {
            mcast_addr.addr = long_be(0xE0000000); /* 224.0.0.0 */
            mcast_nm.addr = long_be(0xF0000000); /* 15.0.0.0 */
            mcast_default_link = NULL;
            pico_ipv4_route_del(mcast_addr, mcast_nm, 1);
        }

        mcast_all_hosts.addr = PICO_MCAST_ALL_HOSTS;
        pico_ipv4_mcast_leave(&address, &mcast_all_hosts, 1, PICO_IP_MULTICAST_EXCLUDE, NULL);
        pico_tree_foreach_safe(index, found->MCASTGroups, _tmp)
        {
            g = index->keyValue;
            pico_tree_delete(found->MCASTGroups, g);
            PICO_FREE(g);
        }
    } while(0);
#endif

    pico_ipv4_cleanup_routes(found);
    pico_tree_delete(&Tree_dev_link, found);
    PICO_FREE(found);

    return 0;
}


struct pico_ipv4_link *pico_ipv4_link_get(struct pico_ip4 *address)
{
    struct pico_ipv4_link test = {
        0
    }, *found = NULL;
    test.address.addr = address->addr;

    found = pico_tree_findKey(&Tree_dev_link, &test);
    if (!found)
        return NULL;
    else
        return found;
}

struct pico_ipv4_link *pico_ipv4_link_by_dev(struct pico_device *dev)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv4_link *link = NULL;

    pico_tree_foreach(index, &Tree_dev_link)
    {
        link = index->keyValue;
        if (link->dev == dev)
            return link;
    }
    return NULL;
}

struct pico_ipv4_link *pico_ipv4_link_by_dev_next(struct pico_device *dev, struct pico_ipv4_link *last)
{
    struct pico_tree_node *index = NULL;
    struct pico_ipv4_link *link = NULL;
    int valid = 0;

    if (last == NULL)
        valid = 1;

    pico_tree_foreach(index, &Tree_dev_link)
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

struct pico_device *pico_ipv4_link_find(struct pico_ip4 *address)
{
    struct pico_ipv4_link test, *found;
    if(!address) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    test.dev = NULL;
    test.address.addr = address->addr;
    found = pico_tree_findKey(&Tree_dev_link, &test);
    if (!found) {
        pico_err = PICO_ERR_ENXIO;
        return NULL;
    }

    return found->dev;
}


static int pico_ipv4_rebound_large(struct pico_frame *f)
{
#ifdef PICO_SUPPORT_IPFRAG
    uint32_t total_payload_written = 0;
    uint32_t len = f->transport_len;
    struct pico_frame *fr;
    struct pico_ip4 dst;
    struct pico_ipv4_hdr *hdr;
    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    dst.addr = hdr->src.addr;

    while(total_payload_written < len) {
        uint32_t space = (uint32_t)len - total_payload_written;
        if (space > PICO_IPV4_MAXPAYLOAD)
            space = PICO_IPV4_MAXPAYLOAD;

        fr = pico_ipv4_alloc(&pico_proto_ipv4, (uint16_t)space);
        if (!fr) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if (space + total_payload_written < len)
            fr->frag |= short_be(PICO_IPV4_MOREFRAG);
        else
            fr->frag &= short_be(PICO_IPV4_FRAG_MASK);

        fr->frag |= short_be((uint16_t)((total_payload_written) >> 3u));

        memcpy(fr->transport_hdr, f->transport_hdr + total_payload_written, fr->transport_len);
        if (pico_ipv4_frame_push(fr, &dst, hdr->proto) > 0) {
            total_payload_written += fr->transport_len;
        } else {
            pico_frame_discard(fr);
            break;
        }
    } /* while() */
    return (int)total_payload_written;
#else
    (void)f;
    return -1;
#endif
}

int pico_ipv4_rebound(struct pico_frame *f)
{
    struct pico_ip4 dst;
    struct pico_ipv4_hdr *hdr;
    if(!f) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    if (!hdr) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    dst.addr = hdr->src.addr;
    if (f->transport_len > PICO_IPV4_MAXPAYLOAD) {
        return pico_ipv4_rebound_large(f);
    }

    return pico_ipv4_frame_push(f, &dst, hdr->proto);
}

static int pico_ipv4_pre_forward_checks(struct pico_frame *f)
{
    static uint16_t last_id = 0;
    static uint16_t last_proto = 0;
    static struct pico_ip4 last_src = {0};
    static struct pico_ip4 last_dst = {0};
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;

    /* Decrease TTL, check if expired */
    hdr->ttl = (uint8_t)(hdr->ttl - 1);
    if (hdr->ttl < 1) {
        pico_notify_ttl_expired(f);
        dbg(" ------------------- TTL EXPIRED\n");
        return -1;
    }

    /* HACK: increase crc to compensate decreased TTL */
    hdr->crc++;

    /* If source is local, discard anyway (packets bouncing back and forth) */
    if (pico_ipv4_link_get(&hdr->src))
        return -1;

    /* If this was the last forwarded packet, silently discard to prevent duplications */
    if ((last_src.addr == hdr->src.addr) && (last_id == hdr->id)
           && (last_dst.addr == hdr->dst.addr) && (last_proto == hdr->proto)) {
        return -1;
    } else {
        last_src.addr = hdr->src.addr;
        last_dst.addr = hdr->dst.addr;
        last_id = hdr->id;
        last_proto = hdr->proto;
    }
    return 0;
}

static int pico_ipv4_forward(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *)f->net_hdr;
    struct pico_ipv4_route *rt;
    if (!hdr) {
        return -1;
    }

    rt = route_find(&hdr->dst);
    if (!rt) {
        pico_notify_dest_unreachable(f);
        return -1;
    }

    f->dev = rt->link->dev;

    if (pico_ipv4_pre_forward_checks(f) < 0)
        return -1;

    pico_ipv4_nat_outbound(f, &rt->link->address);

    f->start = f->net_hdr;
    if(f->dev->eth != NULL)
        f->len -= PICO_SIZE_ETHHDR;

    pico_sendto_dev(f);
    return 0;

}

int pico_ipv4_is_broadcast(uint32_t addr)
{
    struct pico_ipv4_link *link;
    struct pico_tree_node *index;
    if (addr == PICO_IP4_BCAST)
        return 1;

    pico_tree_foreach(index, &Tree_dev_link) {
        link = index->keyValue;
        if ((link->address.addr | (~link->netmask.addr)) == addr)
            return 1;
    }
    return 0;
}

void pico_ipv4_unreachable(struct pico_frame *f, int err)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
#if defined PICO_SUPPORT_TCP || defined PICO_SUPPORT_UDP
    f->transport_hdr = ((uint8_t *)f->net_hdr) + PICO_SIZE_IP4HDR;
    pico_transport_error(f, hdr->proto, err);
#endif
}

int pico_ipv4_cleanup_links(struct pico_device *dev)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;
    struct pico_ipv4_link *link = NULL;

    pico_tree_foreach_safe(index, &Tree_dev_link, _tmp)
    {
        link = index->keyValue;
        if (dev == link->dev)
            pico_ipv4_link_del(dev, link->address);
    }
    return 0;
}


#endif
