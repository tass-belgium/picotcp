/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Ludo Mondelaers, Laurens Miers
 *********************************************************************/


#include "pico_config.h"
#ifdef PICO_SUPPORT_IPV6
#include "pico_ipv6.h"
#include "pico_icmp6.h"
#endif
#ifdef PICO_SUPPORT_IPV4
#include "pico_ipv4.h"
#include "pico_icmp4.h"
#endif
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"
#include "pico_constants.h"
#include "pico_fragments.h"

/*** macros ***/

#define PICO_IP_FRAG_TIMEOUT          60000
#define PICO_IP_LAST_FRAG_RECV        1
#define PICO_IP_FIRST_FRAG_RECV       2
#define PICO_IP_FIRST_FRAG_NOT_RECV   3

//#define IPFRAG_DEBUG
#ifdef IPFRAG_DEBUG
#  define frag_dbg  printf
#else
# define frag_dbg(...) do{}while(0);
#endif


//PICO_IPV4_MTU

/*** Type definitions ***/

typedef struct
{
    // uniquely identify fragments by: (RFC 791 & RFC 2460)
    uint32_t            frag_id;
    uint8_t             proto; //
    union pico_address  src;
    union pico_address  dst;

//    PICO_TREE_DECLARE(holes, hole_compare); // this macro contains an initialisation to a global variable: can not use it here
    struct pico_tree    holes;

    struct pico_frame * frame;
    pico_time           expire;

    uint32_t 			net_hdr_offset;
    uint32_t 			transport_hdr_offset;

}pico_fragment_t;

typedef     struct
{
    uint16_t first;
    uint16_t last;
}pico_hole_t;

/***  Prototypes ***/

static int fragments_compare(void *fa, void *fb);   /*pico_fragment_t*/
static int hole_compare(void *a, void *b);          /*pico_hole_t*/
static int first_fragment_received(struct pico_tree *holes);

// alloc and free of fragment tree
static pico_fragment_t *pico_fragment_alloc( uint16_t iphdrsize, uint32_t bufsize);
static pico_fragment_t *pico_fragment_free(pico_fragment_t * fragment);

static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame, uint16_t byte_offset, uint16_t more_flag );
// alloc and free for the hole tree
static pico_hole_t* pico_hole_free(pico_hole_t *hole);
static pico_hole_t* pico_hole_alloc(uint16_t first,uint16_t last);

static void pico_ip_frag_expired(pico_time now, void *arg);
static int copy_eth_hdr(struct pico_frame* dst, struct pico_frame* src);
static int copy_ipv6_hdrs_nofrag(struct pico_frame* dst, struct pico_frame* src);

/*** static declarations ***/
//static     PICO_TREE_DECLARE(ip_fragments, fragments_compare);
static struct pico_tree    pico_fragments = { &LEAF, fragments_compare};
// our timer: allocoate one instance
static struct pico_timer*      pico_fragment_timer = NULL;



/*** global function called from pico_ipv6.c ***/

#ifdef PICO_SUPPORT_IPV6
// byte offset and more flag from exthdr (RFC2460)
#define IP6FRAG_OFF(frag)  ((frag & 0xFFF8))
#define IP6FRAG_MORE(frag) ((frag & 0x0001) ? 1 : 0)

#define IP6FRAG_ID(exthdr) ((uint32_t)((exthdr->ext.frag.id[0] << 24)   |   \
                                       (exthdr->ext.frag.id[1] << 16)   |   \
                                       (exthdr->ext.frag.id[2] << 8)    |   \
                                        exthdr->ext.frag.id[3]))

static int copy_eth_hdr(struct pico_frame* dst, struct pico_frame* src)
{
    struct pico_eth_hdr *srchdr = NULL;
    struct pico_eth_hdr *dsthdr = NULL;

    if (!dst || !src)
    {
        return -1;
    }

    srchdr = (struct pico_eth_hdr *)src->datalink_hdr;
    dsthdr = (struct pico_eth_hdr *)dst->datalink_hdr;

    if (!srchdr || !dsthdr)
    {
        return -1;
    }

    memcpy(dsthdr, srchdr, PICO_SIZE_ETHHDR);
    return 0;
}

static int copy_ipv6_hdrs_nofrag(struct pico_frame* dst, struct pico_frame* src)
{
    int done = 0;
    struct pico_ipv6_hdr *srchdr = NULL;
    struct pico_ipv6_hdr *dsthdr = NULL;
    int srcidx = 0;
    uint16_t dstidx = 0;
    uint16_t retval = 0;
    uint8_t nxthdr = 0;
    uint8_t* pdstnxthdr = NULL;

    if (!dst || !src)
    {
        return -1;
    }

    srchdr = (struct pico_ipv6_hdr *)src->net_hdr;
    dsthdr = (struct pico_ipv6_hdr *)dst->net_hdr;

    if (!srchdr || !dsthdr)
    {
        return -1;
    }


    nxthdr = srchdr->nxthdr;
    pdstnxthdr = &dsthdr->nxthdr;

    frag_dbg("[LUM:%s:%d] begin offset for pdstnxthdr:%d\n", __FILE__,__LINE__, (uint32_t)(pdstnxthdr - (uint8_t*)dsthdr));
    // copy ethernet header + IPv6 header
    memcpy(dst->buffer + PICO_SIZE_ETHHDR, src->buffer + PICO_SIZE_ETHHDR, PICO_SIZE_IP6HDR);

    retval = src->net_len;

    // parse ext hdrs
    while(!done)
    {
        frag_dbg("[LUM:%s:%d] nxthdr:%d %s\n", __FILE__,__LINE__,nxthdr,
                 nxthdr == PICO_IPV6_EXTHDR_DESTOPT  ? "PICO_IPV6_EXTHDR_DESTOPT":
                 nxthdr == PICO_IPV6_EXTHDR_ROUTING	? "PICO_IPV6_EXTHDR_ROUTING":
                 nxthdr == PICO_IPV6_EXTHDR_HOPBYHOP ? "PICO_IPV6_EXTHDR_HOPBYHOP":
                 nxthdr == PICO_IPV6_EXTHDR_ESP      ? "PICO_IPV6_EXTHDR_ESP":
                 nxthdr == PICO_IPV6_EXTHDR_AUTH		? "PICO_IPV6_EXTHDR_AUTH":
                 nxthdr == PICO_IPV6_EXTHDR_FRAG     ? "PICO_IPV6_EXTHDR_FRAG":
                 nxthdr == PICO_IPV6_EXTHDR_NONE		? "PICO_IPV6_EXTHDR_NONE":
                 nxthdr == PICO_PROTO_TCP			? "PICO_PROTO_TCP":
                 nxthdr == PICO_PROTO_UDP			? "PICO_PROTO_UDP":
                 nxthdr == PICO_PROTO_ICMP6			? "PICO_PROTO_ICMP6":
                 nxthdr == PICO_ICMP6_ECHO_REQUEST	? "PICO_ICMP6_ECHO_REQUEST":
                 nxthdr == PICO_ICMP6_DEST_UNREACH	? "PICO_ICMP6_DEST_UNREACH":
                 nxthdr == PICO_ICMP6_PKT_TOO_BIG	? "PICO_ICMP6_PKT_TOO_BIG":
                 nxthdr == PICO_ICMP6_ECHO_REPLY		? "PICO_ICMP6_ECHO_REPLY":
                 nxthdr == PICO_ICMP6_ROUTER_SOL		? "PICO_ICMP6_ROUTER_SOL":
                 nxthdr == PICO_ICMP6_ROUTER_ADV		? "PICO_ICMP6_ROUTER_ADV":
                 nxthdr == PICO_ICMP6_NEIGH_SOL		? "PICO_ICMP6_NEIGH_SOL":
                 nxthdr == PICO_ICMP6_NEIGH_ADV		? "PICO_ICMP6_NEIGH_ADV":
                 nxthdr == PICO_ICMP6_REDIRECT		? "PICO_ICMP6_REDIRECT":
                 "unknown");

        switch(nxthdr)
        {
        case PICO_IPV6_EXTHDR_DESTOPT:
        case PICO_IPV6_EXTHDR_ROUTING:
        case PICO_IPV6_EXTHDR_HOPBYHOP:
        case PICO_IPV6_EXTHDR_ESP:
        case PICO_IPV6_EXTHDR_AUTH:
        {
            uint8_t len = (uint8_t)(srchdr->extensions[srcidx+1] << 3);
            frag_dbg("[LUM:%s:%d] nxthdr:%d len:%d pdstnxthdr:%p\n", __FILE__,__LINE__,nxthdr,len,pdstnxthdr);
            memcpy(&dsthdr->extensions[dstidx],&srchdr->extensions[srcidx],(size_t)len);
            srcidx += len;
            dstidx = (uint16_t)(dstidx + len);
            *pdstnxthdr = nxthdr;
            pdstnxthdr = &dsthdr->extensions[dstidx];
            frag_dbg("[LUM:%s:%d] offset voor pdstnxthdr:%d\n", __FILE__,__LINE__, (uint32_t)(pdstnxthdr - (uint8_t*)dsthdr));
        }
        break;
        case PICO_IPV6_EXTHDR_FRAG:
            srcidx += 8;            // remove frag field from dsthdr
            retval = (uint16_t)(retval - 8u);
			break;
        case PICO_IPV6_EXTHDR_NONE:
        case PICO_PROTO_TCP:
        case PICO_PROTO_UDP:
        case PICO_PROTO_ICMP6:
        case PICO_ICMP6_ECHO_REQUEST:
            *pdstnxthdr = nxthdr;
            frag_dbg("[LUM:%s:%d] offset for pdstnxthdr:%d\n", __FILE__,__LINE__, (uint32_t)(pdstnxthdr - (uint8_t*)dsthdr));
            done=1;
			break;
        default:
			/* Invalid next header */
            frag_dbg("[LUM:%s:%d] unrecognised nxthdr:%d \n",__FILE__,__LINE__,nxthdr);
            pico_icmp6_parameter_problem(src, PICO_ICMP6_PARAMPROB_NXTHDR, (uint32_t)nxthdr);
            done=1;
			break;
        }
        nxthdr = srchdr->extensions[srcidx];   // advance pointer
    }
    dst->payload = &dsthdr->extensions[dstidx];
    dst->transport_hdr = dst->payload;

	frag_dbg("[LUM:%s:%d] ipv6 hdr without frag len:%d \n",__FILE__,__LINE__, retval);

    return retval;
}


void pico_ipv6_process_frag(struct pico_ipv6_exthdr *exthdr, struct pico_frame *f, uint8_t proto /* see pico_addressing.h */)
{
    int retval = 0;
    uint16_t netlen_without_frag = 0;

    if(exthdr && f)
    {
        struct pico_ipv6_hdr *ip6hdr=(struct pico_ipv6_hdr*)f->net_hdr;
        /* Double braces to get rid of (gcc) compiler warning
         * is a bug in gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
         */
        union pico_address src = { {0} };
        union pico_address dst = { {0} };

        // does the fragment already have its fragment tree?
        pico_fragment_t key;
        pico_fragment_t *fragment = NULL;

		src.ip6 = ip6hdr->src;
        dst.ip6 = ip6hdr->dst;

        memset(&key,0,sizeof(pico_fragment_t));
        key.frag_id = IP6FRAG_ID(exthdr);
        key.proto = proto;

        key.src = src; //src ip6
        key.dst = dst;   // dst ip6

        fragment = pico_tree_findKey( &pico_fragments,  &key);
        if(!fragment)  // this is a new frag_id
        {
            // allocate fragment tree
            fragment = pico_fragment_alloc( PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR, f->buffer_len);

			frag_dbg("[LUM:%s:%d] frag_id not found in fragment tree. frag_id:0x%X \n",__FILE__,__LINE__,IP6FRAG_ID(exthdr));

            if(fragment)
            {
                /* TODO:  options are not being handled now */

                if(IP6FRAG_OFF(f->frag) == 0)  // offset is 0
                {
                    // if first frame: copy options  see RFC815
                }
                else
                {
                    //fragment is not the first fragment: assume no options, and add them later
                }

                // copy headers to reassambled package (but delete the fragment header)
                if (copy_eth_hdr(fragment->frame, f) != 0)
                {
                    pico_fragment_free(fragment);
                    return;
                }

                retval = copy_ipv6_hdrs_nofrag(fragment->frame, f);

                if (retval <= 0)
                {
                    pico_fragment_free(fragment);
                    return;
                }

                netlen_without_frag = (uint16_t)(retval - PICO_SIZE_ETHHDR);
                // copy payload
                memcpy(fragment->frame->transport_hdr,f->transport_hdr,f->transport_len);
                // TODO: this is done in pico_fragment_arrived, but if the packet is not fragmented, it may be lost (I think), further investigate

                // Update netlen
                fragment->frame->net_len = netlen_without_frag;



                fragment->frag_id = IP6FRAG_ID(exthdr);
                fragment->proto = proto;
				fragment->src.ip6 = src.ip6;
				fragment->dst.ip6 = dst.ip6;

                /* fragment->holes.compare = hole_compare; */
                /* fragment->holes.root = &LEAF; */

                pico_tree_insert(&pico_fragments, fragment);

            }
        }
        if(fragment)
        {
			uint16_t offset = IP6FRAG_OFF(f->frag);
            uint16_t more   = IP6FRAG_MORE(f->frag);

            retval = pico_fragment_arrived(fragment, f, offset, more);

            if (retval == PICO_IP_LAST_FRAG_RECV)
            {
                // This was the last packet
                // all done with this fragment: send it up and free it
                pico_transport_receive(fragment->frame, fragment->proto);
                // picoTCP still needs the fragment->frame, but we don't
                // make fragment->frame NULL so that the fragment_free does not clean it up (else we lost the packet)
                fragment->frame = NULL;
                pico_fragment_free(fragment);
            }
            else
            {
                /* TODO:  */
            }
        }
    }
}
#endif

#ifdef PICO_SUPPORT_IPV4


#define IP4FRAG_ID(hdr) (hdr->id)

// byte offset and more flag from iphdr (RFC791)
#define IP4FRAG_OFF(frag)  (((uint32_t)frag & PICO_IPV4_FRAG_MASK) << 3ul)
#define IP4FRAG_MORE(frag) ((frag & PICO_IPV4_MOREFRAG) ? 1 : 0)


int pico_ipv4_process_frag(struct pico_ipv4_hdr *hdr, struct pico_frame *f, uint8_t proto /* see pico_addressing.h */)
{
    int retval = 0;
    if(hdr && f)
    {
        // does the fragment already has its fragment tree?
        pico_fragment_t key;
        pico_fragment_t *fragment = NULL;

        //  hdr is stored in network order !!! oh crap
        uint16_t offset = IP4FRAG_OFF(short_be(hdr->frag));
        uint16_t more   = IP4FRAG_MORE(short_be(hdr->frag));

        struct pico_ipv4_hdr *ip4hdr=(struct pico_ipv4_hdr*)f->net_hdr;
        /* Double braces to get rid of (gcc) compiler warning
         * is a bug in gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
         */
        union pico_address src = { {0} };
        union pico_address dst = { {0} };

        src.ip4 = ip4hdr->src;
        dst.ip4 = ip4hdr->dst;

        memset(&key,0,sizeof(pico_fragment_t));

        key.src = src; //src ip4
        key.dst = dst;   // dst ip4
        key.frag_id = short_be(IP4FRAG_ID(hdr));
        key.proto = proto;

        if(!more &&  (offset == 0))
        {
            frag_dbg("[LUM:%s:%d] Not a fragmented packet, carry on.\n",__FILE__,__LINE__);
            // no need for reassemble packet
            return PICO_IP_LAST_FRAG_RECV;    // process orig packet (return 1)
        }

        fragment = pico_tree_findKey( &pico_fragments,  &key);

        frag_dbg("[LUM:%s:%d] Searching for frag_id:0x%X proto:%d(%s): %s \n",
                    __FILE__,__LINE__,
                    key.frag_id,
                    key.proto,
                        (proto == PICO_PROTO_IPV4)  ? "PICO_PROTO_IPV4" :
                        (proto == PICO_PROTO_ICMP4) ? "PICO_PROTO_ICMP4" :
                        (proto == PICO_PROTO_IGMP)  ? "PICO_PROTO_IGMP" :
                        (proto == PICO_PROTO_TCP)   ? "PICO_PROTO_TCP" :
                        (proto == PICO_PROTO_UDP)   ? "PICO_PROTO_UDP" :
                        (proto == PICO_PROTO_IPV6)  ? "PICO_PROTO_IPV6" :
                        (proto == PICO_PROTO_ICMP6) ? "PICO_PROTO_ICMP6" :  "unknown",
                    fragment?"FOUND":"NOT FOUND");

        if(!fragment)  // this is a new frag_id
        {
            frag_dbg("[LUM:%s:%d] frag_id:0x%X not found, allocate a new fragment.\n",__FILE__,__LINE__, key.frag_id);
            // allocate fragment tree
            fragment = pico_fragment_alloc( PICO_SIZE_ETHHDR + PICO_SIZE_IP4HDR, PICO_IPV4_MTU + 64 /*max length of options*/);
            if(fragment)
            {
                /* TODO: options are not being copied properly */
                if(IP4FRAG_OFF(f->frag) == 0)
                {
                    // if first frame: TODO copy options  see RFC815
                    //fragment->start_payload = PICO_SIZE_IP4HDR;
                }
                else
                {
                    //fragment is not the first fragment: assume no options, and add them later
                    //fragment->start_payload = PICO_SIZE_IP4HDR;
                }

                if(fragment->frame->net_hdr &&  f->net_hdr)
                {
                    memcpy(fragment->frame->net_hdr, f->net_hdr, f->net_len);
                }
                else
                {
                    frag_dbg("[%s:%d] fragment->frame->net_hdr:%p f->net_hdr:%p PICO_SIZE_ETHHDR + PICO_SIZE_IP4HDR:%d);\n",__FILE__,__LINE__,fragment->frame->net_hdr,f->net_hdr,PICO_SIZE_ETHHDR + PICO_SIZE_IP4HDR);
                }

                fragment->frag_id = key.frag_id;
                fragment->src.ip4 = key.src.ip4;
                fragment->dst.ip4 = key.dst.ip4;
                fragment->frame->frag = 0;  // remove frag options
                fragment->frame->proto = proto;
                fragment->proto = proto;
                /* fragment->holes.compare = hole_compare; */
                /* fragment->holes.root = &LEAF; */

                pico_tree_insert(&pico_fragments, fragment);
            }
        }
        if(fragment)
        {
            frag_dbg("[LUM:%s:%d] frag_id:0x%X found.\n",__FILE__,__LINE__, key.frag_id);
            frag_dbg("[LUM:%s:%d] recv a fragmented packet, handle it.\n",__FILE__,__LINE__);
            retval = pico_fragment_arrived(fragment, f, offset, more);

            if (retval == PICO_IP_LAST_FRAG_RECV)
            {
                //This was the last packet
                //Calculate crc of final reassambled packet

                struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) fragment->frame->net_hdr;

                if(net_hdr)
                {
                    net_hdr->crc = 0;
                    net_hdr->crc = short_be(pico_checksum(net_hdr, fragment->frame->net_len));
                }
                else
                {
                    frag_dbg("[LUM:%s:%d] net_hdr NULL \n",__FILE__,__LINE__);
                }
                frag_dbg("[LUM:%s:%d] send the reassembled packet upstream \n",__FILE__,__LINE__);

                // all done with this fragment: send it up and free it
                pico_transport_receive(fragment->frame, fragment->proto);
                fragment->frame = NULL;
                pico_fragment_free(fragment);
            }
            else
            {
                /* TODO:  */
            }
        }
    }
    return retval;
}
#endif



static int fragments_compare(void *a, void *b)
{
    pico_fragment_t *fa = a;
    pico_fragment_t *fb = b;
    int retval=0;

    if(fa && fb)
    {
        if((retval = (int)(fa->frag_id - fb->frag_id)) == 0)    // fragid
        {
            if((retval = (int)(fa->proto - fb->proto)) == 0)  // and protocol
            {
#if 1
                if((fa->proto == PICO_PROTO_IPV4)  || (fa->proto == PICO_PROTO_ICMP4)  ||
                    (fa->proto == PICO_PROTO_IGMP) || (fa->proto == PICO_PROTO_TCP)    ||
                        (fa->proto == PICO_PROTO_UDP))
                {
                    if((retval = memcmp(&fa->src,&fb->src,sizeof(struct pico_ip4))) == 0) //src ip4
                    {
                        retval = memcmp(&fa->dst,&fb->dst,sizeof(struct pico_ip4));       //dst
                    }  //  source addr   & dest addr
                }
                else if ((fa->proto == PICO_PROTO_IPV6)  ||                  (fa->proto == PICO_PROTO_ICMP6))
                {
                    if((retval = memcmp(&fa->src,&fb->src,sizeof(struct pico_ip6))) == 0) //src ip6
                    {
                        retval = memcmp(&fa->dst,&fb->dst,sizeof(struct pico_ip6));   // dst ip6
                    }
                }
#else
     			frag_dbg("[LUM:%s:%d] src and dst ip not checked  \n",__FILE__,__LINE__);

#endif
            }
        }
    }
    else
    {
        retval = -1;
    }
    return retval;
}




static pico_fragment_t *pico_fragment_alloc( uint16_t iphdrsize, uint32_t bufsize )  // size = exthdr + payload (MTU)
{
    pico_fragment_t* fragment;

    if (iphdrsize <= 0 || bufsize<= 0)
    {
        return NULL;
    }

    fragment = PICO_ZALLOC(sizeof(pico_fragment_t) );

    if(fragment)
    {
        struct pico_frame* frame  = pico_frame_alloc((uint32_t)(bufsize + iphdrsize));

        if(frame)
        {
#ifdef IPFRAG_DEBUG
            memset(frame->buffer, 0x55, (size_t)(bufsize + iphdrsize));
#endif
            frame->net_hdr = frame->buffer + PICO_SIZE_ETHHDR;
            frame->net_len = iphdrsize;
            frag_dbg("[LUM:%s:%d] frame->net_len:%d  \n",__FILE__,__LINE__, frame->net_len);

            frame->transport_hdr = frame->net_hdr + iphdrsize;
            frame->transport_len = 0;

            frame->datalink_hdr = frame->buffer;

            fragment->net_hdr_offset = PICO_SIZE_ETHHDR;
            fragment->transport_hdr_offset = (uint32_t)(PICO_SIZE_ETHHDR + iphdrsize);


            fragment->frame = frame;

            fragment->holes.compare = hole_compare;
            fragment->holes.root = &LEAF;
        }
    }
    return fragment;
}


static pico_fragment_t *pico_fragment_free(pico_fragment_t * fragment)
{
    if(fragment)
    {
        struct pico_tree_node *idx=NULL;
        struct pico_tree_node *tmp=NULL;

        /* cancel timer */
        if(fragment->expire)
        {
            fragment->expire = 0;
        }

        /*empty hole tree*/
        pico_tree_foreach_safe(idx, &fragment->holes, tmp)
        {
            pico_hole_t *hole = idx->keyValue;

            pico_tree_delete(&fragment->holes, hole);
            pico_hole_free(hole);
            hole = NULL;
        }

        if(fragment->frame)
        {
            /* discard frame*/
            pico_frame_discard(fragment->frame);
            fragment->frame = NULL;
        }
        pico_tree_delete(&pico_fragments, fragment);
        PICO_FREE(fragment);
        fragment = NULL;
    }
    return NULL;
}

/***
*
*  following functions use the hole algo as described in rfc815
*
***/



static int hole_compare(void* a,void* b)
{
    pico_hole_t *ha = (pico_hole_t *)a;
    pico_hole_t *hb = (pico_hole_t *)b;
    if(ha && hb)
    {
        return  (ha->first - hb->first);
    }
    else
    {
        return -1;
    }
}


static pico_hole_t* pico_hole_alloc(uint16_t first,uint16_t last)
{
    pico_hole_t* hole = NULL;

    if (first > last)
    {
        return NULL;
    }

    hole = PICO_ZALLOC(sizeof(pico_hole_t));
    if(hole)
    {
        hole->first=first;
        hole->last=last;
    }
    return hole;
}


static pico_hole_t* pico_hole_free(pico_hole_t *hole)
{
    if(hole)
    {
        PICO_FREE(hole);
        hole=NULL;
    }
    return hole;
}

static int first_fragment_received(struct pico_tree *holes)
{
    pico_hole_t *hole = NULL;
    struct pico_tree_node *idx=NULL, *tmp=NULL;
    int retval = PICO_IP_FIRST_FRAG_RECV;

    if (holes)
    {
        pico_tree_foreach_safe(idx, holes, tmp)
        {
            hole = idx->keyValue;
            frag_dbg("[LUM:%s:%d] examining hole:%d-%d \n",__FILE__,__LINE__,hole->first,hole->last);
            if (hole->first == 0)
            {
                /* We did not receive the first fragment, do not send notify*/
                frag_dbg("[LUM:%s:%d] we did not recv the first fragment, do not send notify \n",__FILE__,__LINE__);
                retval = PICO_IP_FIRST_FRAG_NOT_RECV;
                break;
            }
        }
    }
    else
    {
        retval = -1;
    }

    return retval;
}

static void pico_ip_frag_expired(pico_time now, void *arg)
{
    pico_fragment_t * fragment = NULL;
    struct pico_tree_node *idx = NULL;
    struct pico_tree_node *tmp = NULL;
    uint32_t empty = 1;

    (void)arg;
    pico_fragment_timer = NULL;  // timer expired
    //frag_dbg("[LUM:%s%d] inside pico_ip_frag_expired \n",__FILE__,__LINE__);

    pico_tree_foreach_safe(idx, &pico_fragments, tmp)
    {
        fragment = idx->keyValue;
        if(fragment->expire < now)
        {
            uint16_t ip_version = ((struct pico_eth_hdr *) fragment->frame->datalink_hdr)->proto;

            frag_dbg("[%s:%d] fragment expired:%p frag_id:0x%X \n",__FILE__,__LINE__,fragment, fragment->frag_id);
#ifdef PICO_SUPPORT_IPV6
            if (ip_version == PICO_IDETH_IPV6)
            {
                /* Check if we received the first fragment of the packet
                 * If so, we send a "frag expired". Else we don't.
                 */
                if (first_fragment_received(&fragment->holes) == PICO_IP_FIRST_FRAG_RECV)
                {
                    /* First fragment was recv, send notify */
                    frag_dbg("LUM[%s:%d] fragment expired:%p frag_id:0x%X, sending notify \n",__FILE__,__LINE__,fragment, fragment->frag_id);
                    pico_icmp6_frag_expired(fragment->frame);
                }
            }
#endif
            if (ip_version == PICO_IDETH_IPV4)
            {
                //TODO: what does IPV4 expect?
            }

            fragment->frame = NULL;
            pico_fragment_free(fragment);
            fragment=NULL;
        }
        empty=0;
    }
    if(!empty)  // if still fragments in the tree...
    {
        // once the timer is expired, it is removed from the queue
        // if there are still fragments in the tree, restart the timer
        pico_fragment_timer = pico_timer_add(3000, /*cleanup expired fragments every x ms*/ pico_ip_frag_expired, NULL);
        //frag_dbg("[LUM:%s:%d] added timer %p \n",__FILE__,__LINE__,pico_fragment_timer);
    }
}


#define INFINITY 55555 /* just a big number <16bits*/

// note: offset and more flag are located differently in ipv4(iphdr) and ipv6(exthdr)
// offset is expressed in octets (bytes) (not the 8 byte unit used in ip)

static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame, uint16_t offset, uint16_t more )
{
    struct pico_frame* full=NULL;
    int retval = -1;
    pico_hole_t *first = NULL;

    if(fragment && frame)
    {

#ifdef IPFRAG_DEBUG
        frag_dbg("[LUM:%s:%d] content of fragmented packet: %p net_len:%d transport_len:%d\n",__FILE__,__LINE__,fragment->frame->buffer,fragment->frame->net_len,fragment->frame->transport_len);
        if(1)
        {
            int i;
            for(i=0;i < fragment->frame->net_len;i=i+8)
            {
                frag_dbg("0x%04X: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X \n",i,
                         frame->buffer[i+0],frame->buffer[i+1],frame->buffer[i+2],frame->buffer[i+3],
                         frame->buffer[i+4],frame->buffer[i+5],frame->buffer[i+6],frame->buffer[i+7]);
            }
        }
#endif

        first = pico_tree_first(&fragment->holes);

        if(first == NULL)   /*first fragment of packet arrived*/
        {
            pico_hole_t *hole = pico_hole_alloc((uint16_t)0,(uint16_t)INFINITY);
            frag_dbg("[LUM:%s:%d] first fragment of packet arrived:fragment:%p fragment->holes:%p \n",__FILE__,__LINE__,fragment,&fragment->holes);

            if(hole)
            {
                pico_tree_insert(&fragment->holes,hole);
            }
            fragment->expire = PICO_TIME_MS() + PICO_IP_FRAG_TIMEOUT;  // fragment expires when the packet is not complete after timeout
            if(pico_fragment_timer == NULL)
            {
                pico_fragment_timer = pico_timer_add(1000, /*cleanup expired fragments every sec*/ pico_ip_frag_expired, NULL);
            }

            // Update pico device
            // TODO: do we need a pico_frame_copy/deepcopy for the other parameters?
            fragment->frame->dev = frame->dev;

        }

        // copy the received frame into the reassembled packet
        frag_dbg("[LUM:%s:%d] offset:%d frame->transport_len:%d fragment->frame->buffer_len:%d\n",__FILE__,__LINE__,offset,frame->transport_len,fragment->frame->buffer_len);
        if( (offset + frame->transport_len) <= fragment->frame->transport_len ) // check for buffer space
        {
            if(fragment->frame->transport_hdr && frame->transport_hdr)
            {
                //frag_dbg("[LUM:%s:%d]  Reassemble packet:      fragment:%p fragment->frame:%p fragment->frame->transport_hdr:%p frame:%p frame->transport_hdr:%p frame->transport_len:%d\n",
                //            __FILE__,__LINE__, fragment,   fragment->frame,   fragment->frame->transport_hdr,   frame,   frame->transport_hdr,   frame->transport_len);
                memcpy(fragment->frame->transport_hdr + offset , frame->transport_hdr, frame->transport_len);
                retval = frame->transport_len;
            }
            else
            {
                frag_dbg("[LUM:%s:%d] TODO: notify ICMP, no transport_hdrs",__FILE__,__LINE__);
                // notify icmp
                pico_fragment_free(fragment);
                fragment=NULL;
            }
        }
        else
        {
            int addr_diff;

            // frame->buffer is too small
            // grow frame and copy new recv frame
            uint32_t alloc_len= frame->transport_len + fragment->frame->buffer_len;

            frag_dbg("[LUM:%s:%d] frame->buffer is too small realloc'd:%p buffer:%p \n",__FILE__,__LINE__,old_buffer,new_buffer );
            frag_dbg("[LUM:%s:%d] frame->buffer original size: %d \n",__FILE__,__LINE__,fragment->frame->buffer_len);
            frag_dbg("[LUM:%s:%d] frame->buffer new size: %d \n",__FILE__,__LINE__, alloc_len);
            frag_dbg("[LUM:%s:%d] recv frame size: %d \n",__FILE__,__LINE__, frame->buffer_len);
            // copy hdrs + options + data
            if(pico_frame_grow(fragment->frame, alloc_len) == 0)
            {

                frag_dbg("[LUM:%s:%d] net_hdr:%p transport_hdr:%p\n",__FILE__,__LINE__,fragment->frame->net_hdr,fragment->frame->transport_hdr);

                /* Copy new frame */
                memcpy(fragment->frame->transport_hdr + offset , frame->transport_hdr, frame->transport_len);
                /* Update transport len */
                fragment->frame->transport_len += frame->transport_len;
                retval = frame->transport_len;
            }
            else
            {
				frag_dbg("[LUM:%s:%d] Failed to allocate frame buffer \n",__FILE__,__LINE__ );
                // discard packet: no more memory
                pico_fragment_free(fragment);
                return -1;
                // notify icmp
            }
        }



        if(!more)    /*last fragment of packet arrived*/
        {
            // retrieve the size of the reassembled packet
            pico_hole_t* hole = pico_tree_last(&fragment->holes);
            uint16_t reassambled_payload_len = (uint16_t)(offset + frame->transport_len);

            if(hole /*&& IS_LEAF(hole)*/)
            {
                hole->last = reassambled_payload_len;
                frag_dbg("[LUM:%s:%d] reassembled packet size:%d \n",__FILE__,__LINE__,hole->last);
                // adjust transport len
                frag_dbg("[LUM:%s:%d] before adjusted transportlen:%d \n",__FILE__,__LINE__,fragment->frame->transport_len);
                fragment->frame->transport_len = (uint16_t)(offset + frame->transport_len);
                frag_dbg("[LUM:%s:%d] after adjusted transportlen:%d \n",__FILE__,__LINE__,fragment->frame->transport_len);

                if(hole->first == hole->last)
                {
                    pico_tree_delete(&fragment->holes,hole);    // all done!
                }
            }

            // Update net_len in hdr
            fragment->frame->net_hdr[4] = (uint8_t)((reassambled_payload_len >> 8) &  0xFF);
            fragment->frame->net_hdr[5] = (uint8_t)((reassambled_payload_len) & 0xFF);

            // Update total buffer len
            fragment->frame->buffer_len = (uint32_t)(reassambled_payload_len + fragment->frame->net_len + PICO_SIZE_ETHHDR);
            fragment->frame->len = (uint32_t)(reassambled_payload_len + fragment->frame->net_len + PICO_SIZE_ETHHDR);
        }


    }
    // do the administration of the missing holes
    if(fragment && (full=fragment->frame) && frame)
    {
        struct pico_tree_node *idx=NULL, *tmp=NULL;
        pico_hole_t *hole = NULL;
        uint16_t    frame_first = offset;
        uint16_t    frame_last  = (uint16_t)(frame_first + frame->transport_len);


        frag_dbg("[LUM:%s:%d] frame_first:%d frame_last:%d offset:%d more:%d fragment->holes:%p \n",__FILE__,__LINE__,frame_first,frame_last,offset,more,&fragment->holes );

        /*RFC 815 step 1*/
        pico_tree_foreach_safe(idx, &fragment->holes, tmp)
        {
            hole = idx->keyValue;
            /*RFC 815 step 2*/
            if(frame_first > hole->last)
            {
                continue;
            }
            /*RFC 815 step 3*/
            else if(frame_last < hole->first)
            {
                continue;
            }
            /*RFC 815 step 4*/
            frag_dbg("[LUM:%s:%d] deleting hole:%d-%d \n",__FILE__,__LINE__,hole->first,hole->last);
            pico_tree_delete(&fragment->holes, hole);
            /*RFC 815 step 5*/
            if(frame_first > hole->first)
            {
                pico_hole_t *new_hole =  pico_hole_alloc(hole->first,(uint16_t)(frame_first - 1u));
                if(new_hole)
                {
                    frag_dbg("[LUM:%s:%d] inserting new hole:%d-%d \n",__FILE__,__LINE__,new_hole->first,new_hole->last);
                    pico_tree_insert(&fragment->holes, new_hole);
                }
            }
            /*RFC 815 step 6*/
            else if(frame_last < hole->last)
            {
                pico_hole_t *new_hole =  pico_hole_alloc((uint16_t)(frame_last + 1u),hole->last);
                if(new_hole)
                {
                    frag_dbg("[LUM:%s:%d] inserting new hole:%d-%d \n",__FILE__,__LINE__,new_hole->first,new_hole->last);
                    pico_tree_insert(&fragment->holes, new_hole);
                }
            }
            /*RFC 815 step 7*/
            PICO_FREE(hole);
            hole=NULL;
        }

#if 0 //def IPFRAG_DEBUG
        if(fragment)
        {
            struct pico_tree_node *idx2=NULL, *tmp2=NULL;
            pico_hole_t *hole2 = NULL;
            uint32_t empty=1;

            frag_dbg("[LUM:%s:%d] printing hole tree for fragment:%p id:0x%X fragment->holes:%p\n",__FILE__,__LINE__,fragment,fragment->frag_id,fragment->holes);
            pico_tree_foreach_safe(idx2, &fragment->holes, tmp2)
            {
                hole2 = idx2->keyValue;
                empty=0;

                frag_dbg("[LUM:%s:%d] first:%d last:%d \n",__FILE__,__LINE__,hole2?hole2->first:0,hole2?hole2->last:0);
            }
            frag_dbg("[LUM:%s:%d] %s \n",__FILE__,__LINE__,empty?"empty":"done");
        }
#endif

        /*RFC 815 step 8*/
        if(pico_tree_empty(&fragment->holes))
        {
            /* now send the reassembled packet upstream*/

#ifdef IPFRAG_DEBUG
            /*complete packet arrived: send full frame*/
            frag_dbg("[LUM:%s:%d] content of reassembled packet:  %p net_len:%d transport_len:%d\n",__FILE__,__LINE__,full->buffer,full->net_len,full->transport_len);
            if(1)
            {
				int i;
				int s=full->net_len + PICO_SIZE_ETHHDR;

				frag_dbg("-----------------------------\n");
				frag_dbg("ETH hdr: \n");
				for(i=0;i < PICO_SIZE_ETHHDR;i=i+7)
				{
					frag_dbg("0x%04X: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n",i,
						full->buffer[i+0],full->buffer[i+1],full->buffer[i+2],full->buffer[i+3],
						full->buffer[i+4],full->buffer[i+5],full->buffer[i+6]);
				}
				frag_dbg("-----------------------------\n");

				frag_dbg("NET hdr: \n");
				for(i=PICO_SIZE_ETHHDR;i < full->net_len + PICO_SIZE_ETHHDR;i=i+8)
				{
					frag_dbg("0x%04X: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X \n",i,
						full->buffer[i+0],full->buffer[i+1],full->buffer[i+2],full->buffer[i+3],
						full->buffer[i+4],full->buffer[i+5],full->buffer[i+6],full->buffer[i+7]);
				}
				frag_dbg("-----------------------------\n");
				frag_dbg("TRANSPORT hdr: \n");
				for(i=s;i < full->transport_len + s;i=i+8)
				{
					frag_dbg("0x%04X: 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X \n",i,
						full->buffer[i+0],full->buffer[i+1],full->buffer[i+2],full->buffer[i+3],
						full->buffer[i+4],full->buffer[i+5],full->buffer[i+6],full->buffer[i+7]);
				}
				frag_dbg("-----------------------------\n");
			}
#endif
            full=NULL;

            retval = PICO_IP_LAST_FRAG_RECV; // this was the last packet
        }

    }

    return retval;
}
