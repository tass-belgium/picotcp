/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Ludo Mondelaers
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

/*** macros ***/

#define PICO_IP_FRAG_TIMEOUT 60000

#ifdef IPFRAG_DEBUG
#  define frag_dbg  dbg
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
}pico_fragment_t;

typedef     struct
{
    uint16_t first;
    uint16_t last;
}pico_hole_t;

/***  Prototypes ***/

static int fragments_compare(void *fa, void *fb);   /*pico_fragment_t*/
static int hole_compare(void *a, void *b);          /*pico_hole_t*/
// alloc and free of fragment tree
static pico_fragment_t *pico_fragment_alloc( uint16_t iphdrsize, uint16_t bufsize);
static pico_fragment_t *pico_fragment_free(pico_fragment_t * fragment);

static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame, uint16_t byte_offset, uint16_t more_flag );
// alloc and free for the hole tree
static pico_hole_t* pico_hole_free(pico_hole_t *hole);
static pico_hole_t* pico_hole_alloc(uint16_t first,uint16_t last);

/*** static declarations ***/
//static     PICO_TREE_DECLARE(ip_fragments, fragments_compare);
static     struct pico_tree    pico_fragments = { &LEAF, fragments_compare};
// our timer: allocoate one instance
static struct pico_timer*      pico_fragment_timer = NULL;



/*** global function called from pico_ipv6.c ***/

#ifdef PICO_SUPPORT_IPV6
// byte offset and more flag from exthdr (RFC2460)
#define IP6FRAG_OFF(frag)  ((frag & 0xFFF8))
#define IP6FRAG_MORE(frag) ((frag & 0x0001))

#define IP6FRAG_ID(exthdr) ((uint32_t)((exthdr->ext.frag.id[0] << 24)   |   \
                                       (exthdr->ext.frag.id[1] << 16)   |   \
                                       (exthdr->ext.frag.id[2] << 8)    |   \
                                        exthdr->ext.frag.id[3]))



static void copy_ipv6_exthdr_nofrag(struct pico_frame* dst, struct pico_frame* src)
{
    int done = 0;
    struct pico_ipv6_hdr *srchdr = (struct pico_ipv6_hdr *)src->net_hdr;
    struct pico_ipv6_hdr *dsthdr = (struct pico_ipv6_hdr *)dst->net_hdr;
    int srcidx = 0;
    int dstidx = 0;
    uint8_t nxthdr = srchdr->nxthdr;
    // parse ext hdrs
    while(!done)
    {
        switch(nxthdr)
        {
        case PICO_IPV6_EXTHDR_DESTOPT:
        case PICO_IPV6_EXTHDR_ROUTING:
        case PICO_IPV6_EXTHDR_HOPBYHOP:
        case PICO_IPV6_EXTHDR_ESP:
        case PICO_IPV6_EXTHDR_AUTH:
        {
            uint8_t len = (uint8_t)(srchdr->extensions[srcidx+1] << 3); 
            memcpy(&dsthdr->extensions[dstidx],&srchdr->extensions[srcidx],(size_t)len);
            srcidx += len;
            dstidx += len;
        }
        break;
        case PICO_IPV6_EXTHDR_FRAG: 
            srcidx += 8;            // remove frag field from dsthdr
        break;
        case PICO_IPV6_EXTHDR_NONE:
        case PICO_PROTO_TCP:
        case PICO_PROTO_UDP:
        case PICO_PROTO_ICMP6:
            done=1;
        break;
        default:
        /* Invalid next header */
            pico_icmp6_parameter_problem(src, PICO_ICMP6_PARAMPROB_NXTHDR, (uint32_t)nxthdr);
            done=1;
        }
        nxthdr = srchdr->extensions[srcidx];   // advance pointer
    }
    dst->payload = &dsthdr->extensions[dstidx];  
    dst->transport_hdr = dst->payload;
}


extern void pico_ipv6_process_frag(struct pico_ipv6_exthdr *exthdr, struct pico_frame *f, uint8_t proto /* see pico_addressing.h */)
{
    int retval = 0;
    if(exthdr && f)
    {
        // does the fragment already has its fragment tree?
        pico_fragment_t key;
        pico_fragment_t *fragment = NULL;

        memset(&key,0,sizeof(pico_fragment_t));
        key.frag_id = IP6FRAG_ID(exthdr);
        key.proto = proto;
        
        fragment = pico_tree_findKey( &pico_fragments,  &key); 
        if(!fragment)  // this is a new frag_id
        {
            // allocate fragment tree
            fragment = pico_fragment_alloc( PICO_SIZE_IP6HDR, /*2**/PICO_IPV6_MIN_MTU + 64 /*max lenght of options RFC815*/);
            if(fragment)
            {
                
                if(IP6FRAG_OFF(f->frag) == 0)  // offset is 0
                {
                    // if first frame: copy options  see RFC815
                    //fragment->start_payload = PICO_SIZE_IP6HDR;
                }
                else  
                {
                    //fragment is not the first fragment: assume no options, and add them later
                    //fragment->start_payload = PICO_SIZE_IP6HDR;
                }
                
                // copy ip hdr
                memcpy(fragment->frame->datalink_hdr,f->datalink_hdr,PICO_SIZE_ETHHDR + PICO_SIZE_IP6HDR);
                // copy ext hdr
                copy_ipv6_exthdr_nofrag(fragment->frame, f);   // copy exthdr except for frag option
                // copy payload
                memcpy(fragment->frame->transport_hdr,f->transport_hdr,f->transport_len);

                fragment->frag_id = IP6FRAG_ID(exthdr);
                fragment->proto = proto;
                {
                    struct pico_ipv6_hdr*ip6hdr=(struct pico_ipv6_hdr*)f->net_hdr;
                    fragment->src.ip6 = ip6hdr->src;
                    fragment->dst.ip6 = ip6hdr->dst;
                }
                
                fragment->holes.compare = hole_compare;
                fragment->holes.root = &LEAF; 
                
                pico_tree_insert(&pico_fragments, fragment);

            }
        }
        if(fragment)
        {
            retval = pico_fragment_arrived(fragment, f, IP6FRAG_OFF(f->frag), IP6FRAG_MORE(f->frag) ? 1 : 0 );
            if(retval < 1)
            {
                pico_frame_discard(f);
                f=NULL;
            }
        }
    }
}
#endif

#ifdef PICO_SUPPORT_IPV4


#define IP4FRAG_ID(hdr) (hdr->id)

// byte offset and more flag from iphdr (RFC791)
#define IP4FRAG_OFF(frag)  (((uint32_t)frag & PICO_IPV4_FRAG_MASK) << 3ul)
#define IP4FRAG_MORE(frag) (((uint32_t)frag & PICO_IPV4_MOREFRAG))


extern int pico_ipv4_process_frag(struct pico_ipv4_hdr *hdr, struct pico_frame *f, uint8_t proto /* see pico_addressing.h */)
{
    int retval = 0;
    if(hdr && f)
    {
        // does the fragment already has its fragment tree?
        pico_fragment_t key;
        pico_fragment_t *fragment = NULL;

        memset(&key,0,sizeof(pico_fragment_t));
        key.frag_id = short_be(IP4FRAG_ID(hdr));
        key.proto = proto;

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
            // allocate fragment tree
            fragment = pico_fragment_alloc( PICO_SIZE_IP4HDR, /*2**/PICO_IPV4_MTU + 64 /*max length of options*/);
            if(fragment)
            {
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
                //TODO: copy ext + clear frag options
                memcpy(fragment->frame->datalink_hdr,f->datalink_hdr,PICO_SIZE_ETHHDR + PICO_SIZE_IP4HDR);

                fragment->frag_id = key.frag_id;
                fragment->frame->frag = 0;  // remove frag options
                fragment->frame->proto = proto;
                
                fragment->proto = proto;
                {
                    struct pico_ipv4_hdr*ip4hdr=(struct pico_ipv4_hdr*)f->net_hdr;
                    fragment->src.ip4 = ip4hdr->src;
                    fragment->dst.ip4 = ip4hdr->dst;
                }

                fragment->holes.compare = hole_compare;
                fragment->holes.root = &LEAF; 
                
                pico_tree_insert(&pico_fragments, fragment);
            }
        }
        if(fragment)
        {
            //  hdr is stored in network order !!! oh crap
            uint16_t offset = IP4FRAG_OFF(short_be(hdr->frag));
            uint16_t more   = IP4FRAG_MORE(short_be(hdr->frag)) ? 1 : 0;

            retval = pico_fragment_arrived(fragment, f, offset, more);
            if(retval < 1)  // the original frame is re-used when retval ==1 , so dont discard here
            {
                pico_frame_discard(f);
                f=NULL;
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
    if(fa && fb)
    {                                                             // sort on dest addr, source addr
        return  (fa->frag_id > fb->frag_id)     ?  1 :        // fragid
                (fa->frag_id < fb->frag_id)     ? -1 : 
                (fa->proto   > fb->proto)       ?  1 :        // and protocol
                (fa->proto   < fb->proto)       ? -1 :
                0;
    }
    else
    {
        return 0;
    }
}




static pico_fragment_t *pico_fragment_alloc( uint16_t iphdrsize, uint16_t bufsize )  // size = exthdr + payload (MTU)
{
    pico_fragment_t* fragment = PICO_ZALLOC(sizeof(pico_fragment_t) );

    if(fragment)
    {
        struct pico_frame* frame  = pico_frame_alloc(/*exthdr_size +*/ bufsize + iphdrsize + (uint32_t)PICO_SIZE_ETHHDR);
        
        if(frame)
        {
            frame->datalink_hdr = frame->buffer;
            frame->net_hdr = frame->buffer + PICO_SIZE_ETHHDR;
            frame->net_len = iphdrsize;
            frame->transport_hdr = frame->net_hdr + iphdrsize;
            frame->transport_len = bufsize;
            frame->len =  (uint32_t)(bufsize + iphdrsize);

            fragment->frame = frame;
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
        return  (ha->first > hb->first)     ?  1 : 
                (ha->first < hb->first)     ? -1 :
                0;
    }
    else
    {
        return 0;
    }
}


static pico_hole_t* pico_hole_alloc(uint16_t first,uint16_t last)
{
    pico_hole_t* hole = PICO_ZALLOC(sizeof(pico_hole_t));
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


static void pico_ip_frag_expired(pico_time now, void *arg)
{
    pico_fragment_t * fragment=NULL;    
    struct pico_tree_node *idx=NULL;
    struct pico_tree_node *tmp=NULL;

    (void)arg;
    pico_fragment_timer = NULL;  // timer expired
    frag_dbg("[LUM:%s%d] inside pico_ip_frag_expired \n",__FILE__,__LINE__);
    
    pico_tree_foreach_safe(idx, &pico_fragments, tmp) 
    {
        fragment = idx->keyValue;
        if(fragment->expire < now)
        {
            frag_dbg("[%s:%d]//TODO notify ICMP \n", ,__FILE__,__LINE__);
            frag_dbg("[%s:%d] fragment expired:%p frag_id:0x%X \n",__FILE__,__LINE__,fragment, fragment->frag_id);
            
            pico_fragment_free(fragment);
            fragment=NULL;
        }
    }
    if(pico_tree_first(&pico_fragments))  // if first element exists
    {
        // once the timer is expired, it is removed from the queue
        // if there are still fragments in the tree, restart the timer
        pico_fragment_timer = pico_timer_add(1000, /*cleanup expired fragments every sec*/ pico_ip_frag_expired, NULL);
        frag_dbg("[LUM:%s:%d] added timer %p \n",__FILE__,__LINE__,pico_fragment_timer);
    }
}


#define INFINITY 55555 /* just a big number <16bits*/

// note: offset and more flag are located differently in ipv4(iphdr) and ipv6(exthdr)
// offset in expressed in octets (bytes) (not the 8 byte unit used in ip)

static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame, uint16_t offset, uint16_t more )
{
    struct pico_frame* full=NULL;

    if(fragment && frame)
    {
        pico_hole_t *first = pico_tree_first(&fragment->holes);
        if(!more &&  (offset == 0))
        {
            // no need for reassemble packet
            return 1;    // process orig packet
        }

        
        if(first == NULL)   /*first fragment of packet arrived*/
        {
            pico_hole_t *hole = pico_hole_alloc((uint16_t)0,(uint16_t)INFINITY);
            if(hole)
            {
                pico_tree_insert(&fragment->holes,hole);
            }
            if(pico_fragment_timer == NULL)
            {
                pico_fragment_timer = pico_timer_add(1000, /*cleanup expired fragments every sec*/ pico_ip_frag_expired, NULL);
            }
            fragment->expire = PICO_TIME_MS() + PICO_IP_FRAG_TIMEOUT;  // fragment expires when the packet is not complete after timeout
        }
        if(!more)    /*last fragment of packet arrived*/
        {
            // retrieve the size of the reassembled packet
            pico_hole_t* hole = pico_tree_last(&fragment->holes);
            if(hole /*&& IS_LEAF(hole)*/)
            {
                hole->last = (uint16_t)(offset + frame->transport_len);
                frag_dbg("[LUM:%s:%d] reassembled packet size:%d \n",__FILE__,__LINE__,hole->last);
                
                if(hole->first == hole->last)
                {
                    pico_tree_delete(&fragment->holes,hole);    // all done!
                }
            }
        }


        // copy the received frame into the reassembled packet
        frag_dbg("[LUM:%s:%d] offset:%d frame->transport_len:%d fragment->frame->buffer_len:%d\n",__FILE__,__LINE__,offset,frame->transport_len,fragment->frame->buffer_len);
        if( (offset + frame->transport_len) < fragment->frame->buffer_len ) // check for buffer space 
        {

            if(fragment->frame->transport_hdr && frame->transport_hdr)
            {
                frag_dbg("[LUM:%s:%d]  Reassemble packet:      fragment:%p fragment->frame:%p fragment->frame->transport_hdr:%p frame:%p frame->transport_hdr:%p frame->transport_len:%d\n",
                            __FILE__,__LINE__, fragment,   fragment->frame,   fragment->frame->transport_hdr,   frame,   frame->transport_hdr,   frame->transport_len);
                memcpy(fragment->frame->transport_hdr + offset , frame->transport_hdr, frame->transport_len);
            }
            else
            {
                // notify icmp
                pico_fragment_free(fragment);
                fragment=NULL;
            }
        }
        else
        {
            // frame->buffer is too small
            // allocate new frame and copy all
            uint32_t alloc_len= frame->buffer_len > fragment->frame->buffer_len ? 2*frame->buffer_len : 2*fragment->frame->buffer_len ;
            struct pico_frame* newframe = pico_frame_alloc( alloc_len); // make it twice as big
            struct pico_frame* oldframe = NULL;

            frag_dbg("[LUM:%s:%d] frame->buffer is too small realloc'd:%p\n",__FILE__,__LINE__,newframe);
            
            // copy hdrs + options + data
            if(newframe)
            {
                memcpy(newframe->buffer,fragment->frame->buffer,fragment->frame->buffer_len);
                oldframe = fragment->frame;
                fragment->frame = newframe;
                pico_frame_discard(oldframe);
                newframe=NULL;
                oldframe=NULL;
            }
            else
            {
                // discard packet: no more memory
                pico_fragment_free(fragment);
                // notify icmp
            }
        }
    }
    // do the administration of the missing holes
    if(fragment && (full=fragment->frame))
    {
        struct pico_tree_node *idx=NULL, *tmp=NULL;
        pico_hole_t *hole = NULL;
        uint16_t    frame_first = offset; 
        uint16_t    frame_last  = frame_first + frame->transport_len; 
        

        frag_dbg("[LUM:%s:%d] frame_first:%d frame->frag:0x%X\n",__FILE__,__LINE__,frame_first,frame->frag);
        frag_dbg("[LUM:%s:%d] frame_last:%d frame->transport_len:%d \n",__FILE__,__LINE__,frame_last,frame->transport_len);

        /*RFC 815 step 1*/
        //pico_tree_foreach_safe(index, &fragment->holes, hole) 
        pico_tree_foreach_safe(idx, &fragment->holes, tmp) 
        {
            hole = idx->keyValue;
            /*RFC 815 step 2*/
            if(frame_first > hole->last)
            {
                continue;
            }
            /*RFC 815 step 3*/
            if(frame_last < hole->first)
            {
                continue;
            }
            /*RFC 815 step 4*/
            pico_tree_delete(&fragment->holes, hole);
            /*RFC 815 step 5*/
            if(frame_first > hole->first)
            {
                pico_hole_t *new_hole =  pico_hole_alloc(hole->first,frame_first - 1u);
                if(new_hole)
                {
                    pico_tree_insert(&fragment->holes, new_hole);
                }
            }
            /*RFC 815 step 6*/
            if(frame_last < hole->last)
            {
                pico_hole_t *new_hole =  pico_hole_alloc(frame_last + 1u,hole->last);
                if(new_hole)
                {
                    pico_tree_insert(&fragment->holes, new_hole);
                }
            }
            /*RFC 815 step 7*/
            PICO_FREE(hole);
            hole=NULL;
        }    

        /*RFC 815 step 8*/
        if(pico_tree_empty(&fragment->holes))
        {
            /* now send the reassembled packet upstream*/
            // TODO calc crc of complete packet and send upstream 
            
            fragment->frame=NULL;
            
            /*complete packet arrived: send full frame*/
            pico_transport_receive(full, fragment->proto);
            full=NULL;
            
            // all done with this fragment: free it
            pico_fragment_free(fragment);
            fragment=NULL;
        }

#ifdef IPFRAG_DEBUG
        if(fragment)
        {
            frag_dbg("[LUM:%s:%d] printing hole tree for fragment:%p id:0x%X\n",__FILE__,__LINE__,fragment,fragment->frag_id);
            pico_tree_foreach_safe(idx, &fragment->holes, tmp) 
            {
                hole = idx->keyValue;

                frag_dbg("[LUM:%s:%d] first:%d last:%d \n",__FILE__,__LINE__,hole?hole->first:0,hole?hole->last:0);
            }
            frag_dbg("[LUM:%s:%d] done \n",__FILE__,__LINE__);
        }
#endif
    }
    return 0;
}



