/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Ludo Mondelaers
 *********************************************************************/


#ifdef PICO_SUPPORT_IPV6
#include "pico_ipv6.h"
#include "pico_icmp6.h"
#endif
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_eth.h"
#include "pico_udp.h"
#include "pico_tcp.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_tree.h"


/*** macros ***/

#define PICO_IP_FRAG_TIMEOUT 60000

#define IPFRAG_OFF(frag)  ((frag & 0xFFF8))
#define IPFRAG_MORE(frag) ((frag & 0x0001))


//PICO_IPV4_MTU

/*** Type definitions ***/

typedef struct 
{
    uint32_t            frag_id;
    /***
    union pico_address  src; 
    union pico_address  dst;
    ***/
    uint8_t            proto;

//    PICO_TREE_DECLARE(holes, hole_compare); // this macro contains an initialisation to a global variable: can not use it here 
    struct pico_tree    holes;
 
    uint32_t            start_payload;
    struct pico_frame * frame;
    struct pico_timer * expire;
}pico_fragment_t;

typedef     struct
{
    unsigned int first;
    unsigned int last;
}pico_hole_t;

/***  Prototypes ***/

static int fragments_compare(void *fa, void *fb);   /*pico_fragment_t*/
static int hole_compare(void *a, void *b);          /*pico_hole_t*/
// alloc and free of fragment tree
static pico_fragment_t *pico_fragment_alloc( uint32_t size);
static pico_fragment_t *pico_fragment_free(pico_fragment_t * fragment);

static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame );
// alloc and free for the hole tree
static pico_hole_t* pico_hole_free(pico_hole_t *hole);
static pico_hole_t* pico_hole_alloc(unsigned int first,unsigned int last);

/*** static declarations ***/
//static     PICO_TREE_DECLARE(ip_fragments, fragments_compare);
static     struct pico_tree    pico_fragments = { &LEAF, fragments_compare};





/*** global function called from pico_ipv6.c ***/

#ifdef PICO_SUPPORT_IPV6

#define IP6FRAG_ID(exthdr) ((uint32_t)((exthdr->ext.frag.id[0] << 24)   |   \
                                       (exthdr->ext.frag.id[1] << 16)   |   \
                                       (exthdr->ext.frag.id[2] << 8)    |   \
                                        exthdr->ext.frag.id[3]))

extern void pico_ipv6_process_frag(struct pico_ipv6_exthdr *exthdr, struct pico_frame *f, uint8_t proto /* see pico_addressing.h */)
{
    if(exthdr && f)
    {
        // does the fragment already has its fragment tree?
        pico_fragment_t key={0};
        pico_fragment_t *fragment = NULL;

        key.frag_id = IP6FRAG_ID(exthdr);
        key.proto = proto;
        
        fragment = pico_tree_findKey( &pico_fragments,  &key); 
        if(!fragment)  // this is a new frag_id
        {
            // allocate fragment tree
            fragment = pico_fragment_alloc( PICO_IPV6_MIN_MTU + 64 /*max lenght of options RFC815*/);
            if(fragment)
            {
                
                if(IPFRAG_OFF(f->frag) == 0)
                {
                    // if first frame: copy options  see RFC815
                    fragment->start_payload = PICO_SIZE_IP6HDR;
                }
                else  
                {
                    //fragment is not the first fragment: assume no options, and add them later
                    fragment->start_payload = PICO_SIZE_IP6HDR;
                }
                fragment->frag_id = IP6FRAG_ID(exthdr);
                fragment->proto = proto;
                
                
                fragment->holes.compare = hole_compare;
                fragment->holes.root = &LEAF; 
                
                pico_tree_insert(&pico_fragments, fragment);
            }
        }
        if(fragment)
        {
            pico_fragment_arrived(fragment, f);
            pico_frame_discard(f);
            f=NULL;
        }
    }
}
#endif

#ifdef PICO_SUPPORT_IPV4


#define IP4FRAG_ID(hdr) ((uint32_t)(short_be(hdr->id)))

extern int pico_ipv4_process_frag(struct pico_ipv4_hdr *hdr, struct pico_frame *f, uint8_t proto /* see pico_addressing.h */)
{
    int retval = 0;
    if(hdr && f)
    {
        // does the fragment already has its fragment tree?
        pico_fragment_t key={0};
        pico_fragment_t *fragment = NULL;

        key.frag_id = IP4FRAG_ID(hdr);
        key.proto = proto;

        fragment = pico_tree_findKey( &pico_fragments,  &key); 

printf("[LUM:%s:%d] Searching for frag_id:%d proto:%d: %s \n",__FILE__,__LINE__,key.frag_id,key.proto,fragment?"FOUND":"NOT FOUND");

        if(!fragment)  // this is a new frag_id
        {
            // allocate fragment tree
            fragment = pico_fragment_alloc( PICO_IPV4_MTU + 64 /*max length of options*/);
            if(fragment)
            {
                if(IPFRAG_OFF(f->frag) == 0)
                {
                    // if first frame: TODO copy options  see RFC815
                    fragment->start_payload = PICO_SIZE_IP4HDR;
                }
                else  
                {
                    //fragment is not the first fragment: assume no options, and add them later
                    fragment->start_payload = PICO_SIZE_IP4HDR;
                }
                fragment->frag_id = IP4FRAG_ID(hdr);
                fragment->proto = proto;
                
                fragment->holes.compare = hole_compare;
                fragment->holes.root = &LEAF; 
                
                pico_tree_insert(&pico_fragments, fragment);
            }
        }
        if(fragment)
        {
#if 0   // moved to pico_fragment_arrived         
            uint32_t offset = IPFRAG_OFF(f->frag);
            uint32_t more = IPFRAG_MORE(f->frag);
            uint32_t payload_offset = fragment->start_payload + offset;

            if(f->buffer_len  > (payload_offset+f->transport_len))
            {
                
                memcpy(fragment->frame->transport_hdr + payload_offset, f->transport_hdr, f->transport_len);
            }
            else
            {
                // frame->buffer is too small
                // allocate new frame and copy all
            }
            if(!more)
            {
                // retrieve the size of the reassembled packet
                pico_hole_t* hole = pico_tree_last(fragment->holes);
                if(hole)
                {
                    pico_tree_delete(fragment->holes,hole);
                    hole->last=offset + f->transport_len;
                    if(hole->first != hole->last)
                    {
                        pico_tree_insert(fragment->holes,hole);
                    }
                }
            }
#endif            
            pico_fragment_arrived(fragment, f);
            pico_frame_discard(f);
            f=NULL;
        }
    }
printf("[LUM:%s:%d] \n",__FILE__,__LINE__);
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




static pico_fragment_t *pico_fragment_alloc(/*uint32_t frag_id,*/ uint32_t size )  // size = exthdr + payload (MTU)
{
//    uint32_t iphdrsize = (iphdr_type == iphdr_ipv6) ? PICO_SIZE_IP6HDR : PICO_SIZE_IP4HDR;
    pico_fragment_t* fragment = PICO_ZALLOC(sizeof(pico_fragment_t) );

    if(fragment)
    {
        //fragment->frag_id   = frag_id;
        //proto
        //src
        //dst
        struct pico_frame* frame     = pico_frame_alloc(/*exthdr_size +*/ size + PICO_SIZE_IP4HDR + PICO_SIZE_ETHHDR);
        
        if(frame)
        {

            frame->datalink_hdr = frame->buffer;
            frame->net_hdr = frame->buffer + PICO_SIZE_ETHHDR;
            frame->net_len = PICO_SIZE_IP4HDR;
            frame->transport_hdr = frame->net_hdr + PICO_SIZE_IP4HDR;
            frame->transport_len = (uint16_t)size;
            frame->len =  size + PICO_SIZE_IP4HDR;

            fragment->frame = frame;
        }
    }
    return fragment;   
}


static pico_fragment_t *pico_fragment_free(pico_fragment_t * fragment)
{
    if(fragment)
    {
        struct pico_tree_node *index=NULL;
        struct pico_tree_node *tmp=NULL;
        
        /* cancel timer */
        if(fragment->expire)
        {
            pico_timer_cancel(fragment->expire);
            fragment->expire = NULL;
        }
        
        /*empty hole tree*/
        pico_tree_foreach_safe(index, &fragment->holes, tmp) 
        {
            pico_hole_t *hole = index->keyValue;
            
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
        return  (ha->first > hb->first)     ? 1 : 
                (ha->first == hb->first)    ? 0 :
                -1;
    }
    else
    {
        return 0;
    }
}


static pico_hole_t* pico_hole_alloc(unsigned int first,unsigned int last)
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
    (void)now;
    
    // notify ICMP
    
    pico_fragment_free((pico_fragment_t *) arg);
}


#define INFINITY 999999 /* just a big number*/


static int pico_fragment_arrived(pico_fragment_t* fragment, struct pico_frame* frame /*, ipv, len*/)
{
    if(fragment && frame)
    {
        pico_hole_t *first = pico_tree_first(&fragment->holes);
        struct pico_frame* full=NULL;
        
        uint32_t offset = IPFRAG_OFF(frame->frag);
        uint32_t more =   IPFRAG_MORE(frame->frag);
        uint32_t payload_offset = fragment->start_payload + offset;

        if(frame->buffer_len  > (payload_offset + frame->transport_len))
        {
printf("[LUM:%s:%d]  Reassemble packet:      fragment:%p fragment->frame:%p fragment->frame->transport_hdr:%p frame:%p frame->transport_hdr:%p frame->transport_len:%d\n",
        __FILE__,__LINE__, fragment,   fragment->frame,   fragment->frame->transport_hdr,   frame,   frame->transport_hdr,   frame->transport_len);
            
            memcpy(fragment->frame->transport_hdr + payload_offset, frame->transport_hdr, frame->transport_len);
        }
        else
        {
printf("[LUM:%s:%d] frame->buffer is too small\n",__FILE__,__LINE__);
            // frame->buffer is too small
            // allocate new frame and copy all
        }
        if(!more)
        {
            // retrieve the size of the reassembled packet
            pico_hole_t* hole = pico_tree_last(&fragment->holes);
            if(hole /*&& IS_LEAF(hole)*/)
            {
                pico_tree_delete(&fragment->holes,hole);
                hole->last=offset + frame->transport_len;
printf("[LUM:%s:%d] reassembled packet size:%d \n",__FILE__,__LINE__,hole->last);
                if(hole->first != hole->last)
                {
                    pico_tree_insert(&fragment->holes,hole);
                }
            }
        }
        
        if(first == NULL)   /*first fragment of packet arrived*/
        {
            pico_hole_t *hole = pico_hole_alloc(0,INFINITY);
            if(hole)
            {
printf("[LUM:%s:%d] first fragment of packet arrived \n",__FILE__,__LINE__);
                pico_tree_insert(&fragment->holes,hole);
            }
        }
        
        full= fragment->frame;   // the full frame 
        if(full)
        {
            struct pico_tree_node *index=NULL, *tmp=NULL;
            pico_hole_t *hole = NULL;
            uint32_t    frame_first = IPFRAG_OFF(frame->frag); 
            uint32_t    frame_last  = frame_first + frame->transport_len; 
            
//            full->net_hdr = full->buffer;
//            full->net_len = hdrlen;
            /*RFC 815 step 1*/
            //pico_tree_foreach_safe(index, &fragment->holes, hole) 
            pico_tree_foreach_safe(index, &fragment->holes, tmp) 
            {
                hole = index->keyValue;
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
                    pico_hole_t *new_hole =  pico_hole_alloc(hole->first,frame_first - 1);
                    if(new_hole)
                    {
                        pico_tree_insert(&fragment->holes, new_hole);
                    }
                }
                /*RFC 815 step 6*/
                if(frame_last < hole->last)
                {
                    pico_hole_t *new_hole =  pico_hole_alloc(frame_last +1,hole->last);
                    if(new_hole)
                    {
                        pico_tree_insert(&fragment->holes, new_hole);
                    }
                }
                /*RFC 815 step 7*/
                PICO_FREE(hole);
                hole=NULL;
            }    
            //if (fragment->expire)  // cancel the timer
            //{
            //    pico_timer_cancel(fragment->expire);
            //    fragment->expire = NULL;
            //}
            /*RFC 815 step 8*/
            if(pico_tree_empty(&fragment->holes))
            {
                /*complete packet arrived: send full frame*/
                pico_transport_receive(full, fragment->proto);
            }
            else
            {
                if (fragment->expire == NULL)
                {
                    fragment->expire = pico_timer_add(PICO_IP_FRAG_TIMEOUT, pico_ip_frag_expired, fragment);
                }
            }
        }
    }
    return 0;
}



