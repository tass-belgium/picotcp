/*********************************************************************
   PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
   See LICENSE and COPYING for usage.

   This module handles the equalities between the IGMP and the MLD protocol
   Authors: Roel Postelmans
 *********************************************************************/

#include "pico_stack.h"
#include "pico_ipv6.h"
#include "pico_mld.h"
#include "pico_config.h"
#include "pico_eth.h"
#include "pico_addressing.h"
#include "pico_frame.h"
#include "pico_tree.h"
#include "pico_device.h"
#include "pico_socket.h"
#include "pico_icmp6.h"
#include "pico_dns_client.h"
#include "pico_mld.h"
#include "pico_igmp.h"
#include "pico_constants.h"
#include "pico_mcast.h"

#if ((defined(PICO_SUPPORT_MLD) && defined(PICO_SUPPORT_IPV6)) || (defined(PICO_SUPPORT_IGMP)) && defined(PICO_SUPPORT_MULTICAST)) 

#define multicast_dbg(...) do {} while(0)
 
#define MCAST_EVENT_DELETE_GROUP           (0x0)
#define MCAST_EVENT_CREATE_GROUP           (0x1)
#define MCAST_EVENT_UPDATE_GROUP           (0x2)
#define MCAST_EVENT_QUERY_RECV             (0x3)
#define MCAST_EVENT_REPORT_RECV            (0x4)
#define MCAST_EVENT_TIMER_EXPIRED          (0x5)

#define MCAST_MODE_IS_INCLUDE                  (1)
#define MCAST_MODE_IS_EXCLUDE                  (2)
#define MCAST_CHANGE_TO_INCLUDE_MODE           (3)
#define MCAST_CHANGE_TO_EXCLUDE_MODE           (4)

#define MCAST_MODE_IS_INCLUDE                  (1)
#define MCAST_MODE_IS_EXCLUDE                  (2)
#define MCAST_CHANGE_TO_INCLUDE_MODE           (3)
#define MCAST_CHANGE_TO_EXCLUDE_MODE           (4)
#define MCAST_ALLOW_NEW_SOURCES            (5)
#define MCAST_BLOCK_OLD_SOURCES            (6)


int pico_mcast_src_filtering_inc_inc(struct filter_parameters* mcast ) {
    struct pico_tree_node *index = NULL;
    union pico_address *source;
    /* all ADD_SOURCE_MEMBERSHIP had an equivalent DROP_SOURCE_MEMBERSHIP */
    if (mcast->p->event == MCAST_EVENT_DELETE_GROUP) {
        /* TO_IN (B) */
        mcast->record_type = MCAST_CHANGE_TO_INCLUDE_MODE;
        mcast->filter = mcast->allow;
        if (mcast->p->MCASTFilter) {
            pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
            {
                pico_tree_insert(mcast->allow, index->keyValue);
                mcast->sources++;
            }
        } /* else { allow stays empty } */
        return 0;
    }
    /* ALLOW (B-A) */
    /* if event is CREATE A will be empty, thus only ALLOW (B-A) has sense */
    if (mcast->p->event == MCAST_EVENT_CREATE_GROUP) /* first ADD_SOURCE_MEMBERSHIP */
        mcast->record_type = MCAST_CHANGE_TO_INCLUDE_MODE;
    else
        mcast->record_type = MCAST_ALLOW_NEW_SOURCES;
    mcast->filter = mcast->allow;
    pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
    {
        pico_tree_insert(mcast->allow, index->keyValue);
        mcast->sources++;
    }
    pico_tree_foreach(index, &mcast->g->MCASTSources) /* A */
    {
        source = pico_tree_findKey(mcast->allow, index->keyValue);
        if (source) {
            pico_tree_delete(mcast->allow, source);
            mcast->sources--;
        }
    }
    if (!pico_tree_empty(mcast->allow)) /* record type is ALLOW */
        return 0;

    /* BLOCK (A-B) */
    mcast->record_type = MCAST_BLOCK_OLD_SOURCES;
    mcast->filter = mcast->block;
    pico_tree_foreach(index, &mcast->g->MCASTSources) /* A */
    {
        pico_tree_insert(mcast->block, index->keyValue);
        mcast->sources++;
    }
    pico_tree_foreach(index, mcast->p->MCASTFilter) /* B */
    {
        source = pico_tree_findKey(mcast->block, index->keyValue);
        if (source) {
            pico_tree_delete(mcast->block, source);
            mcast->sources--;
        }
    }
    if (!pico_tree_empty(mcast->block)) /* record type is BLOCK */
        return 0;

    /* ALLOW (B-A) and BLOCK (A-B) are empty: do not send report  */
    (mcast->p)->f = NULL;
    return -1;
}




#if 0

            case PICO_IP_MULTICAST_EXCLUDE:
                /* TO_EX (B) */
                record_type = MLD_CHANGE_TO_EXCLUDE_MODE;
                MLDFilter = &MLDBlock;
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    pico_tree_insert(&MLDBlock, index->keyValue);
                    sources++;
                }
                break;
            default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            break;
        case PICO_IP_MULTICAST_EXCLUDE:
            switch (p->filter_mode) {
            case PICO_IP_MULTICAST_INCLUDE:
                /* TO_IN (B) */
                record_type = MLD_CHANGE_TO_INCLUDE_MODE;
                MLDFilter = &MLDAllow;
                if (p->MCASTFilter) {
                    pico_tree_foreach(index, p->MCASTFilter) /* B */
                    {
                        pico_tree_insert(&MLDAllow, index->keyValue);
                        sources++;
                    }
                } /* else { MLDAllow stays empty } */

                break;
            case PICO_IP_MULTICAST_EXCLUDE:
                /* BLOCK (B-A) */
                record_type = MLD_BLOCK_OLD_SOURCES;
                MLDFilter = &MLDBlock;
                pico_tree_foreach(index, p->MCASTFilter)
                {
                    pico_tree_insert(&MLDBlock, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, &g->MCASTSources) /* A */
                {
                    source = pico_tree_findKey(&MLDBlock, index->keyValue); /* B */
                    if (source) {
                    pico_tree_delete(&MLDBlock, source);
                    sources--;
                    }
                }
                if (!pico_tree_empty(&MLDBlock)) /* record type is BLOCK */
                    break;
                /* ALLOW (A-B) */
                record_type = MLD_ALLOW_NEW_SOURCES;
                MLDFilter = &MLDAllow;
                pico_tree_foreach(index, &g->MCASTSources)
                {
                    pico_tree_insert(&MLDAllow, index->keyValue);
                    sources++;
                }
                pico_tree_foreach(index, p->MCASTFilter) /* B */
                {
                    source = pico_tree_findKey(&MLDAllow, index->keyValue); /* A */
                    if (source) {
                        pico_tree_delete(&MLDAllow, source);
                        sources--;
                    }
                }
                if (!pico_tree_empty(&MLDAllow)) /* record type is ALLOW */
                    break;
                /* BLOCK (B-A) and ALLOW (A-B) are empty: do not send report  */
                p->f = NULL;
                return 0;  
           default:
                pico_err = PICO_ERR_EINVAL;
                return -1;
            }
            break;
        default:
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
mld2_report:
        /* RFC3810 $5.1.10 */
        if(sources > MLD_MAX_SOURCES) {
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
        len = (uint16_t)(sizeof(struct mldv2_report) + sizeof(struct mldv2_group_record) \
                         + (sources * sizeof(struct pico_ip6))+MLD_ROUTER_ALERT_LEN);
        
        p->f = pico_proto_ipv6.alloc(&pico_proto_ipv6, len);
        p->f->dev = pico_ipv6_link_find(&p->mcast_link);
        /* p->f->len is correctly set by alloc */
        
        hbh = (struct pico_ipv6_hbhoption *) p->f->transport_hdr;
        report = (struct mldv2_report *)(pico_mld_fill_hopbyhop(hbh));
        report->type = PICO_MLD_REPORTV2;
        report->res = 0;
        report->crc = 0;
        report->res1 = 0;
        report->nbr_gr = short_be(1);

        record = &report->record[0];
        record->type = record_type;
        record->aux = 0;
        record->nbr_src = short_be(sources);
        record->mcast_group = p->mcast_group;
        if (MLDFilter && !pico_tree_empty(MLDFilter)) {
            i = 0;
            pico_tree_foreach(index, MLDFilter)
            {
                record->src[i] = (*(struct pico_ip6 *)index->keyValue);
                i++;
            }
        }
        if(i != sources)
            return -1;
        //Checksum done in ipv6 module, no need to do it twice
        //report->crc= short_be(pico_mld_checksum(p->f));
        break;
    }   
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}
#endif
#endif
