#include <stdint.h>
#include "pico_socket.h"
#include "pico_socket_multicast.h"
#include "pico_tree.h"
#include "pico_ipv4.h"
#include "pico_udp.h"

#ifdef PICO_SUPPORT_MCAST
# define so_mcast_dbg(...) do {} while(0) /* ip_mcast_dbg in pico_ipv4.c */

/*                       socket
 *                         |
 *                    MCASTListen
 *                    |    |     |
 *         ------------    |     ------------
 *         |               |                |
 *   MCASTSources    MCASTSources     MCASTSources
 *   |  |  |  |      |  |  |  |       |  |  |  |
 *   S  S  S  S      S  S  S  S       S  S  S  S
 *
 *   MCASTListen: RBTree(mcast_link, mcast_group)
 *   MCASTSources: RBTree(source)
 */
struct pico_mcast_listen
{
    uint8_t filter_mode;
    struct pico_ip4 mcast_link;
    struct pico_ip4 mcast_group;
    struct pico_tree MCASTSources;
};

static int mcast_listen_link_cmp(struct pico_mcast_listen *a, struct pico_mcast_listen *b)
{
    if (a->mcast_link.addr < b->mcast_link.addr)
        return -1;

    if (a->mcast_link.addr > b->mcast_link.addr)
        return 1;

    return 0;
}

static int mcast_listen_cmp(void *ka, void *kb)
{
    struct pico_mcast_listen *a = ka, *b = kb;
    if (a->mcast_group.addr < b->mcast_group.addr)
        return -1;

    if (a->mcast_group.addr > b->mcast_group.addr)
        return 1;

    return mcast_listen_link_cmp(a, b);

}

static int mcast_sources_cmp(void *ka, void *kb)
{
    struct pico_ip4 *a = ka, *b = kb;
    if (a->addr < b->addr)
        return -1;

    if (a->addr > b->addr)
        return 1;

    return 0;
}

static int mcast_socket_cmp(void *ka, void *kb)
{
    struct pico_socket *a = ka, *b = kb;
    if (a < b)
        return -1;

    if (a > b)
        return 1;

    return 0;
}
/* gather all multicast sockets to hasten filter aggregation */
PICO_TREE_DECLARE(MCASTSockets, mcast_socket_cmp);

static int mcast_filter_cmp(void *ka, void *kb)
{
    struct pico_ip4 *a = ka, *b = kb;
    if (a->addr < b->addr)
        return -1;

    if (a->addr > b->addr)
        return 1;

    return 0;
}
/* gather sources to be filtered */
PICO_TREE_DECLARE(MCASTFilter, mcast_filter_cmp);

static struct pico_mcast_listen *listen_find(struct pico_socket *s, struct pico_ip4 *lnk, struct pico_ip4 *grp)
{
    struct pico_mcast_listen ltest = {
        0
    };
    ltest.mcast_link.addr = lnk->addr;
    ltest.mcast_group.addr = grp->addr;
    return pico_tree_findKey(s->MCASTListen, &ltest);
}

/* MCASTFilter will be empty if no socket is listening on mcast_group on mcast_link anymore */
static int pico_socket_aggregate_mcastfilters(struct pico_ip4 *mcast_link, struct pico_ip4 *mcast_group)
{
    uint8_t filter_mode = PICO_IP_MULTICAST_INCLUDE;
    struct pico_mcast_listen *listen = NULL;
    struct pico_ip4 *source = NULL;
    struct pico_socket *mcast_sock = NULL;
    struct pico_tree_node *index = NULL, *_tmp = NULL, *index2 = NULL, *_tmp2 = NULL;


    /* cleanup old filter */
    pico_tree_foreach_safe(index, &MCASTFilter, _tmp)
    {
        pico_tree_delete(&MCASTFilter, index->keyValue);
    }

    /* construct new filter */
    pico_tree_foreach(index, &MCASTSockets)
    {
        mcast_sock = index->keyValue;
        listen = listen_find(mcast_sock, mcast_link, mcast_group);
        if (listen) {
            /* aggregate filter */
            switch(filter_mode)
            {
            case PICO_IP_MULTICAST_INCLUDE:
                switch (listen->filter_mode)
                {
                case PICO_IP_MULTICAST_INCLUDE:
                    /* filter = summation of INCLUDEs */
                    /* mode stays INCLUDE, add all sources to filter */
                    pico_tree_foreach(index2, &listen->MCASTSources)
                    {
                        source = index2->keyValue;
                        pico_tree_insert(&MCASTFilter, source);
                    }
                    break;

                case PICO_IP_MULTICAST_EXCLUDE:
                    /* filter = EXCLUDE - INCLUDE */
                    /* delete from the interface INCLUDE filter any source NOT in the socket EXCLUDE filter */
                    pico_tree_foreach_safe(index2, &MCASTFilter, _tmp2)
                    {
                        source = pico_tree_findKey(&listen->MCASTSources, index2->keyValue);
                        if (!source)
                            pico_tree_delete(&MCASTFilter, index2->keyValue);
                    }
                    /* any record with filter mode EXCLUDE, causes the interface mode to be EXCLUDE */
                    filter_mode = PICO_IP_MULTICAST_EXCLUDE;
                    /* add to the interface EXCLUDE filter any socket source NOT in the former interface INCLUDE filter */
                    pico_tree_foreach(index2, &listen->MCASTSources)
                    {
                        source = pico_tree_insert(&MCASTFilter, index2->keyValue);
                        if (source)
                            pico_tree_delete(&MCASTFilter, source);
                    }
                    break;

                default:
                    return -1;
                }
                break;

            case PICO_IP_MULTICAST_EXCLUDE:
                switch (listen->filter_mode)
                {
                case PICO_IP_MULTICAST_INCLUDE:
                    /* filter = EXCLUDE - INCLUDE */
                    /* any record with filter mode EXCLUDE, causes the interface mode to be EXCLUDE */
                    /* remove from the interface EXCLUDE filter any source in the socket INCLUDE filter */
                    pico_tree_foreach(index2, &listen->MCASTSources)
                    {
                        source = pico_tree_findKey(&MCASTFilter, index2->keyValue);
                        if (source)
                            pico_tree_delete(&MCASTFilter, source);
                    }
                    break;

                case PICO_IP_MULTICAST_EXCLUDE:
                    /* filter = intersection of EXCLUDEs */
                    /* any record with filter mode EXCLUDE, causes the interface mode to be EXCLUDE */
                    /* remove from the interface EXCLUDE filter any source not in the socket EXCLUDE filter */
                    pico_tree_foreach_safe(index2, &MCASTFilter, _tmp2)
                    {
                        source = pico_tree_findKey(&listen->MCASTSources, index2->keyValue);
                        if (!source)
                            pico_tree_delete(&MCASTFilter, index2->keyValue);
                    }
                    break;

                default:
                    return -1;
                }
                break;

            default:
                return -1;
            }
        }
    }
    return filter_mode;
}

static int pico_socket_mcast_filter_include(struct pico_mcast_listen *listen, struct pico_ip4 *src)
{
    struct pico_tree_node *index = NULL;
    pico_tree_foreach(index, &listen->MCASTSources)
    {
        if (src->addr == ((struct pico_ip4 *)index->keyValue)->addr) {
            so_mcast_dbg("MCAST: IP %08X in included socket source list\n", src->addr);
            return 0;
        }
    }
    so_mcast_dbg("MCAST: IP %08X NOT in included socket source list\n", src->addr);
    return -1;

}

static int pico_socket_mcast_filter_exclude(struct pico_mcast_listen *listen, struct pico_ip4 *src)
{
    struct pico_tree_node *index = NULL;
    pico_tree_foreach(index, &listen->MCASTSources)
    {
        if (src->addr == ((struct pico_ip4 *)index->keyValue)->addr) {
            so_mcast_dbg("MCAST: IP %08X in excluded socket source list\n", src->addr);
            return -1;
        }
    }
    so_mcast_dbg("MCAST: IP %08X NOT in excluded socket source list\n", src->addr);
    return 0;
}

static int pico_socket_mcast_source_filtering(struct pico_mcast_listen *listen, struct pico_ip4 *src)
{
    /* perform source filtering */
    if (listen->filter_mode == PICO_IP_MULTICAST_INCLUDE)
        return pico_socket_mcast_filter_include(listen, src);
    if (listen->filter_mode == PICO_IP_MULTICAST_EXCLUDE)
        return pico_socket_mcast_filter_exclude(listen, src);
    return -1;
}

static struct pico_ipv4_link *pico_socket_mcast_filter_link_get(struct pico_socket *s)
{
    /* check if no multicast enabled on socket */
    if (!s->MCASTListen)
        return NULL;
    return pico_ipv4_link_get(&s->local_addr.ip4);
}

int pico_socket_mcast_filter(struct pico_socket *s, struct pico_ip4 *mcast_group, struct pico_ip4 *src)
{
    struct pico_ipv4_link *mcast_link = NULL;
    struct pico_mcast_listen *listen = NULL;

    mcast_link = pico_socket_mcast_filter_link_get(s);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mcast_link->address, mcast_group);
    if (!listen)
        return -1;

    return pico_socket_mcast_source_filtering(listen, src);

}

static struct pico_ipv4_link *mcast_link(struct pico_ip4 *a)
{
    if (!a->addr)
        return pico_ipv4_get_default_mcastlink();

    return pico_ipv4_link_get(a);
}


static int pico_socket_setoption_pre_validation(struct pico_ip_mreq *mreq)
{
    if (!mreq)
        return -1;
    if (!mreq->mcast_group_addr.addr)
        return -1;
    return 0;
}

static struct pico_ipv4_link *pico_socket_setoption_validate_mreq(struct pico_ip_mreq *mreq)
{
    if (pico_socket_setoption_pre_validation(mreq) < 0)
        return NULL;

    if (pico_ipv4_is_unicast(mreq->mcast_group_addr.addr))
        return NULL;

    return mcast_link(&mreq->mcast_link_addr);
}

static int pico_socket_setoption_pre_validation_s(struct pico_ip_mreq_source *mreq)
{
    if (!mreq)
        return -1;
    if (!mreq->mcast_group_addr.addr)
        return -1;
    return 0;
}

static struct pico_ipv4_link *pico_socket_setoption_validate_s_mreq(struct pico_ip_mreq_source *mreq)
{
    if (pico_socket_setoption_pre_validation_s(mreq) < 0)
        return NULL;
    if (pico_ipv4_is_unicast(mreq->mcast_group_addr.addr))
        return NULL;
    if (!pico_ipv4_is_unicast(mreq->mcast_source_addr.addr))
        return NULL;
    return mcast_link(&mreq->mcast_link_addr);
}


static struct pico_ipv4_link *setop_multicast_link_search(void *value, int bysource)
{

    struct pico_ip_mreq *mreq = NULL;
    struct pico_ipv4_link *mcast_link = NULL;
    struct pico_ip_mreq_source *mreq_src = NULL;
    if (!bysource) {
        mreq = (struct pico_ip_mreq *) value;
        mcast_link = pico_socket_setoption_validate_mreq(mreq);
        if (!mcast_link)
            return NULL;
        if (!mreq->mcast_link_addr.addr)
            mreq->mcast_link_addr.addr = mcast_link->address.addr;
    } else {
        mreq_src = (struct pico_ip_mreq_source *) value;
        mcast_link = pico_socket_setoption_validate_s_mreq(mreq_src);
        if (!mreq_src->mcast_link_addr.addr)
            mreq_src->mcast_link_addr.addr = mcast_link->address.addr;
    }
    return mcast_link;
} 

static int setop_verify_listen_tree(struct pico_socket *s, int alloc)
{
    if(!alloc)
        return -1;
    s->MCASTListen = pico_zalloc(sizeof(struct pico_tree));
    if (!s->MCASTListen) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    s->MCASTListen->root = &LEAF;
    s->MCASTListen->compare = mcast_listen_cmp;
    return 0;
}


static struct pico_ipv4_link *setopt_multicast_check(struct pico_socket *s, void *value, int alloc, int bysource)
{
    struct pico_ipv4_link *mcast_link = NULL;

    if (!value) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }
    mcast_link = setop_multicast_link_search(value, bysource);

    if (!mcast_link) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (!s->MCASTListen) { /* No RBTree allocated yet */
        if (setop_verify_listen_tree(s, alloc) < 0)
            return NULL;
    }
    return mcast_link;
}


void pico_multicast_delete(struct pico_socket *s)
{
    int filter_mode;
    struct pico_tree_node *index = NULL, *_tmp = NULL, *index2 = NULL, *_tmp2 = NULL;
    struct pico_mcast_listen *listen = NULL;
    struct pico_ip4 *source = NULL;
    if (s->MCASTListen) {
        pico_tree_delete(&MCASTSockets, s);
        pico_tree_foreach_safe(index, s->MCASTListen, _tmp)
        {
            listen = index->keyValue;
            pico_tree_foreach_safe(index2, &listen->MCASTSources, _tmp2)
            {
                source = index->keyValue;
                pico_tree_delete(&listen->MCASTSources, source);
                pico_free(source);
            }
            filter_mode = pico_socket_aggregate_mcastfilters(&listen->mcast_link, &listen->mcast_group);
            if (filter_mode >= 0)
                pico_ipv4_mcast_leave(&listen->mcast_link, &listen->mcast_group, 1, (uint8_t)filter_mode, &MCASTFilter);

            pico_tree_delete(s->MCASTListen, listen);
            pico_free(listen);
        }
        pico_free(s->MCASTListen);
    }
}


int pico_getsockopt_mcast(struct pico_socket *s, int option, void *value)
{
    switch(option) {
    case PICO_IP_MULTICAST_IF:
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;

    case PICO_IP_MULTICAST_TTL:
        if (s->proto->proto_number == PICO_PROTO_UDP) {
            pico_udp_get_mc_ttl(s, (uint8_t *) value);
        } else {
            *(uint8_t *)value = 0;
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        break;

    case PICO_IP_MULTICAST_LOOP:
        if (s->proto->proto_number == PICO_PROTO_UDP) {
            *(uint8_t *)value = (uint8_t)PICO_SOCKET_GETOPT(s, PICO_SOCKET_OPT_MULTICAST_LOOP);
        } else {
            *(uint8_t *)value = 0;
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        break;
    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    return 0;
}

static int mcast_so_loop(struct pico_socket *s, void *value)
{
    uint8_t val = (*(uint8_t *)value);
    if (val == 0u) {
        PICO_SOCKET_SETOPT_DIS(s, PICO_SOCKET_OPT_MULTICAST_LOOP);
        return 0;
    } else if (val == 1u) {
        PICO_SOCKET_SETOPT_EN(s, PICO_SOCKET_OPT_MULTICAST_LOOP);
        return 0;
    }

    pico_err = PICO_ERR_EINVAL;
    return -1;
}

static int mcast_so_addm(struct pico_socket *s, void *value)
{
    int filter_mode;
    struct pico_mcast_listen *listen;
    struct pico_ip_mreq *mreq = (struct pico_ip_mreq *)value;
    struct pico_ipv4_link *mcast_link = setopt_multicast_check(s, value, 1, 0);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mreq->mcast_link_addr, &mreq->mcast_group_addr);
    if (listen) {
        if (listen->filter_mode != PICO_IP_MULTICAST_EXCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR any-source multicast (exclude) on source-specific multicast (include)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        } else {
            so_mcast_dbg("pico_socket_setoption: ERROR duplicate PICO_IP_ADD_MEMBERSHIP\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }
    } else {
        listen = pico_zalloc(sizeof(struct pico_mcast_listen));
        if (!listen) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        listen->filter_mode = PICO_IP_MULTICAST_EXCLUDE;
        listen->mcast_link = mreq->mcast_link_addr;
        listen->mcast_group = mreq->mcast_group_addr;
        listen->MCASTSources.root = &LEAF;
        listen->MCASTSources.compare = mcast_sources_cmp;
        pico_tree_insert(s->MCASTListen, listen);
    }

    pico_tree_insert(&MCASTSockets, s);
    filter_mode = pico_socket_aggregate_mcastfilters(&mcast_link->address, &mreq->mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    return pico_ipv4_mcast_join(&mreq->mcast_link_addr, &mreq->mcast_group_addr, 1, (uint8_t)filter_mode, &MCASTFilter);
}

static int mcast_so_dropm(struct pico_socket *s, void *value)
{
    int filter_mode = 0;
    struct pico_mcast_listen *listen;
    struct pico_ip_mreq *mreq = (struct pico_ip_mreq *)value;
    struct pico_ip4 *source = NULL;
    struct pico_tree_node *index, *_tmp;
    struct pico_ipv4_link *mcast_link = setopt_multicast_check(s, value, 0, 0);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mreq->mcast_link_addr, &mreq->mcast_group_addr);
    if (!listen) {
        so_mcast_dbg("pico_socket_setoption: ERROR PICO_IP_DROP_MEMBERSHIP before PICO_IP_ADD_MEMBERSHIP/SOURCE_MEMBERSHIP\n");
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
    } else {
        pico_tree_foreach_safe(index, &listen->MCASTSources, _tmp)
        {
            source = index->keyValue;
            pico_tree_delete(&listen->MCASTSources, source);
            pico_free(source);
        }
        pico_tree_delete(s->MCASTListen, listen);
        pico_free(listen);
        if (pico_tree_empty(s->MCASTListen)) {
            pico_free(s->MCASTListen);
            s->MCASTListen = NULL;
            pico_tree_delete(&MCASTSockets, s);
        }
    }

    filter_mode = pico_socket_aggregate_mcastfilters(&mcast_link->address, &mreq->mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    return pico_ipv4_mcast_leave(&mreq->mcast_link_addr, &mreq->mcast_group_addr, 1, (uint8_t)filter_mode, &MCASTFilter);
}

static int mcast_so_unblock_src(struct pico_socket *s, void *value)
{
    int filter_mode = 0;
    struct pico_ip_mreq_source *mreq = (struct pico_ip_mreq_source *)value;
    struct pico_mcast_listen *listen = NULL;
    struct pico_ip4 *source = NULL, stest = {
        0
    };
    struct pico_ipv4_link *mcast_link = setopt_multicast_check(s, value, 0, 1);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mreq->mcast_link_addr, &mreq->mcast_group_addr);
    if (!listen) {
        so_mcast_dbg("pico_socket_setoption: ERROR PICO_IP_UNBLOCK_SOURCE before PICO_IP_ADD_MEMBERSHIP\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (listen->filter_mode != PICO_IP_MULTICAST_EXCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR any-source multicast (exclude) on source-specific multicast (include)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        stest.addr = mreq->mcast_source_addr.addr;
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (!source) {
            so_mcast_dbg("pico_socket_setoption: ERROR address to unblock not in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            pico_tree_delete(&listen->MCASTSources, source);
            pico_free(source);
        }
    }

    filter_mode = pico_socket_aggregate_mcastfilters(&mcast_link->address, &mreq->mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    return pico_ipv4_mcast_leave(&mreq->mcast_link_addr, &mreq->mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
}


static int mcast_so_block_src(struct pico_socket *s, void *value)
{
    int filter_mode = 0;
    struct pico_ip_mreq_source *mreq = (struct pico_ip_mreq_source *)value;
    struct pico_mcast_listen *listen = NULL;
    struct pico_ip4 *source = NULL, stest = {
        0
    };
    struct pico_ipv4_link *mcast_link = setopt_multicast_check(s, value, 0, 1);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mreq->mcast_link_addr, &mreq->mcast_group_addr);
    if (!listen) {
        dbg("pico_socket_setoption: ERROR PICO_IP_BLOCK_SOURCE before PICO_IP_ADD_MEMBERSHIP\n");
        pico_err = PICO_ERR_EINVAL;
        return -1;
    } else {
        if (listen->filter_mode != PICO_IP_MULTICAST_EXCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR any-source multicast (exclude) on source-specific multicast (include)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        stest.addr = mreq->mcast_source_addr.addr;
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (source) {
            so_mcast_dbg("pico_socket_setoption: ERROR address to block already in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            source = pico_zalloc(sizeof(struct pico_ip4));
            if (!source) {
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }

            source->addr = mreq->mcast_source_addr.addr;
            pico_tree_insert(&listen->MCASTSources, source);
        }
    }

    filter_mode = pico_socket_aggregate_mcastfilters(&mcast_link->address, &mreq->mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    return pico_ipv4_mcast_join(&mreq->mcast_link_addr, &mreq->mcast_group_addr, 0, (uint8_t)filter_mode, &MCASTFilter);
}

static int mcast_so_addsrcm(struct pico_socket *s, void *value)
{
    int filter_mode = 0, reference_count = 0;
    struct pico_ip_mreq_source *mreq = (struct pico_ip_mreq_source *)value;
    struct pico_mcast_listen *listen = NULL;
    struct pico_ip4 *source = NULL, stest = {
        0
    };
    struct pico_ipv4_link *mcast_link = setopt_multicast_check(s, value, 1, 1);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mreq->mcast_link_addr, &mreq->mcast_group_addr);
    if (listen) {
        if (listen->filter_mode != PICO_IP_MULTICAST_INCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR source-specific multicast (include) on any-source multicast (exclude)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        stest.addr = mreq->mcast_source_addr.addr;
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (source) {
            so_mcast_dbg("pico_socket_setoption: ERROR source address to allow already in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            source = pico_zalloc(sizeof(struct pico_ip4));
            if (!source) {
                pico_err = PICO_ERR_ENOMEM;
                return -1;
            }

            source->addr = mreq->mcast_source_addr.addr;
            pico_tree_insert(&listen->MCASTSources, source);
        }
    } else {
        listen = pico_zalloc(sizeof(struct pico_mcast_listen));
        if (!listen) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        listen->filter_mode = PICO_IP_MULTICAST_INCLUDE;
        listen->mcast_link = mreq->mcast_link_addr;
        listen->mcast_group = mreq->mcast_group_addr;
        listen->MCASTSources.root = &LEAF;
        listen->MCASTSources.compare = mcast_sources_cmp;
        source = pico_zalloc(sizeof(struct pico_ip4));
        if (!source) {
            pico_free(listen);
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        source->addr = mreq->mcast_source_addr.addr;
        pico_tree_insert(&listen->MCASTSources, source);
        pico_tree_insert(s->MCASTListen, listen);
        reference_count = 1;
    }

    pico_tree_insert(&MCASTSockets, s);
    filter_mode = pico_socket_aggregate_mcastfilters(&mcast_link->address, &mreq->mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    return pico_ipv4_mcast_join(&mreq->mcast_link_addr, &mreq->mcast_group_addr, (uint8_t)reference_count, (uint8_t)filter_mode, &MCASTFilter);
}

static int mcast_so_dropsrcm(struct pico_socket *s, void *value)
{
    int filter_mode = 0, reference_count = 0;
    struct pico_ip_mreq_source *mreq = (struct pico_ip_mreq_source *)value;
    struct pico_mcast_listen *listen = NULL;
    struct pico_ip4 *source = NULL, stest = {
        0
    };
    struct pico_ipv4_link *mcast_link = setopt_multicast_check(s, value, 0, 1);
    if (!mcast_link)
        return -1;

    listen = listen_find(s, &mreq->mcast_link_addr, &mreq->mcast_group_addr);
    if (!listen) {
        so_mcast_dbg("pico_socket_setoption: ERROR PICO_IP_DROP_SOURCE_MEMBERSHIP before PICO_IP_ADD_SOURCE_MEMBERSHIP\n");
        pico_err = PICO_ERR_EADDRNOTAVAIL;
        return -1;
    } else {
        if (listen->filter_mode != PICO_IP_MULTICAST_INCLUDE) {
            so_mcast_dbg("pico_socket_setoption: ERROR source-specific multicast (include) on any-source multicast (exclude)\n");
            pico_err = PICO_ERR_EINVAL;
            return -1;
        }

        stest.addr = mreq->mcast_source_addr.addr;
        source = pico_tree_findKey(&listen->MCASTSources, &stest);
        if (!source) {
            so_mcast_dbg("pico_socket_setoption: ERROR address to drop not in source list\n");
            pico_err = PICO_ERR_EADDRNOTAVAIL;
            return -1;
        } else {
            pico_tree_delete(&listen->MCASTSources, source);
            pico_free(source);
            if (pico_tree_empty(&listen->MCASTSources)) { /* 1 if empty, 0 otherwise */
                reference_count = 1;
                pico_tree_delete(s->MCASTListen, listen);
                pico_free(listen);
                if (pico_tree_empty(s->MCASTListen)) {
                    pico_free(s->MCASTListen);
                    s->MCASTListen = NULL;
                    pico_tree_delete(&MCASTSockets, s);
                }
            }
        }
    }

    filter_mode = pico_socket_aggregate_mcastfilters(&mcast_link->address, &mreq->mcast_group_addr);
    if (filter_mode < 0)
        return -1;

    return pico_ipv4_mcast_leave(&mreq->mcast_link_addr, &mreq->mcast_group_addr, (uint8_t)reference_count, (uint8_t)filter_mode, &MCASTFilter);
}

int pico_setsockopt_mcast(struct pico_socket *s, int option, void *value)
{

    if (s->proto->proto_number != PICO_PROTO_UDP) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    switch(option) {

    case PICO_IP_MULTICAST_IF:
        pico_err = PICO_ERR_EOPNOTSUPP;
        return -1;

    case PICO_IP_MULTICAST_TTL:
        return pico_udp_set_mc_ttl(s, *((uint8_t *) value));

    case PICO_IP_MULTICAST_LOOP:
        return mcast_so_loop(s, value);

    case PICO_IP_ADD_MEMBERSHIP:
        return mcast_so_addm(s, value);

    case PICO_IP_DROP_MEMBERSHIP:
        return mcast_so_dropm(s, value);

    case PICO_IP_UNBLOCK_SOURCE:
        return mcast_so_unblock_src(s, value);

    case PICO_IP_BLOCK_SOURCE:
        return mcast_so_block_src(s, value);

    case PICO_IP_ADD_SOURCE_MEMBERSHIP:
        return mcast_so_addsrcm(s, value);

    case PICO_IP_DROP_SOURCE_MEMBERSHIP:
        return mcast_so_dropsrcm(s, value);

    default:
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }
}

int pico_udp_set_mc_ttl(struct pico_socket *s, uint8_t ttl)
{
    struct pico_socket_udp *u;
    if(!s) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    u = (struct pico_socket_udp *) s;
    u->mc_ttl = ttl;
    return 0;
}

int pico_udp_get_mc_ttl(struct pico_socket *s, uint8_t *ttl)
{
    struct pico_socket_udp *u;
    if(!s)
        return -1;

    u = (struct pico_socket_udp *) s;
    *ttl = u->mc_ttl;
    return 0;
}
#else
int pico_udp_set_mc_ttl(struct pico_socket *s, uint8_t ttl)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_udp_get_mc_ttl(struct pico_socket *s, uint8_t *ttl)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_socket_mcast_filter(struct pico_socket *s, struct pico_ip4 *mcast_group, struct pico_ip4 *src)
{
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

void pico_multicast_delete(struct pico_socket *s)
{
    (void)s;
}

int pico_getsockopt_mcast(struct pico_socket *s, int option, void *value) 
{
    (void)s;
    (void)option;
    (void)value;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;
}

int pico_setsockopt_mcast(struct pico_socket *s, int option, void *value)
{
    (void)s;
    (void)option;
    (void)value;
    pico_err = PICO_ERR_EPROTONOSUPPORT;
    return -1;

}
#endif /* PICO_SUPPORT_MCAST */

