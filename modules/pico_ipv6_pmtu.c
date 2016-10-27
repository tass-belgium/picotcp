/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Milan Platisa
 *********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_tree.h"
#include "pico_ipv6.h"
#include "pico_ipv6_pmtu.h"

#define PICO_PMTU_CACHE_NEW (0)
#define PICO_PMTU_CACHE_UPDATED (1)
#define PICO_PMTU_CACHE_OLD (2)

#ifdef PICO_SUPPORT_IPV6PMTU

struct pico_ipv6_path_mtu {
    struct pico_ipv6_path_id path;
    uint32_t mtu;
    int cache_status;
};

struct pico_ipv6_path_timer {
    pico_time interval;
    uint32_t id;
};

static int pico_ipv6_path_compare(void *ka, void *kb)
{
    struct pico_ipv6_path_mtu *a = ka, *b = kb;
    return pico_ipv6_compare(&((a->path).dst), &((b->path).dst));
}

static PICO_TREE_DECLARE(PathCache, pico_ipv6_path_compare);
static struct pico_ipv6_path_timer gc_timer = {
		PICO_PMTU_CACHE_CLEANUP_INTERVAL, 0
};

uint32_t pico_ipv6_pmtu_get(const struct pico_ipv6_path_id *path)
{
    struct pico_ipv6_path_mtu test;
    struct pico_ipv6_path_mtu *found = NULL;
    uint32_t mtu = 0;
    if (path != NULL) {
        test.path = *path;
        found = pico_tree_findKey(&PathCache, &test);
        if (found) {
            mtu = found->mtu;
        }
    }

    return mtu;
}

int pico_ipv6_path_add(const struct pico_ipv6_path_id *path, uint32_t mtu)
{
    int status = PICO_PMTU_ERROR;
    if (path != NULL && mtu >= PICO_IPV6_MIN_MTU) {
        struct pico_ipv6_path_mtu test;
        struct pico_ipv6_path_mtu *new = NULL;

        test.path = *path;
        new = pico_tree_findKey(&PathCache, &test);
        if (new == NULL) {
            new = PICO_ZALLOC(sizeof(struct pico_ipv6_path_mtu));
            if (new != NULL) {
                new->path = *path;
                new->mtu = mtu;
                new->cache_status = PICO_PMTU_CACHE_NEW;
                pico_tree_insert(&PathCache, new);
                status = PICO_PMTU_OK;
            }
        }
        else {
            new->mtu = mtu;
            new->cache_status = PICO_PMTU_CACHE_NEW;
            status = PICO_PMTU_OK;
        }
    }

    return status;
}

int pico_ipv6_path_update(const struct pico_ipv6_path_id *path, uint32_t mtu)
{
    int status = PICO_PMTU_ERROR;
    if (path != NULL) {
        struct pico_ipv6_path_mtu test;
        struct pico_ipv6_path_mtu *found = NULL;
        test.path = *path;
        found = pico_tree_findKey(&PathCache, &test);
        if (found) {
            if (found->mtu > mtu) {
                if (mtu < PICO_IPV6_MIN_MTU) {
                    mtu = PICO_IPV6_MIN_MTU;
                }
                found->mtu = mtu;
                found->cache_status = PICO_PMTU_CACHE_UPDATED;
                status = PICO_PMTU_OK;
            }
        }
    }

    return status;
}

int pico_ipv6_path_del(const struct pico_ipv6_path_id *path)
{
    int status = PICO_PMTU_ERROR;
    if (path != NULL) {
        struct pico_ipv6_path_mtu test;
        struct pico_ipv6_path_mtu *found = NULL;
        test.path = *path;
        found = pico_tree_findKey(&PathCache, &test);
        if (found) {
            pico_tree_delete(&PathCache, found);
            PICO_FREE(found);
            status = PICO_PMTU_OK;
        }
    }

    return status;
}

static void pico_ipv6_path_gc(pico_time now, void *unused)
{
    struct pico_tree_node *index = NULL, *_tmp = NULL;

    IGNORE_PARAMETER(now);
    IGNORE_PARAMETER(unused);

    if(!pico_tree_empty(&PathCache)) {
        pico_tree_foreach_safe(index, &PathCache, _tmp)
        {
            if(((struct pico_ipv6_path_mtu *)index->keyValue)->cache_status == PICO_PMTU_CACHE_OLD) {
                pico_tree_delete(&PathCache, index->keyValue);
            } else {
                ((struct pico_ipv6_path_mtu *)index->keyValue)->cache_status = PICO_PMTU_CACHE_OLD;
            }
        }
    }
    gc_timer.id = pico_timer_add(gc_timer.interval, &pico_ipv6_path_gc, NULL);
}

void pico_ipv6_path_init(pico_time interval)
{
    gc_timer.interval = interval;
    if (gc_timer.id != 0) {
        pico_timer_cancel(gc_timer.id);
    }

    gc_timer.id = pico_timer_add(gc_timer.interval, &pico_ipv6_path_gc, NULL);
}

#endif
