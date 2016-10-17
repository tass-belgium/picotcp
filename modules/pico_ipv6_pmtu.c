/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   .

   Authors: Milan Platisa
 *********************************************************************/
#include "pico_config.h"
#include "pico_tree.h"
#include "pico_ipv6.h"
#include "pico_ipv6_pmtu.h"
#ifdef PICO_SUPPORT_IPV6PMTU

struct pico_ipv6_path_mtu {
	struct pico_ipv6_path_id path;
    uint32_t mtu;
};

static int pico_ipv6_path_compare(void *ka, void *kb)
{
    struct pico_ipv6_path_mtu *a = ka, *b = kb;
    return pico_ipv6_compare(&((a->path).dst), &((b->path).dst));
}

static PICO_TREE_DECLARE(PathCache, pico_ipv6_path_compare);


uint32_t pico_ipv6_pmtu_get(const struct pico_ipv6_path_id *path)
{
	struct pico_ipv6_path_mtu test;
	struct pico_ipv6_path_mtu *found = NULL;
	uint32_t mtu = PICO_IPV6_MIN_MTU;
	if (path != NULL){
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
	if (path != NULL && mtu >= PICO_IPV6_MIN_MTU){
		struct pico_ipv6_path_mtu test;
		struct pico_ipv6_path_mtu *new = NULL;

		test.path = *path;
		new = pico_tree_findKey(&PathCache, &test);
		if (new == NULL) {
			new = PICO_ZALLOC(sizeof(struct pico_ipv6_path_mtu));
			if (new != NULL) {
				new->path = *path;
				new->mtu = mtu;
				pico_tree_insert(&PathCache, new);
				status = PICO_PMTU_OK;
			}
		}
		else {
			new->mtu = mtu;
			status = PICO_PMTU_OK;
		}
	}
	return status;
}

int pico_ipv6_path_update(const struct pico_ipv6_path_id *path, uint32_t mtu)
{
	int status = PICO_PMTU_ERROR;
	if (path != NULL && mtu >= PICO_IPV6_MIN_MTU){
		struct pico_ipv6_path_mtu test;
		struct pico_ipv6_path_mtu *found = NULL;
		test.path = *path;
		found = pico_tree_findKey(&PathCache, &test);
		if (found) {
			if (found->mtu > mtu){
				found->mtu = mtu;
				status = PICO_PMTU_OK;
			}
		}
	}
    return status;
}

int pico_ipv6_path_del(const struct pico_ipv6_path_id *path)
{
	int status = PICO_PMTU_ERROR;
	if (path != NULL){
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
#endif
