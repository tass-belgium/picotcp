/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

   Authors: Gustav Janssens, Jonas Van Nieuwenberg, Sam Van Den Berge
 *********************************************************************/

#include "pico_config.h"
#include "pico_mm.h"
#include "pico_tree.h"
#include "pico_config.h"
#include "pico_protocol.h" /* For pico_err */

#define DBG_MM(x, args ...) /* dbg("[%s:%s:%i] "x" \n",__FILE__,__func__,__LINE__ ,##args ) */
#define DBG_MM_RED(x, args ...) /* dbg("\033[31m[%s:%s:%i] "x" \033[0m\n",__FILE__,__func__,__LINE__ ,##args ) */
#define DBG_MM_GREEN(x, args ...) /* dbg("\033[32m[%s:%s:%i] "x" \033[0m\n",__FILE__,__func__,__LINE__ ,##args ) */
#define DBG_MM_YELLOW(x, args ...) /* dbg("\033[33m[%s:%s:%i] "x" \033[0m\n",__FILE__,__func__,__LINE__ ,##args ) */
#define DBG_MM_BLUE(x, args ...) /* dbg("\033[34m[%s:%s:%i] "x" \033[0m\n",__FILE__,__func__,__LINE__ ,##args ) */

/* The memory manager also uses the pico_tree to keep track of all the different slab sizes it has.
 * These nodes should be placed in the manager page which is in a different memory region then the nodes
 * which are used for the pico stack in general.
 * Therefore the following 2 functions are created so that pico_tree can use them to to put these nodes
 * into the correct memory regions.
 */
void*pico_mem_page0_zalloc(size_t len);
void pico_mem_page0_free(void*ptr);


/* this is a wrapper function for pico_tree_insert. The function pointers that are used by pico_tree
 * to zalloc/free are modified so that pico_tree will insert the node in another memory region
 */
static void *manager_tree_insert(struct pico_tree*tree, void *key)
{
    return (void*) pico_tree_insert_implementation(tree, key, USE_PICO_PAGE0_ZALLOC);
}

/* this is a wrapper function for pico_tree_insert. The function pointers that are used by pico_tree
 * to zalloc/free are modified so that pico_tree will insert the node in another memory region
 */
static void *manager_tree_delete(struct pico_tree *tree, void *key)
{
    return (void *) pico_tree_delete_implementation(tree, key, USE_PICO_PAGE0_ZALLOC);
}


static const uint32_t slab_sizes[] = {
    1200, 1400, 1600
};                                                          /* Sizes must be from small to big */
static uint32_t slab_size_statistics[] = {
    0, 0, 0
};
static uint32_t slab_size_global = PICO_MEM_DEFAULT_SLAB_SIZE;
/*
   typedef struct pico_mem_manager         pico_mem_manager;
   typedef struct pico_mem_manager_extra   pico_mem_manager_extra;
   typedef struct pico_mem_page            pico_mem_page;
   typedef struct pico_mem_heap            pico_mem_heap;
   typedef struct pico_mem_slab            pico_mem_slab;
   typedef struct pico_mem_heap_block      pico_mem_heap_block;
   typedef struct pico_mem_slab_block      pico_mem_slab_block;
   typedef struct pico_mem_slab_node       pico_mem_slab_node;
   typedef struct pico_mem_block           pico_mem_block;
   typedef struct pico_tree                pico_tree;
   typedef struct pico_tree_node           pico_tree_node;
   typedef union block_internals           block_internals;
 */
#define HEAP_BLOCK_NOT_FREE 0xCAFED001
#define HEAP_BLOCK_FREE 0xCAFED00E

#define SLAB_BLOCK_TYPE 0
#define HEAP_BLOCK_TYPE 1
/*
 *                                   page
 *       <---------------------------------------------------------------------->
 *
 *
 *       +------------<------------+----------<-----------+
 *       |                         ^                      ^
 *       v                         |                      |
 *       +---------+------------+--+----+---------------+-+-----+---------------+
 *       |         |            |       |               |       |               |
 *       |  pico_  |            | pico_ |               | pico_ |               |
 *       |  mem_   | ...HEAP... | mem_  |     slab      | mem_  |     slab      |
 *       |  page   |            | block |               | block |               |
 *       |         |            |       |               |       |               |
 *       +---------+------------+-------+-----+---------+-------+----------+----+
 *                              ^             |         ^                  |
 *                              +-------+     |         |                  |
 *                                      |     |       +-+                  |
 *                               +------|-----+       |                    |
 *                               |      |       +-----|--------------------+
 *                               v      |       v     |
 *       +---------+-----+-------+------+-+-----+-----+--+
 *       |         |     |       |        |     |        |
 *       | pico_   |     | pico_ | pico_  |     | pico_  |
 *       | mem_    | ... | tree_ | mem_   | ... | mem_   |
 *       | manager |     | node  | slab_  |     | slab_  |
 *       |         |     |       | node   |     | node   |
 *       +---------+-----+-+-----+-----+--+-----+-----+--+
 *                         |     ^     |        ^     |
 *                         |     |     +---->---+     |
 *                         +-->--+----<-----------<---+
 *
 *       <----------------------------------------------->
 *                         manager page
 *
 *
 *                    +----------------+
 *                    |                |
 *                    | pico_tree_node +-------------------------------------+
 *                    |    (size x)    |                                     |
 *                    +--+----------+--+                                     |
 *                       |          |                              +---------v----------+
 *                       |          |                              |                    |
 *                       v          v                         +----> pico_mem_slab_node +----+
 *                       |          |                         |    |                    |    |
 *             +----<----+          +---->----+               |    +--------------------+    |
 *             |                              |               |                              |
 *             |                              |               ^                              v
 *             |                              |               |                              |
 *             |                              |               |    +--------------------+    |
 *      +------v---------+          +---------v------+        +----+                    <----+
 *      |                |          |                |             | pico_mem_slab_node |
 *      | pico_tree_node |          | pico_tree_node |        +---->                    +----+
 *      |   (size x/2)   |          |    (size 2x)   |        |    +--------------------+    |
 *      +----------------+          +----------------+        |                              |
 *                                                            |                              |
 *                                                            |                              |
 *                                                            ^                              v
 *                                                           ...                            ...
 *
 */

/* Housekeeping memory manager (start of page 0) */
struct pico_mem_manager
{
    uint32_t size;             /* Maximum size in bytes */
    uint32_t used_size;        /* Used size in bytes */
    struct pico_tree tree;
    struct pico_mem_page*first_page;
    struct pico_mem_manager_extra*manager_extra;  /* this is a pointer to a page with extra heap space used by the manager */
};
/* Housekeeping additionnal memory manager heap pages */
struct pico_mem_manager_extra
{
    struct pico_mem_manager_extra*next;
    uint32_t timestamp;
    uint32_t blocks;
};
/* Housekeeping of every page (start of all pages except the manager pages) */
struct pico_mem_page
{
    uint32_t slab_size;
    uint16_t slabs_max;
    uint16_t slabs_free;
    uint32_t heap_max_size;
    uint32_t heap_max_free_space;
    uint32_t timestamp;
    struct pico_mem_page*next_page;
};
/* Housekeeping struct for a heap block (kept per block of memory in heap) */
struct pico_mem_heap_block
{
    uint32_t size;
    /* uint8_t free; */
    uint32_t free;
};
/* Housekeeping struct for a slab block (kept per block of memory in slabs) */
struct pico_mem_slab_block
{
    struct pico_mem_page*page;
    struct pico_mem_slab_node*slab_node;
};
union block_internals
{
    struct pico_mem_heap_block heap_block;
    struct pico_mem_slab_block slab_block;
};
struct pico_mem_block
{
    union block_internals internals; /* Union has to be in first place!!! */
    uint8_t type;
};
/* Used to store the slab objects in the RB-tree */
struct pico_mem_slab_node
{
    struct pico_mem_block*slab;
    struct pico_mem_slab_node*prev;
    struct pico_mem_slab_node*next;
};

static struct pico_mem_manager*manager = NULL;

/*
 * This compare function will be called by pico_tree.c to compare 2 keyValues (type: struct pico_mem_slab_nodes)
 * We want to compare slab_nodes by their size. We also want to be able to directly compare an integer, which explains
 * the casts from void* to uint32_t***
 */
static int compare_slab_keys(void*keyA, void*keyB)
{
    /* keyValues are pico_mem_slab_nodes */
    /* We want to compare the sizes */
    /* first element of pico_mem_slab_node: pico_mem_block* slab_block */
    /* first element of pico_mem_block: (slab_block in union): pico_mem_page* page */
    /* first element of pico_mem_page: uint32_t slab_size */
    uint32_t sizeKeyA = ***(uint32_t***) keyA;
    uint32_t sizeKeyB = ***(uint32_t***) keyB;
    DBG_MM_BLUE("Compare called: sizeA = %i, sizeB = %i", sizeKeyA, sizeKeyB);
    if(sizeKeyA == sizeKeyB)
    {
        return 0;
    }
    else if(sizeKeyA < sizeKeyB)
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

/*
 * Pico_mem_init_page is called to initialize a block of memory pointed to by pico_mem_page* page.
 * Slabs of size slabsize are created, and the page, heap and slab housekeeping is initialized.
 */
static void _pico_mem_init_page(struct pico_mem_page*page, size_t slabsize)
{
    uint8_t*byteptr = (uint8_t*) page;
    struct pico_mem_block*slab_block;
    struct pico_mem_block*heap_block;
    struct pico_tree_node*tree_node;
    struct pico_mem_slab_node*slab_node;
    void*temp;
    uint16_t i;

    DBG_MM_YELLOW("Initializing page %p with slabsize %u", page, slabsize);

    page->next_page = manager->first_page;
    manager->first_page = page;
    page->slab_size = (uint32_t)slabsize;
    page->slabs_max = (uint16_t)((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block)) / (slabsize + sizeof(struct pico_mem_block)));
    page->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page->slabs_max * (sizeof(struct pico_mem_block) + slabsize)));
    if(page->heap_max_size < PICO_MIN_HEAP_SIZE)
    {
        DBG_MM_BLUE("Not enough heap size available with slabsize %u, allocating one slab to heap.", slabsize);
        page->slabs_max--;
        /* DBG_MM_BLUE("Heap size %u -> %lu",page->heap_max_size, page->heap_max_size + sizeof(pico_mem_slab_block) + slabsize); */
        DBG_MM_BLUE("Heap size %u -> %lu", page->heap_max_size, page->heap_max_size + sizeof(struct pico_mem_block) + slabsize);
        page->heap_max_size += (uint32_t)(sizeof(struct pico_mem_block) + slabsize);
    }

    page->slabs_free = page->slabs_max;
    page->heap_max_free_space = page->heap_max_size;
    page->timestamp = 0;
    DBG_MM_BLUE("max slab objects = %i, object_size = %i", page->slabs_max, page->slab_size);
    DBG_MM_BLUE("Heap size: %i", page->heap_max_size);
    byteptr += sizeof(struct pico_mem_page);    /* jump over page struct so byteptr points to start of heap */

    /* Init HEAP at the beginning of the page */
    heap_block = (struct pico_mem_block*) byteptr;
    heap_block->type = HEAP_BLOCK_TYPE;
    heap_block->internals.heap_block.free = HEAP_BLOCK_FREE;
    heap_block->internals.heap_block.size = page->heap_max_free_space;

    byteptr += sizeof(struct pico_mem_block) + heap_block->internals.heap_block.size;
    for(i = 0; i < page->slabs_max; i++)
    {
        slab_block = (struct pico_mem_block*) byteptr;
        DBG_MM_BLUE("Slab object %i at %p. Start of object data at %p", i, slab_block, (uint8_t*) slab_block + sizeof(struct pico_mem_slab_block));
        slab_block->type = SLAB_BLOCK_TYPE;
        slab_block->internals.slab_block.page = page;

        DBG_MM_BLUE("Calling find_node with size %u", **((uint32_t**) slab_block));
        tree_node = pico_tree_findNode(&(manager->tree), &slab_block);

        DBG_MM("Creating slab_node..");
        slab_node = pico_mem_page0_zalloc(sizeof(struct pico_mem_slab_node));
        if(slab_node == NULL)
        {
            DBG_MM_RED("No more space in the manager heap for the housekeeping of slab %i, and no more space for extra manager pages!", i + 1);
            DBG_MM_RED("Debug info:\nUsed size: %u/%u\nmanager_extra = %p", manager->used_size, manager->size, manager->manager_extra);
            DBG_MM_RED("This page will be initialized with %u slabs instead of %u slabs", i, page->slabs_max);
            page->slabs_max = i;
            page->slabs_free = page->slabs_max;
            return;
            /* exit(1); */
        }

        slab_node->slab = slab_block;
        slab_node->prev = NULL;
        slab_node->next = NULL;

        slab_block->internals.slab_block.slab_node = slab_node;

        if(tree_node != NULL)
        {
            struct pico_mem_slab_node*first_node = (struct pico_mem_slab_node*) tree_node->keyValue;
            tree_node->keyValue = slab_node;
            slab_node->next = first_node;
            first_node->prev = slab_node;
        }
        else
        {
            /* Insert new slab_node */
            DBG_MM_BLUE("Inserting new slab node in the tree of size %u", slabsize);
            /* pico_err_t pico_err_backup = pico_err; */
            /* pico_err = 0; */


            /* temp = pico_tree_insert(&manager->tree, slab_node); */
            temp = manager_tree_insert(&manager->tree, slab_node);

            /* IF SLAB_NODE COULDN'T BE INSERTED */
            /* if(pico_err == PICO_ERR_ENOMEM) */
            /* if(temp == &LEAF) */
            if(temp != NULL)
            {
                DBG_MM_RED("No more space in the manager heap for the housekeeping of slab %i, and no more space for extra manager pages!", i + 1);
                DBG_MM_RED("This page will be initialized without slabs.");
                pico_mem_page0_free(slab_node);
                page->slabs_max = (uint16_t) i;
                page->slabs_free = page->slabs_max;
                /* pico_err = pico_err_backup; */
                return;
            }
        }

        /* byteptr = (uint8_t*) (slab_block+1); */
        byteptr = (uint8_t*) slab_block;
        byteptr += sizeof(struct pico_mem_block);
        byteptr += page->slab_size;
    }
    DBG_MM_GREEN("Initialized page %p with slabsize %u", page, slabsize);
}

/*
 * Initializes the memory by creating a memory manager page and one page with default slab size
 * A maximum space of memsize can be occupied by the memory manager at any time
 */
void pico_mem_init(uint32_t memsize)
{
    struct pico_mem_block*first_block;
    struct pico_mem_page*page;
    uint8_t*startofmanagerheap;

    DBG_MM_YELLOW("Initializing memory with memsize %u", memsize);
    if(memsize < PICO_MEM_PAGE_SIZE * 2)
    {
        /* Not enough memory was provided to initialize a manager page and a data page, return without initializing memory */
        /* Set pico_err to an appropriate value */
        pico_err = PICO_ERR_ENOMEM;
        DBG_MM_RED("The memsize provided is too small, memory not initialized!");

        return;
    }

    /* First pico_mem_page is already included in pico_mem_manager. Others are added. */
    /* manager = pico_azalloc(sizeof(pico_mem_manager) + sizeof(pico_mem_page*)*(pages - 1));	//Points to usermanager if one present */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    if( NULL != manager )
    {
        manager->size = memsize;
        manager->used_size = PICO_MEM_PAGE_SIZE;
        manager->first_page = NULL;
        manager->manager_extra = NULL;

        manager->tree.compare = compare_slab_keys;
        manager->tree.root = &LEAF;
        DBG_MM_BLUE("Manager page is at %p", manager);

        DBG_MM_BLUE("Start of tree: %p, sizeof(pico_tree): %lu", &manager->tree, sizeof(struct pico_tree));
        DBG_MM_BLUE("Root node of tree at %p", manager->tree.root);

        /* Init manager heap. Used to store the RB-tree nodes which store pointers to free slab objects */
        startofmanagerheap = (uint8_t*) manager + sizeof(struct pico_mem_manager); /* manager heap is after struct pico_mem_manager */
        DBG_MM_BLUE("Start of manager heap = %p", startofmanagerheap);
        first_block = (struct pico_mem_block*) startofmanagerheap;
        first_block->type = HEAP_BLOCK_TYPE;
        first_block->internals.heap_block.free = HEAP_BLOCK_FREE;
        first_block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block);

        /* Initialize the first page only! */
        page = pico_zalloc(PICO_MEM_PAGE_SIZE);
        if(page != NULL)
        {
            manager->used_size += PICO_MEM_PAGE_SIZE;
            DBG_MM_BLUE("Page 1 at %p, manager used size = %u", page, manager->used_size);
            _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
        }
        else
        {
            /* Not enough memory was provided to initialize a manager page and a data page, return without initializing memory */
            /* Set pico_err to an appropriate value */
            pico_err = PICO_ERR_ENOMEM;
            /* Free the manager page */
            pico_free(manager);
            manager = NULL;
            DBG_MM_RED("Not enough space to allocate page 1, memory not initialized!");
            return;
        }

        DBG_MM_GREEN("Memory initialized. Returning from pico_mem_init.");
    }
    else
    {
        /* Not enough memory was provided to initialize a manager page and a data page, return without initializing memory */
        /* Set pico_err to an appropriate value */
        pico_err = PICO_ERR_ENOMEM;
        DBG_MM_RED("Not enough space to allocate manager page, memory not initialized!");
        return;
    }
}

/*
 * Deinitializes the memory manager, returning all its memory to the system's control.
 */
void pico_mem_deinit()
{
    struct pico_mem_page*next_page;
    struct pico_mem_manager_extra*next_manager_page;

    DBG_MM_YELLOW("Pico_mem_deinit called");
    if(manager == NULL)
    {
        DBG_MM_GREEN("No memory instance initialized, returning");
    }
    else
    {
        while(manager->first_page != NULL)
        {
            next_page = manager->first_page->next_page;
            pico_free(manager->first_page);
            manager->first_page = next_page;
        }
        while(manager->manager_extra != NULL)
        {
            next_manager_page = manager->manager_extra->next;
            pico_free(manager->manager_extra);
            manager->manager_extra = next_manager_page;
        }
        DBG_MM_BLUE("Freeing manager page at %p", manager);
        pico_free(manager);
        manager = NULL;
        slab_size_global = PICO_MEM_DEFAULT_SLAB_SIZE;
        DBG_MM_GREEN("Memory manager reset");
    }
}

/*
 * This function is called internally by page0_zalloc if there isn't enough space left in the heap of the initial memory page
 * This function allocates heap space in extra manager pages, creating new pages as necessary.
 */
static void*_pico_mem_manager_extra_alloc(struct pico_mem_manager_extra*heap_page, size_t len)
{
    struct pico_mem_manager_extra*extra_heap_page;
    struct pico_mem_block*heap_block;
    struct pico_mem_block*first_block;
    struct pico_mem_block*new_block;
    uint8_t*startOfData;
    uint8_t*byteptr;
    uint32_t sizeleft;

    DBG_MM_YELLOW("Searching for a block of len %u in extra manager page %p (%u blocks in use)", len, heap_page, heap_page->blocks);
    /* Linearly search for a free heap block */

    /* heap_block = (pico_mem_block*) (heap_page+1); */
    byteptr = (uint8_t*) heap_page + sizeof(struct pico_mem_manager_extra);
    heap_block = (struct pico_mem_block*) byteptr;

    sizeleft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra);

    while(heap_block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE || heap_block->internals.heap_block.size < len)
    {
        sizeleft -= (uint32_t)sizeof(struct pico_mem_block);
        sizeleft -= heap_block->internals.heap_block.size;
        /* DBG_MM("Sizeleft=%i", sizeleft); */
        /* byteptr = (uint8_t*) (heap_block+1); */
        byteptr = (uint8_t*) heap_block + sizeof(struct pico_mem_block);
        byteptr += heap_block->internals.heap_block.size;
        heap_block = (struct pico_mem_block*) byteptr;
        if(sizeleft <= sizeof(struct pico_mem_block))
        {
            DBG_MM_RED("No more heap space left in the extra manager heap page!");
            if(heap_page->next == NULL)
            {
                /* TODO: Probably need another function for this */
                DBG_MM_RED("Trying to allocate a new page for extra heap space: space usage %uB/%uB", manager->used_size, manager->size);
                if(manager->used_size + PICO_MEM_PAGE_SIZE > manager->size)
                {
                    DBG_MM_RED("No more space left for this page!");
                    /* exit(1); */
                    return NULL;
                }

                extra_heap_page = pico_zalloc(PICO_MEM_PAGE_SIZE);
                if(extra_heap_page != NULL)
                {
                    extra_heap_page->blocks = 0;
                    extra_heap_page->next = NULL;
                    extra_heap_page->timestamp = 0;
                    byteptr = (uint8_t*) extra_heap_page + sizeof(struct pico_mem_manager_extra);
                    first_block = (struct pico_mem_block*) byteptr;
                    first_block->type = HEAP_BLOCK_TYPE;
                    first_block->internals.heap_block.free = HEAP_BLOCK_FREE;
                    first_block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra) - sizeof(struct pico_mem_block);
                    extra_heap_page->next = heap_page;
                    manager->manager_extra = extra_heap_page;
                    manager->used_size += PICO_MEM_PAGE_SIZE;
                    DBG_MM_BLUE("Allocated an extra manager heap page at %p, manager space usage: %uB/%uB", extra_heap_page, manager->used_size, manager->size);
                    return _pico_mem_manager_extra_alloc(extra_heap_page, len);
                }
                else
                {
                    /* This should be a dirty crash */
                    DBG_MM_RED("Page not allocated even though the max size for the memory manager hasn't been reached yet!");
                    /* exit(1); */
                    return NULL;
                }
            }
            else
            {
                DBG_MM_RED("This should never happen: debug information:");
                DBG_MM_RED("manager->manager_extra = %p", manager->manager_extra);
                DBG_MM_RED("heap_page = %p", heap_page);
                DBG_MM_RED("heap_page->next = %p", heap_page->next);
                /* exit(1); */
                return NULL;
            }
        }
    }
    heap_page->blocks++;
    heap_page->timestamp = 0;
    DBG_MM_BLUE("Found free heap block in extra manager page %p at: %p (%u blocks in use)", heap_page, heap_block, heap_page->blocks);
    heap_block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;

    if(heap_block->internals.heap_block.size == sizeleft - sizeof(struct pico_mem_block))
    {
        DBG_MM_BLUE("End of heap, splitting up into a new block");
        heap_block->internals.heap_block.size = (uint32_t)len;
        sizeleft = (uint32_t)(sizeleft - (uint32_t)sizeof(struct pico_mem_block) - len);
        if(sizeleft > sizeof(struct pico_mem_block))
        {
            sizeleft -= (uint32_t)sizeof(struct pico_mem_block);
            byteptr = (uint8_t*) heap_block + sizeof(struct pico_mem_block);
            byteptr += len;
            new_block = (struct pico_mem_block*) byteptr;
            new_block->type = HEAP_BLOCK_TYPE;
            new_block->internals.heap_block.free = HEAP_BLOCK_FREE;
            new_block->internals.heap_block.size = sizeleft;
            DBG_MM_BLUE("New block: %p, size = %u", new_block, new_block->internals.heap_block.size);
        }
        else
        {
            DBG_MM_RED("No more space in extra manager heap page left to initialize a new heap block!");
            DBG_MM_RED("A new page will be allocated when even more space is needed");
        }
    }

    startOfData = (uint8_t*) heap_block + sizeof(struct pico_mem_block);
    DBG_MM_GREEN("Start of data = %p", startOfData);

    return startOfData;
}

/*
 * Page0 zalloc is called by pico_tree.c so that nodes which contain pointers to the free slab objects are put in the
 * manager page. Additional manager pages can be created if necessary.
 */
void*pico_mem_page0_zalloc(size_t len)
{
    struct pico_mem_manager_extra*heap_page;
    struct pico_mem_block*heap_block;
    struct pico_mem_block*first_block;
    struct pico_mem_block*new_block;
    uint8_t*startOfData;
    uint8_t*byteptr;
    uint32_t sizeleft;

    DBG_MM_YELLOW("pico_mem_page0_zalloc(%u) called", len);

    byteptr = (uint8_t*) manager + sizeof(struct pico_mem_manager);
    heap_block = (struct pico_mem_block*) byteptr;

    /* If heap_block == NULL then a free block at the end of the list is found. */
    /* Else, if the block is free and the size > len, an available block is also found. */
    sizeleft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager);
    /* this would mean that heap_block is never NULL */
    /* while(heap_block != NULL && ( heap_block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE || heap_block->internals.heap_block.size < len)) */
    while(heap_block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE || heap_block->internals.heap_block.size < len)
    {
        sizeleft -= (uint32_t)sizeof(struct pico_mem_block);
        sizeleft -= heap_block->internals.heap_block.size;
        /* DBG_MM("Sizeleft=%i", sizeleft); */
        byteptr = (uint8_t*) heap_block + sizeof(struct pico_mem_block); /* byteptr points to start of heap block data */
        byteptr += heap_block->internals.heap_block.size; /* jump over that data to start of next heap_block */
        heap_block = (struct pico_mem_block*) byteptr;
        if(sizeleft <= sizeof(struct pico_mem_block))
        {
            DBG_MM_RED("No more heap space left in the manager page!");
            if(manager->manager_extra == NULL)
            {
                DBG_MM_RED("Trying to allocate a new page for extra heap space: space usage: %uB/%uB", manager->used_size, manager->size);
                if(manager->used_size + PICO_MEM_PAGE_SIZE > manager->size)
                {
                    DBG_MM_RED("No more space left for this page!");
                    /* exit(1); */
                    return NULL;
                }

                heap_page = pico_zalloc(PICO_MEM_PAGE_SIZE);
                if(heap_page != NULL)
                {
                    /* Initialize the new heap page */
                    heap_page->blocks = 0;
                    heap_page->next = NULL;
                    heap_page->timestamp = 0;
                    byteptr = (uint8_t*) heap_page + sizeof(struct pico_mem_manager_extra);
                    first_block = (struct pico_mem_block*) byteptr;
                    first_block->type = HEAP_BLOCK_TYPE;
                    first_block->internals.heap_block.free = HEAP_BLOCK_FREE;
                    first_block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra) - sizeof(struct pico_mem_block);
                    manager->manager_extra = heap_page;
                    manager->used_size += PICO_MEM_PAGE_SIZE;
                    DBG_MM_BLUE("Allocated an extra manager heap page at %p, manager space usage: %uB/%uB", heap_page, manager->used_size, manager->size);
                    return _pico_mem_manager_extra_alloc(heap_page, len);
                }
                else
                {
                    /* This should be a dirty crash */
                    DBG_MM_RED("Page not allocated even though the max size for the memory manager hasn't been reached yet!");
                    /* exit(1); */
                    return NULL;
                }
            }
            else
            {
                return _pico_mem_manager_extra_alloc(manager->manager_extra, len);
            }
        }
    }
    DBG_MM_BLUE("Found free heap block in manager page at : %p", heap_block);
    heap_block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;

    if(heap_block->internals.heap_block.size == sizeleft - sizeof(struct pico_mem_block))
    {
        sizeleft = (uint32_t)(sizeleft - (uint32_t)sizeof(struct pico_mem_block) - len);
        if(sizeleft > sizeof(struct pico_mem_block))
        {
            DBG_MM_BLUE("End of heap, splitting up into a new block");
            heap_block->internals.heap_block.size = (uint32_t)len;
            sizeleft -= (uint32_t)sizeof(struct pico_mem_block);
            byteptr = (uint8_t*) heap_block + sizeof(struct pico_mem_block);
            byteptr += len;
            new_block = (struct pico_mem_block*) byteptr;
            new_block->internals.heap_block.free = HEAP_BLOCK_FREE;
            new_block->internals.heap_block.size = sizeleft;
            DBG_MM_BLUE("New block: %p, size = %u", new_block, new_block->internals.heap_block.size);
        }
        else
        {
            /* DBG_MM_RED("ERROR! No more space in manager heap left to initialise a new heap_block!"); */
            /* exit(1); */
            DBG_MM_RED("No more space in manager heap left to initialize a new heap block!");
            DBG_MM_RED("A new page will be allocated when more space is needed");
        }
    }

    startOfData = (uint8_t*) heap_block + sizeof(struct pico_mem_block);
    DBG_MM_GREEN("Start of data = %p", startOfData);

    return startOfData;
}


/*
 * This method will free a given heap block and try to merge it with
 * surrounding blocks if they are free.
 */
static void _pico_mem_free_and_merge_heap_block(struct pico_mem_page*page, struct pico_mem_block*mem_block)
{
    uint8_t*byteptr;
    /* pico_mem_block* prev = NULL; */
    struct pico_mem_block*prev;
    struct pico_mem_block*curr;
    struct pico_mem_block*next;

    DBG_MM_YELLOW("Freeing heap block %p with size %u in page %p", mem_block, mem_block->internals.heap_block.size, page);

    mem_block->internals.heap_block.free = HEAP_BLOCK_FREE;

    byteptr = (uint8_t*) page + sizeof(struct pico_mem_page);
    curr = (struct pico_mem_block*) byteptr;
    byteptr = (uint8_t*) curr + sizeof(struct pico_mem_block);
    byteptr += curr->internals.heap_block.size;
    next = (struct pico_mem_block*) byteptr;

    while(curr->type == HEAP_BLOCK_TYPE && next->type == HEAP_BLOCK_TYPE)
    {
        DBG_MM("Checking heap block (%s) with size %u at %p", (curr->internals.heap_block.free == HEAP_BLOCK_FREE) ? "free" : "not free", curr->internals.heap_block.size, curr);
        if(curr->internals.heap_block.free == HEAP_BLOCK_FREE && next->internals.heap_block.free == HEAP_BLOCK_FREE)
        {
            DBG_MM_BLUE("Merging blocks with sizes %u and %u", curr->internals.heap_block.size, next->internals.heap_block.size);
            curr->internals.heap_block.size += (uint32_t)sizeof(struct pico_mem_block) + next->internals.heap_block.size;
        }

        prev = curr;
        byteptr = (uint8_t*) curr + sizeof(struct pico_mem_block);
        byteptr += curr->internals.heap_block.size;
        curr = (struct pico_mem_block*) byteptr;
        byteptr = (uint8_t*) curr + sizeof(struct pico_mem_block);
        byteptr += curr->internals.heap_block.size;
        next = (struct pico_mem_block*) byteptr;
    }
    DBG_MM("Checking heap block (%s) with size %u at %p", (curr->internals.heap_block.free == HEAP_BLOCK_FREE) ? "free" : "not free", curr->internals.heap_block.size, curr);
    if(curr->type == HEAP_BLOCK_TYPE && prev->internals.heap_block.free == HEAP_BLOCK_FREE && curr->internals.heap_block.free == HEAP_BLOCK_FREE)
    {
        DBG_MM_BLUE("Merging blocks with sizes %u and %u", prev->internals.heap_block.size, curr->internals.heap_block.size);
        prev->internals.heap_block.size += (uint32_t)sizeof(struct pico_mem_block) + curr->internals.heap_block.size;
    }

    DBG_MM_GREEN("Heap block freed and heap space defragmentized");
}

/*
 * This method will return the max. available contiguous free space in the heap
 * from a given page.
 */
static uint32_t _pico_mem_determine_max_free_space(struct pico_mem_page*page)
{
    uint32_t maxfreespace = 0;
    uint8_t*byteptr;
    struct pico_mem_block*mem_block;

    DBG_MM_YELLOW("Determining new maximum free space in page %p (old free space: %u)", page, page->heap_max_free_space);

    /* pico_mem_block* mem_block = (pico_mem_block*) (page+1);	//reset mem_block to first block in the heap */
    byteptr = (uint8_t*) page + sizeof(struct pico_mem_page);
    mem_block = (struct pico_mem_block*) byteptr;   /* reset mem_block to first block in the heap */

    /* Determine max free space by iterating trough the list */
    /* while(mem_block != NULL && mem_block->type == HEAP_BLOCK_TYPE) */
    while(mem_block->type == HEAP_BLOCK_TYPE)
    {
        /* DBG_MM("Memblock %p of size %i is free %i\n",block, block->size, block->free); */
        DBG_MM("Memblock %s (size %u) at %p", (mem_block->internals.heap_block.free == HEAP_BLOCK_FREE) ? "not in use" : "in use", mem_block->internals.heap_block.size, mem_block);
        if(mem_block->internals.heap_block.free == HEAP_BLOCK_FREE && mem_block->internals.heap_block.size > maxfreespace)
        {
            maxfreespace = mem_block->internals.heap_block.size;
            page->heap_max_free_space = maxfreespace;
        }

        byteptr = (uint8_t*) mem_block + sizeof(struct pico_mem_block);
        byteptr += mem_block->internals.heap_block.size;
        mem_block = (struct pico_mem_block*) byteptr;
    }
    page->heap_max_free_space = maxfreespace;
    DBG_MM_GREEN("New free space: %u", page->heap_max_free_space);
    return maxfreespace;
}

/*
 * This method will make a slab object available again by putting it in the RB-tree.
 * Slab objects of the same size are stored in a double linked list. One pico_tree_node represents
 * all the slab objects of the same size by making the keyvalue of a pico_tree_node point to
 * the first element of the linked list.
 * An element in this linked list is a struct pico_mem_slab_node. All the elements are also
 * stored in the heap of the manager page (page0), or in the heap of extra manager spaces if there isn't enough space.
 */
static void _pico_mem_free_slab_block(struct pico_mem_block*slab_block)
{
    struct pico_mem_slab_node*slab_node;
    struct pico_mem_slab_node*first_slab_node;
    struct pico_tree_node*tree_node;
    void*temp;

    DBG_MM_YELLOW("Freeing slab object");

    slab_node = pico_mem_page0_zalloc(sizeof(struct pico_mem_slab_node));

    if(slab_node == NULL)
    {
        /* Update the page householding without making the slab available again! */
        DBG_MM_RED("No more space in the manager heap and no more space for extra pages!");
        DBG_MM_RED("This slab will be leaked, but the leak will be plugged at the next cleanup, if and when the page is empty");
        slab_block->internals.slab_block.page->slabs_free++;
        return;
    }

    slab_node->slab = slab_block;
    slab_block->internals.slab_block.slab_node = slab_node;
    tree_node = pico_tree_findNode(&manager->tree, slab_node);
    if(tree_node != NULL)
    {
        first_slab_node = (struct pico_mem_slab_node*) tree_node->keyValue;
        tree_node->keyValue = slab_node;
        first_slab_node->prev = slab_node;
        slab_node->prev = NULL;
        slab_node->next = first_slab_node;
    }
    else{
        DBG_MM_BLUE("No node found for size %i so calling pico_tree_insert", slab_node->slab->internals.slab_block.page->slab_size);
        slab_node->next = NULL;
        slab_node->prev = NULL;
        /* pico_err_t pico_err_backup = pico_err; */
        /* pico_err = 0; */


        /* temp = pico_tree_insert(&manager->tree, slab_node); */
        temp = manager_tree_insert(&manager->tree, slab_node);

        /* if(pico_err == PICO_ERR_ENOMEM) */
        if(temp == &LEAF)
        {
            DBG_MM_RED("No more space in the manager heap and no more space for extra pages!");
            DBG_MM_RED("This slab will be leaked, but the leak will be plugged at the next cleanup, if and when the page is empty");
            pico_mem_page0_free(slab_node);
            /* pico_err = pico_err_backup; */
            slab_block->internals.slab_block.page->slabs_free++;
            return;
        }
    }

    /* Update free slabs in page householding */
    slab_block->internals.slab_block.page->slabs_free++;
    DBG_MM_GREEN("Freed slab object, there are now %i free slab objects in the corresponding page", slab_block->internals.slab_block.page->slabs_free);
}

/*
 * This method zero initializes a block of memory pointed to by startOfData, of size len
 */
static void _pico_mem_zero_initialize(void*startOfData, size_t len)
{
    if(startOfData != NULL)
    {
        DBG_MM_YELLOW("Zero initializing user memory at %p of %u bytes", startOfData, len);
        memset(startOfData, 0, len);
        DBG_MM_GREEN("Zero initialized.");
    }
    else
    {
        DBG_MM_RED("Got a NULL pointer to zero initialize!");
    }
}

/*
 * This method will try to find a free heap block of size len in a given page.
 */
static void*_pico_mem_find_heap_block(struct pico_mem_page*page, size_t len)
{
    struct pico_mem_block*mem_block;
    struct pico_mem_block*inserted_block;
    uint8_t*startOfData;
    uint8_t*byteptr;

    DBG_MM_YELLOW("Searching for a heap block of length %u in page %p (largest free block size = %u)", len, page, page->heap_max_free_space);
    if(page->heap_max_free_space < len )
    {
        DBG_MM_RED("Size %u > max free space %u of the page. This should only happen when this page is newly created, and its heap space is not large enough for the heap length!", len, page->heap_max_free_space);
        return NULL;
    }

    byteptr = (uint8_t*) page + sizeof(struct pico_mem_page);
    mem_block = (struct pico_mem_block*) byteptr;   /* Jump over the page struct to the start of the heap */

    /* If mem_block == NULL then a free block at the end of the list is found. */
    /* Else, if the block is free and the size > len, an available block is also found. */
    /* while(mem_block != NULL && mem_block->type == HEAP_BLOCK_TYPE  && ( mem_block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE || mem_block->internals.heap_block.size < len)) */
    while(mem_block->type == HEAP_BLOCK_TYPE  && (mem_block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE || mem_block->internals.heap_block.size < len))
    {
        /* DBG_MM_RED("Skipping heap block in use at %p of size %i", mem_block, mem_block->size); */
        DBG_MM_BLUE("Skipping heap block %s (size %u) at %p", (mem_block->internals.heap_block.free == HEAP_BLOCK_FREE) ? "not in use" : "in use", mem_block->internals.heap_block.size, mem_block);
        byteptr = (uint8_t*) mem_block + sizeof(struct pico_mem_block);
        byteptr += mem_block->internals.heap_block.size;
        mem_block = (struct pico_mem_block*) byteptr;
    }
    if(mem_block->type == SLAB_BLOCK_TYPE)
    {
        DBG_MM_RED("No free heap block of contiguous size %u could be found in page %p", len, page);
        /* exit(1); */
        return NULL;
    }

    DBG_MM_BLUE("Found free heap block of size %u at %p", mem_block->internals.heap_block.size, mem_block);
    mem_block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    page->timestamp = 0;

    /* Check to split the block into two smaller blocks */
    if(mem_block->internals.heap_block.size >= (len + sizeof(struct pico_mem_block) + PICO_MEM_MINIMUM_OBJECT_SIZE))
    {
        byteptr = (uint8_t*) mem_block + sizeof(struct pico_mem_block);
        byteptr += len;
        inserted_block = (struct pico_mem_block*) byteptr;

        /* Update newly inserted block */
        inserted_block->type = HEAP_BLOCK_TYPE;
        inserted_block->internals.heap_block.free = HEAP_BLOCK_FREE;
        inserted_block->internals.heap_block.size = (uint32_t)(mem_block->internals.heap_block.size - (uint32_t)sizeof(struct pico_mem_block) - len);
        /* Update block that was split up */
        mem_block->internals.heap_block.size = (uint32_t)len;
        DBG_MM_BLUE("Splitting up the block, creating a new block of size %u at %p", inserted_block->internals.heap_block.size, inserted_block);
    }

    startOfData = (uint8_t*) mem_block + sizeof(struct pico_mem_block);

    page->heap_max_free_space = _pico_mem_determine_max_free_space(page);

    /* Zero-initialize */
    _pico_mem_zero_initialize(startOfData, len);
    DBG_MM_GREEN("Returning %p", startOfData);
    return startOfData;
}

/*
 * This method will be called from pico_mem_zalloc. If an appropriate slab object is found,
 * it is deleted from the RB tree and a pointer to the start of data in the slab object
 * is returned.
 */
static void*_pico_mem_find_slab(size_t len)
{
    size_t*lenptr = &len;
    size_t**doublelenptr = &lenptr;
    struct pico_tree_node*node;
    uint8_t *returnVal = NULL;

    DBG_MM_YELLOW("Finding slab with size %u", len);
    /* The compare function takes an int*** length */
    node = pico_tree_findNode(&manager->tree, &doublelenptr);

    if(node != NULL) {
        /* DBG_MM_BLUE("Found node, size = %d ", ((pico_mem_slab_node*) node->keyValue)->slab->size); */
        struct pico_mem_slab_node*slab_node = node->keyValue;
        slab_node->slab->internals.slab_block.page->slabs_free--;
        slab_node->slab->internals.slab_block.page->timestamp = 0;
        DBG_MM_BLUE("Found node, size = %u at page %p, %u free slabs left in page", slab_node->slab->internals.slab_block.page->slab_size, slab_node->slab->internals.slab_block.page, slab_node->slab->internals.slab_block.page->slabs_free);
        if(slab_node->next == NULL)
        {
            DBG_MM_BLUE("This was the last available slab object. Deleting the tree node now.");
            /* if this is the last slab object of this size in the tree, then also delete the tree_node! */


            /* pico_tree_delete(&manager->tree, &doublelenptr); */
            manager_tree_delete(&manager->tree, &doublelenptr);


        }
        else
        {
            /* Remove the pico_mem_slab_node by making the keyvalue of the pico_tree_node point to the next element. */
            slab_node->next->prev = NULL;
            node->keyValue = slab_node->next;
        }

        returnVal =  ((uint8_t*) (slab_node->slab)) + sizeof(struct pico_mem_block);
        DBG_MM_BLUE("Start of slab: %p -> start of data : %p", slab_node->slab, returnVal);
        /* Update the slab block housekeeping */
        slab_node->slab->internals.slab_block.slab_node = NULL;
        /* Zero-initialize */
        _pico_mem_zero_initialize(returnVal, len);
        /* Free the struct that was used by the linked list in the RB-tree */
        pico_mem_page0_free(slab_node);
    }

    DBG_MM_GREEN("Returning %p", returnVal);
    return returnVal;
}

/*
 * This method is called by the picotcp stack to free memory.
 */
void pico_mem_free(void*ptr)
{
    struct pico_mem_block*generic_block;
    struct pico_mem_page*page;
    /*Uncomment i for debugging!*/
    /*uint16_t i = 0;*/

    DBG_MM_YELLOW("Free called on %p", ptr);

    if(ptr == NULL) return;

    generic_block = (struct pico_mem_block*) ptr;
    generic_block--;

    if(generic_block->type == SLAB_BLOCK_TYPE)
    {
        if(generic_block->internals.slab_block.slab_node)
        {
            DBG_MM_RED("ERROR: Double free on a slab block (recovered)!");
            return;
        }

        DBG_MM_BLUE("Request to free a slab block");
        _pico_mem_free_slab_block(generic_block);
    }
    else if(generic_block->type == HEAP_BLOCK_TYPE)
    {
        if(generic_block->internals.heap_block.free == HEAP_BLOCK_FREE)
        {
            DBG_MM_RED("ERROR: Double free on a heap block (recovered)!");
            return;
        }

        DBG_MM_BLUE("Request to free a heap block");

        /* Update the page housekeeping */
        /* Update the housekeeping of the extra manager pages */
        page = manager->first_page;
        while(page != NULL)
        {
            DBG_MM_BLUE("Checking page %i at %p", i++, page);
            if(((uint8_t*) page < (uint8_t*) ptr) && ((uint8_t*) ptr < (uint8_t*) page + PICO_MEM_PAGE_SIZE))
            {
                /* DBG_MM_RED("page < ptr < page + PICO_MEM_PAGE_SIZE"); */
                /* DBG_MM_RED("%p < %p < %p", (uint8_t*) page, (uint8_t*) ptr, (uint8_t*) page + PICO_MEM_PAGE_SIZE); */
                _pico_mem_free_and_merge_heap_block(page, generic_block);
                _pico_mem_determine_max_free_space(page);
                break;
            }

            page = page->next_page;
        }
    }
    else
    {
        DBG_MM_RED("ERROR: You tried to free a pointer from which the type ( heap block or slab object ) could not be determined!!");
    }
}

/************************NEW***************************/
static void _pico_mem_reset_slab_statistics(void)
{
    slab_size_statistics[0] = 0;
    slab_size_statistics[1] = 0;
    slab_size_statistics[2] = 0;
}

static size_t _pico_mem_determine_slab_size(size_t len)
{
    DBG_MM_YELLOW("Determining slab size to use, request for %u bytes", len);
    if (len > slab_sizes[1])
    {
        slab_size_statistics[2]++;
        if(slab_size_statistics[2] > 3)
        {
            _pico_mem_reset_slab_statistics();
            if(slab_size_global != slab_sizes[2])
            {
                slab_size_global = slab_sizes[2];
            }
        }

        if(slab_size_global != slab_sizes[2])
        {
            DBG_MM_RED("Using slab size %u, but we have to use a slab size of %u for the request of %u bytes", slab_size_global, slab_sizes[2], len);
            return slab_sizes[2];
        }
    }
    else if(len > slab_sizes[0])
    {
        slab_size_statistics[1]++;
        if (slab_size_statistics[1] > 3)
        {
            _pico_mem_reset_slab_statistics();
            if(slab_size_global != slab_sizes[1])
            {
                slab_size_global = slab_sizes[1];
            }
        }

        if(len > slab_size_global)
        {
            DBG_MM_RED("Using slab size %u, but we have to use a slab size of %u for the request of %u bytes", slab_size_global, slab_sizes[1], len);
            return slab_sizes[1];
        }
    }
    else
    {
        slab_size_statistics[0]++;
        if (slab_size_statistics[0] > 3)
        {
            _pico_mem_reset_slab_statistics();
            if(slab_size_global != slab_sizes[0])
            {
                slab_size_global = slab_sizes[0];
            }
        }
    }

    DBG_MM_GREEN("Using slab size %u", slab_size_global);
    return slab_size_global;
}
/************************NEW***************************/

/*
 * This method will be called by the picotcp stack to allocate new memory.
 * If the requested size is bigger than the threshold of a slab object,
 * then the manager will try to find an appropriate slab object and return a pointer
 * to the beginning of the data in that slab object.
 *
 * If no slab objects could be found, or the requested size is less then the threshold
 * of a slab object, the manager will try to allocate a heap block and return a pointer
 * to the beginning of the data of that heap block.
 *
 * If still no memory could be found, then the manager will check again if the
 * requested size is smaller than the threshold of a slab object.
 * If so, the manager will try to find a slab object again but now ignoring the threshold.
 * By doing so, there will be a large amount of internal fragmentation, but at least the
 * memory request could be fulfilled.
 *
 * In any other case, the manager will return NULL.
 */
void*pico_mem_zalloc(size_t len)
{
    struct pico_mem_page*page;
    void*returnCandidate;
    uint32_t pagenr;
    void *ret;

    DBG_MM_YELLOW("===> pico_mem_zalloc(%i) called", len);
    len += (len % 4 == 0) ? 0 : 4 - len % 4;
    DBG_MM_YELLOW("Aligned size: %i", len);

    if(manager == NULL)
    {
        DBG_MM_RED("Invalid alloc, a memory manager hasn't been instantiated yet!");
        return NULL;
    }

    if(len > PICO_MAX_SLAB_SIZE)
    {
        DBG_MM_RED("Invalid alloc, the size you requested is larger than the maximum slab size! (%uB>%uB)", len, PICO_MAX_SLAB_SIZE);
        return NULL;
    }

    /* /////// FIND SLAB OBJECTS ///////// */
    if(len >= PICO_MIN_SLAB_SIZE)
    {
        /* feed the size into a statistic engine that determines the slabsize to use */
        /* DBG_MM_RED("Placeholder: determine correct slab size to use!"); */
        len = _pico_mem_determine_slab_size(len);
        ret = _pico_mem_find_slab(len);
        if(ret != NULL) return ret;

        /* No slab object could be found. => Init new page? */

        DBG_MM_BLUE("No free slab found, trying to create a new page (Used size = %u, max size = %u)", manager->used_size, manager->size);
        if(manager->used_size + PICO_MEM_PAGE_SIZE <= manager->size)
        {
            struct pico_mem_page*newpage = pico_zalloc(PICO_MEM_PAGE_SIZE);
            if(newpage != NULL)
            {
                manager->used_size += PICO_MEM_PAGE_SIZE;
                DBG_MM_BLUE("Created new page at %p -> used size = %u", newpage, manager->used_size);
                _pico_mem_init_page(newpage, len);
                /* Return pointer to first slab in that page */
                return _pico_mem_find_slab(len);    /* Find the new slab object! */
            }
            else
            {
                DBG_MM_RED("Not enough space to allocate a new page, even though the max size hasn't been reached yet!");
                return NULL;
            }
        }
        else
        {
            DBG_MM_RED("Not enough space to allocate a new page!");
            return NULL;
        }
    }

    /* /////// FIND HEAP BLOCKS ///////// */
    if(len < PICO_MEM_MINIMUM_OBJECT_SIZE)
        len = PICO_MEM_MINIMUM_OBJECT_SIZE;

    DBG_MM_BLUE("Searching for heap space of length %u now.", len);

    pagenr = 1;
    page = manager->first_page;

    /* The algorithm to find a heap block is based on first fit. */
    /* But when the internal fragmentation is too big, the block is split. */
    while(page != NULL)
    {
        /* DBG_MM_RED("Max free space in page %i = %i bytes", pagecounter+1, page->heap.max_free_space); */
        DBG_MM_BLUE("Max free space in page %u = %uB (page=%p)", pagenr, page->heap_max_free_space, page);
        if(len <= page->heap_max_free_space)
        {
            return _pico_mem_find_heap_block(page, len);
        }

        pagenr++;
        page = page->next_page;
    }
    /* No free heap block could be found, try to alloc a new page */
    DBG_MM_BLUE("No free heap block found, trying to create a new page (Used size = %u, max size = %u)", manager->used_size, manager->size);
    if(manager->used_size + PICO_MEM_PAGE_SIZE <= manager->size)
    {
        struct pico_mem_page*newpage = pico_zalloc(PICO_MEM_PAGE_SIZE);
        if(newpage != NULL)
        {
            manager->used_size += PICO_MEM_PAGE_SIZE;
            DBG_MM_BLUE("Created new page at %p -> used size = %u", newpage, manager->used_size);
            /* TODO: Careful, if the current slabsize is determined in another way, this needs to change too */
            _pico_mem_init_page(newpage, slab_size_global);
            returnCandidate = _pico_mem_find_heap_block(newpage, len);
            if(returnCandidate != NULL)
                return returnCandidate;
        }
        else
        {
            DBG_MM_RED("Not enough space to allocate a new page, even though the max size hasn't been reached yet!");
            return NULL;
        }
    }

    /* DBG_MM_RED("NO HEAP BLOCK FOUND!"); */

    /* /////// TRY TO FIND NEW SLAB OBJECT, BUT INCREASE SIZE ///////// */
    DBG_MM_RED("TRYING TO FIND FREE SLAB OBJECT WITH DANGER OF LARGE INTERNAL FRAGMENTATION");
    /* TODO: Careful, if the current slabsize is determined in another way, this needs to change too */
    return _pico_mem_find_slab(slab_size_global);
}
/*
 * This method frees heap space used in the manager page, or in one of the extra manager pages
 */
void pico_mem_page0_free(void*ptr)
{
    struct pico_mem_block*node = ptr;
    struct pico_mem_manager_extra*heap_page;
    /* Uncomment for debugging! */
    /* int i = 0; */

    /* TODO: should be able to merge free neighbouring blocks (??) */
    DBG_MM_YELLOW("page0_free called");

    node--;
    node->internals.heap_block.free = HEAP_BLOCK_FREE;
    /* Update the housekeeping of the extra manager pages */
    heap_page = manager->manager_extra;
    while(heap_page != NULL)
    {
        DBG_MM_BLUE("Checking extra heap page %i at %p", i++, heap_page);
        if(((uint8_t*) heap_page < (uint8_t*) ptr) && ((uint8_t*) ptr < (uint8_t*) heap_page + PICO_MEM_PAGE_SIZE))
        {
            /* DBG_MM_RED("heap_page < ptr < heap_page + PICO_MEM_PAGE_SIZE"); */
            /* DBG_MM_RED("%p < %p < %p", (uint8_t*) heap_page, (uint8_t*) ptr, (uint8_t*) heap_page + PICO_MEM_PAGE_SIZE); */
            heap_page->blocks--;
            DBG_MM_BLUE("Updating heap page housekeeping: %u->%u used blocks", heap_page->blocks + 1, heap_page->blocks);
            break;
        }

        heap_page = heap_page->next;
    }
    DBG_MM_GREEN("Heap block (located in %s) succesfully freed", (i != -1) ? "main manager page" : "extra manager page");
}

/*
 * This cleanup function must be called externally at downtime moments. A system timestamp must be passed to the function.
 * All pages and extra manager pages will be checked. If they are empty, the timestamp of the page will be updated. If the
 * page has been empty for a time longer than PICO_MEM_PAGE_LIFETIME, the page is returned to the system's control, and all
 * the housekeeping is updated.
 */
void pico_mem_cleanup(uint32_t timestamp)
{
    struct pico_mem_slab_node*slab_node;
    struct pico_tree_node*tree_node;
    struct pico_mem_block*slab_block;
    struct pico_mem_page*next_page;
    struct pico_mem_page*prev_page;
    struct pico_mem_page*page;
    struct pico_mem_manager_extra*heap_page;
    struct pico_mem_manager_extra*next;
    struct pico_mem_manager_extra*prev_heap_page;
    uint8_t*byteptr;
    int pagenr = 1;
    int i;

    DBG_MM_YELLOW("Starting cleanup with timestamp %u", timestamp);
    /* Iterate over all pages */
    page = manager->first_page;
    prev_page = NULL;
    while(page != NULL)
    {
        DBG_MM_BLUE("Checking page %i at %p", pagenr, page);
        /* Check the timestamp of the page. If it doesn't have one (0), update it with the new timestamp if the page is completely empty. */
        if(page->timestamp == 0)
        {
            if((page->heap_max_size == page->heap_max_free_space) && (page->slabs_free == page->slabs_max))
            {
                DBG_MM_BLUE("Page %i empty, updating timestamp", pagenr);
                page->timestamp = timestamp;
            }
        }
        /* If the timestamp is old enough, remove the page and all its slabs. This means we have to: */
        /* > Remove all slabs out of the RB tree */
        /* > Update the page list */
        /* > Return the page to the system's control */
        /* > Update manager housekeeping */
        else if(timestamp > page->timestamp)
        {
            if(timestamp - page->timestamp > PICO_MEM_PAGE_LIFETIME)
            {
                DBG_MM_BLUE("Page %i is empty and has exceeded the lifetime (%u > lifetime=%u)", pagenr, timestamp - page->timestamp, PICO_MEM_PAGE_LIFETIME);
                /* Remove all the slabs out of the RB tree */
                byteptr = (uint8_t*) page + sizeof(struct pico_mem_page); /* byteptr points to the start of the heap (a pico_mem_block), after page housekeeping */
                byteptr += sizeof(struct pico_mem_block); /* jump over pico_mem_block, containing the housekeeping for the heap space */
                byteptr += page->heap_max_size; /* jump over heap space, byteptr now points to the start of the slabs */
                slab_block = (struct pico_mem_block*) byteptr;
                slab_node = slab_block->internals.slab_block.slab_node;
                /* The corresponding tree_node */
                tree_node = pico_tree_findNode(&manager->tree, slab_node);
                for(i = 0; i < page->slabs_max; i++)
                {
                    DBG_MM("Removing slab %i at %p", i, slab_block);
                    if(slab_node->prev == NULL && slab_node->next == NULL)
                    {
                        DBG_MM("This node is the last node in the tree_node, removing tree_node");
                        /* slab_node is the last node in the tree leaf, delete it */


                        /* pico_tree_delete(&manager->tree, slab_node); */
                        manager_tree_delete(&manager->tree, slab_node);


                    }
                    else if(slab_node->prev == NULL)
                    {
                        DBG_MM("This node is the first node in the linked list, adjusting tree_node");
                        tree_node->keyValue = slab_node->next;
                        slab_node->next->prev = NULL;
                    }
                    else if(slab_node->next == NULL)
                    {
                        DBG_MM("This node is the last node in the linked list");
                        slab_node->prev->next = NULL;
                    }
                    else
                    {
                        DBG_MM("This node is neither the first, nor the last node in the list");
                        slab_node->prev->next = slab_node->next;
                        slab_node->next->prev = slab_node->prev;
                    }

                    pico_mem_page0_free(slab_node);
                    byteptr = (uint8_t*) slab_block + sizeof(struct pico_mem_block); /* byteptr points to the start of the slab data, after the housekeeping */
                    byteptr += page->slab_size; /* jump over the slab data, byteptr now points to the start of the next slab block */
                    slab_block = (struct pico_mem_block*) byteptr;
                    slab_node = slab_block->internals.slab_block.slab_node;
                }
                /* Update the page list */
                if(prev_page == NULL) /* prev_page == NULL when pagenr=1, or when previous pages were deleted */
                {
                    DBG_MM("Updating page list, manager->first_page = page->next_page");
                    manager->first_page = page->next_page;
                }
                else
                {
                    DBG_MM("Updating page list, prev_page->next_page = page->next_page");
                    prev_page->next_page = page->next_page;
                }

                /* Return the page to the system's control */
                next_page = page->next_page;
                DBG_MM("Freeing page, manager used size = %u", manager->used_size);
                pico_free(page);
                /* Update the manager housekeeping */
                manager->used_size -= PICO_MEM_PAGE_SIZE;
                DBG_MM("Freed page, manager used size = %u, down from %u", manager->used_size, manager->used_size + PICO_MEM_PAGE_SIZE);
                /* ITERATION */
                page = next_page;
                pagenr++;
                continue;
            }
            else
            {
                DBG_MM_BLUE("Page %i is empty, but has not exceeded the lifetime (%u < lifetime=%u)", pagenr, timestamp - page->timestamp, PICO_MEM_PAGE_LIFETIME);
            }
        }
        else /* timestamp < page->timestamp */
        {
            DBG_MM_RED("Page %i is empty, but the system timestamp < page timestamp! (%u<%u)", pagenr, timestamp, page->timestamp);
            DBG_MM_RED("Updating page %i timestamp!", pagenr);
            page->timestamp = timestamp;
        }

        pagenr++;
        prev_page = page;
        page = page->next_page;
    }
    /* Check all extra manager pages if they are empty */
    heap_page = manager->manager_extra;
    prev_heap_page = NULL;
    pagenr = 1;
    while(heap_page != NULL)
    {
        DBG_MM_BLUE("Checking extra manager page %i at %p", pagenr, heap_page);
        if(heap_page->timestamp == 0)
        {
            if( heap_page->blocks == 0 )
            {
                DBG_MM_BLUE("Extra manager page %i empty, updating timestamp", pagenr);
                heap_page->timestamp = timestamp;
            }
        }
        else if(timestamp > heap_page->timestamp)
        {
            if(timestamp - heap_page->timestamp > PICO_MEM_PAGE_LIFETIME)
            {
                DBG_MM_BLUE("Extra manager page %i empty and has exceeded the lifetime (%u > lifetime=%u)", pagenr, timestamp - heap_page->timestamp, PICO_MEM_PAGE_LIFETIME);
                /* Update the page list */
                if(prev_heap_page == NULL)
                {
                    DBG_MM("Updating page list, manager->manager_extra = heap_page->next");
                    manager->manager_extra = heap_page->next;
                }
                else
                {
                    DBG_MM("Updating page list, prev_heap_page->next = heap_page->next");
                    prev_heap_page->next = heap_page->next;
                }

                /* Return the page to the system's control */
                next = heap_page->next;
                DBG_MM("Freeing page, manager used size = %u", manager->used_size);
                pico_free(heap_page);
                /* Update the manager housekeeping */
                manager->used_size -= PICO_MEM_PAGE_SIZE;
                DBG_MM("Freed page, manager used size = %u, down from %u", manager->used_size, manager->used_size + PICO_MEM_PAGE_SIZE);
                /* ITERATION */
                heap_page = next;
                pagenr++;
                continue;
            }
            else
            {
                DBG_MM_BLUE("Page %i is empty, but has not exceeded the lifetime (%u < lifetime=%u)", pagenr, timestamp - heap_page->timestamp, PICO_MEM_PAGE_LIFETIME);
            }
        }
        else
        {
            DBG_MM_RED("Page %i is empty, but the system timestamp < page timestamp! (%u<%u)", pagenr, timestamp, heap_page->timestamp);
            DBG_MM_RED("Updating page %i timestamp!", pagenr);
            heap_page->timestamp = timestamp;
        }

        /* ITERATION */
        pagenr++;
        prev_heap_page = heap_page;
        heap_page = heap_page->next;
    }
}






#ifdef PICO_SUPPORT_MM_PROFILING
/***********************************************************************************************************************
 ***********************************************************************************************************************
   MEMORY PROFILING FUNCTIONS
 ***********************************************************************************************************************
 ***********************************************************************************************************************/

static struct pico_mem_manager*manager_profile;

static void _pico_mem_print_tree(struct pico_tree_node*root)
{
    struct pico_mem_slab_node*iterator;
    int j;

    if (root == &LEAF || root == NULL)
    {
        DBG_MM("No tree nodes at this time.\n");
        return;
    }

    iterator = (struct pico_mem_slab_node*) root->keyValue;
    DBG_MM("Tree node for size %u:\n", iterator->slab->internals.slab_block.page->slab_size);
    j = 0;
    while(iterator != NULL)
    {
        DBG_MM("\tSlab_node %i at %p:\n", j, iterator);
        DBG_MM("\t\tPrev:%p\n", iterator->prev);
        DBG_MM("\t\tNext:%p\n", iterator->next);
        DBG_MM("\t\tSlab:%p\n", iterator->slab);
        j++;
        iterator = iterator->next;
    }
    if(root->leftChild != &LEAF && root->leftChild != NULL)
        _pico_mem_print_tree(root->leftChild);

    if(root->rightChild != &LEAF && root->rightChild != NULL)
        _pico_mem_print_tree(root->rightChild);
}

void pico_mem_profile_scan_data()
{
    if(manager == NULL)
    {
        DBG_MM("No memory manager instantiated!\n");
    }
    else
    {
        int manager_pages = 0;
        int pages = 0;
        int counter = 0;
        struct pico_mem_manager_extra*heap_page;
        struct pico_mem_page*page;
        uint8_t*byteptr;
        struct pico_mem_block*mem_block;

        DBG_MM("Memory manager: %uB/%uB in use\n", manager->used_size, manager->size);
        _pico_mem_print_tree(manager->tree.root);

        /* Iterate over every extra manager page: */
        heap_page = manager->manager_extra;
        while(heap_page != NULL)
        {
            manager_pages++;
            DBG_MM("Extra manager page %i:\n\tBlocks in use: %u\n\tTimestamp: %u\n", manager_pages, heap_page->blocks, heap_page->timestamp);
            heap_page = heap_page->next;
        }
        /* Iterate over every page: */
        pages = (manager->used_size / PICO_MEM_PAGE_SIZE) - manager_pages - 1;
        page = manager->first_page;
        while(page != NULL)
        {
            counter++;
            DBG_MM("Page %i/%i:\n\tSlabsize: %u\n\tSlabs free: %u/%u\n\tTimestamp: %u\n", counter, pages, page->slab_size, page->slabs_free, page->slabs_max, page->timestamp);
            byteptr = (uint8_t*) page + sizeof(struct pico_mem_page);
            mem_block = (struct pico_mem_block*) byteptr;
            DBG_MM("\tHeap:\n");
            while(mem_block->type == HEAP_BLOCK_TYPE)
            {
                DBG_MM("\t\tBlock: size %u, %s\n", mem_block->internals.heap_block.size, (mem_block->internals.heap_block.free == HEAP_BLOCK_FREE) ? "free" : "not free");
                byteptr = (uint8_t*) mem_block + sizeof(struct pico_mem_block);
                byteptr += mem_block->internals.heap_block.size;
                mem_block = (struct pico_mem_block*) byteptr;
            }
            page = page->next_page;
        }
    }
}

void pico_mem_profile_collect_data(struct profiling_data*profiling_struct)
{
    struct pico_mem_block*mem_block;
    uint8_t*byteptr;

    profiling_struct->free_heap_space = 0;
    profiling_struct->free_slab_space = 0;
    profiling_struct->used_heap_space = 0;
    profiling_struct->used_slab_space = 0;
    if(manager != NULL)
    {
        struct pico_mem_page*page = manager->first_page;
        while(page != NULL)
        {
            profiling_struct->free_slab_space += page->slab_size * page->slabs_free;
            profiling_struct->used_slab_space += page->slab_size * page->slabs_max;

            byteptr = (uint8_t*) page + sizeof(struct pico_mem_page);
            mem_block = (struct pico_mem_block*) byteptr;

            while(mem_block->type == HEAP_BLOCK_TYPE)
            {
                if(mem_block->internals.heap_block.free == HEAP_BLOCK_FREE)
                {
                    profiling_struct->free_heap_space += mem_block->internals.heap_block.size;
                }
                else
                {
                    /* dbg("Block: size=%u\n", mem_block->internals.heap_block.size); */
                    profiling_struct->used_heap_space += mem_block->internals.heap_block.size;
                }

                byteptr += sizeof(struct pico_mem_block) + mem_block->internals.heap_block.size;
                mem_block = (struct pico_mem_block*) byteptr;
            }
            page = page->next_page;
        }
    }
}

uint32_t pico_mem_profile_used_size()
{
    if(manager != NULL)
    {
        return manager->used_size;
    }
    else
    {
        return 0;
    }
}

struct pico_mem_manager*pico_mem_profile_manager()
{
    return manager;
}
#endif /* PICO_SUPPORT_MM_PROFILING */

