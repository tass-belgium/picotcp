/* PicoTCP unit test platform */
/* How does it works:
 * 1. Define your unit test function as described in the check manual
 * 2. Add your test to the suite in the pico_suite() function
 */

#include "pico_mm.c"
#include "pico_tree.c"
#include <check.h>

volatile pico_err_t pico_err;

START_TEST (test_compare_slab_keys)
{

    uint32_t len1 = 1200;
    uint32_t len2 = 1600;
    uint32_t len3 = 1600;
    uint32_t*lenptr1;
    uint32_t*lenptr2;
    uint32_t*lenptr3;
    uint32_t**doublelenptr1;
    uint32_t**doublelenptr2;
    uint32_t**doublelenptr3;
    struct pico_mem_block*block1;
    struct pico_mem_block*block2;
    struct pico_mem_block*block3;
    struct pico_mem_slab_node*node1;
    struct pico_mem_slab_node*node2;
    struct pico_mem_slab_node*node3;

    /* Dependencies: none */
    printf("\n***************Running test_compare_slab_keys***************\n\n");
    /* Scenario's to test: */
    /* >Compare a large size with a small size */
    /* >Compare a small size with a large size */
    /* >Compare equal sizes */
    /* >Finally, compare with int pointers and with slab_nodes */

    block1 = pico_zalloc(sizeof(struct pico_mem_block));
    block1->internals.heap_block.size = 1200;
    block2 = pico_zalloc(sizeof(struct pico_mem_block));
    block2->internals.heap_block.size = 1600;
    block3 = pico_zalloc(sizeof(struct pico_mem_block));
    block3->internals.heap_block.size = 1600;
    node1 = pico_zalloc(sizeof(struct pico_mem_slab_node));
    node1->slab = block1;
    node2 = pico_zalloc(sizeof(struct pico_mem_slab_node));
    node2->slab = block2;
    node3 = pico_zalloc(sizeof(struct pico_mem_slab_node));
    node3->slab = block3;

    lenptr1 = &len1;
    lenptr2 = &len2;
    lenptr3 = &len3;
    doublelenptr1 = &lenptr1;
    doublelenptr2 = &lenptr2;
    doublelenptr3 = &lenptr3;

    ck_assert(compare_slab_keys(&node1, &node2) > 0);
    ck_assert(compare_slab_keys(&node2, &node3) == 0);
    ck_assert(compare_slab_keys(&node2, &node1) < 0);

    ck_assert(compare_slab_keys(&doublelenptr1, &doublelenptr2) > 0);
    ck_assert(compare_slab_keys(&doublelenptr2, &doublelenptr3) == 0);
    ck_assert(compare_slab_keys(&doublelenptr2, &doublelenptr1) < 0);

    ck_assert(compare_slab_keys(&doublelenptr1, &node1) == 0);
    ck_assert(compare_slab_keys(&node3, &doublelenptr1) < 0);

    pico_free(block1);
    pico_free(block2);
    pico_free(block3);
    pico_free(node1);
    pico_free(node2);
    pico_free(node3);
}
END_TEST

START_TEST (test_manager_extra_alloc)
{

    uint8_t*byteptr;
    uint8_t*byteptr1;
    uint8_t*byteptr2;
    struct pico_mem_block*block;
    size_t sizeLeft;
    size_t size = 50;

    uint8_t*data0;
    uint8_t*data1;
    uint8_t*data2;
    uint8_t*data3;

    struct pico_mem_manager_extra*heap_page;
    struct pico_mem_manager_extra*heap_page2;


    /* Dependencies: */
    /* >pico_zalloc */
    printf("\n***************Running test_manager_extra_alloc***************\n\n");
    /* Scenario's to test: */
    /* Page with enough space in it passed, space should not be split up further */
    /* Page with not enough space in it passed, manager isn't allowed to alloc further space */
    /* Page with not enough space in it passed, manager is allowed to alloc further space */
    /* Page with enough space in it passed, space should be split up further */

    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra);

    /* Housekeeping of extra manager page */
    heap_page = pico_zalloc(PICO_MEM_PAGE_SIZE);
    heap_page->blocks = 2;
    heap_page->timestamp = 12345;

    heap_page->next = NULL;
    /* Housekeeping of manager page */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->manager_extra = heap_page;
    manager->used_size = 2 * PICO_MEM_PAGE_SIZE;
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    manager->first_page = NULL;
/*
    byteptr = (uint8_t*) (heap_page+1);
    block = (pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = 100;
    sizeLeft -= sizeof(pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    byteptr += sizeof(pico_mem_block);
    byteptr += block->internals.heap_block.size;
 */
    /* First block in extra manager page, unusable due to too small size */
    byteptr = (uint8_t*) (heap_page + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(size / 2);
    sizeLeft -= sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;

    /* Second block in extra manager page, free with more than enough size */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(100 - size / 2);
    sizeLeft -= sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    byteptr1 = byteptr;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;

    /* Third block in extra manager page, not free, takes up remainder of the space, minus the space of one extra block */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    /* Size of this block is thus that only one of the two testblocks will fit in the page */
    block->internals.heap_block.size = (uint32_t)(sizeLeft - 2 * sizeof(struct pico_mem_block) - size);
    sizeLeft -= sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    byteptr2 = byteptr;

    /* Fourth block in extra manager page, free, large enough size */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));

    /* Second block will be used */
    data0 = _pico_mem_manager_extra_alloc(heap_page, size);
    /* Fourth block will be used */
    data1 = _pico_mem_manager_extra_alloc(heap_page, size);
    /* Limit the space */
    manager->size = 2 * PICO_MEM_PAGE_SIZE;
    /* No more space for another block, no more space for another page, function should return NULL */
    data2 = _pico_mem_manager_extra_alloc(heap_page, size);
    ck_assert(data2 == NULL);
    /* Allow more space */
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    /* New page will be allocated, first block in it will be used, the space will be split up properly */
    data2 = _pico_mem_manager_extra_alloc(heap_page, size);
    heap_page2 = manager->manager_extra;
    ck_assert(heap_page2 != heap_page);
    ck_assert(heap_page2->next == heap_page);
    ck_assert(manager->used_size == 3 * PICO_MEM_PAGE_SIZE);
    data3 = _pico_mem_manager_extra_alloc(heap_page2, size);

    /* Check the buildup of page 1 */
    ck_assert(heap_page->blocks == 4);
    ck_assert(heap_page->timestamp == 0);

    block = (struct pico_mem_block*) byteptr1;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == 100 - size / 2);
    ck_assert(data0 == (byteptr1 + sizeof(struct pico_mem_block)));

    block = (struct pico_mem_block*) byteptr2;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == size);
    ck_assert(data1 == (byteptr2 + sizeof(struct pico_mem_block)));

    /* Check the buildup of page 2 */
    ck_assert(heap_page2->blocks == 2);
    ck_assert(heap_page2->timestamp == 0);

    byteptr = (uint8_t*) (heap_page2 + 1);
    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra);
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == size);
    ck_assert(data2 == (byteptr + sizeof(struct pico_mem_block)));
    sizeLeft -= sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;

    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == size);
    ck_assert(data3 == (byteptr + sizeof(struct pico_mem_block)));
    sizeLeft -= sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;

    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block->internals.heap_block.size == sizeLeft - sizeof(struct pico_mem_block));

    /* DEPENDENCY ON CLEANUP */
    pico_mem_deinit();
}
END_TEST

START_TEST (test_page0_zalloc)
{
    uint8_t*byteptr;
    struct pico_mem_block*block;
    size_t size1 = 50;
    uint8_t*temp;
    size_t sizeLeft;
    struct pico_mem_manager_extra*heap_page;

    /* Dependencies: */
    /* >pico_zalloc */
    /* >_pico_mem_manager_extra_alloc() */
    printf("\n***************Running test_page0_zalloc***************\n\n");

    /* Scenario's to test: */
    /* Empty block somewhere that doesn't fit the needed space */
    /* Empty block somewhere that exactly fits the needed space */
    /* NOTE: Splitting up isn't implemented, assessed as not necessary */
    /* Large empty block in the middle of the heap */
    /* Empty space at the end that needs splitting up */

    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager);

    /* Memory manager housekeeping */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    byteptr = (uint8_t*) (manager + 1);
    /* Block 1: not free, size1 */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)size1;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Block 2: free, size1/2 */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(size1 / 2);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Block 3: free, size1 */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)size1;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Block 4: free, size1*2 */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(size1 * 2);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Rest of the heap space (free) */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));

    pico_mem_page0_zalloc(size1);
    pico_mem_page0_zalloc(size1);
    pico_mem_page0_zalloc((size_t)size1);
    sizeLeft -= sizeof(struct pico_mem_block);
    sizeLeft -= size1;

    /* Check buildup of heap space */
    byteptr = (uint8_t*) (manager + 1);
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_FREE);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block->internals.heap_block.size == sizeLeft - sizeof(struct pico_mem_block));

    /* Now, fill up the rest of the space minus a few bytes, so that the space can't be split up further */
    /* pico_mem_page0_zalloc(sizeLeft - sizeof(struct pico_mem_block) - 3); */
    pico_mem_page0_zalloc(sizeLeft - sizeof(struct pico_mem_block) - 3);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == sizeLeft - sizeof(struct pico_mem_block));

    pico_free(manager);

    /* Extra scenario's: */
    /* No more space left in the main heap, a second page doesn't exist yet */
    /* No more space left in the main heap, a second heap_page exists (space left doesn't matter, extra_alloc handles that) */

    /* Manager housekeeping */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->manager_extra = NULL;
    manager->used_size = PICO_MEM_PAGE_SIZE;
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager);

    /* Heap space full */
    byteptr = (uint8_t*) (manager + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));

    /* Limit manager space */
    manager->size = PICO_MEM_PAGE_SIZE;
    /* Try to alloc another block, no more space in manager heap, no more pages can be created: NULL should be returned */
    temp = pico_mem_page0_zalloc(size1);
    ck_assert(temp == NULL);
    /* Allow more space usage */
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    /* Alloc 2 more blocks */
    pico_mem_page0_zalloc(size1);
    pico_mem_page0_zalloc(size1);

    /* Check extra manager page housekeeping */
    ck_assert(manager->manager_extra != NULL);
    heap_page = manager->manager_extra;

    ck_assert(heap_page->blocks == 2);
    ck_assert(heap_page->next == NULL);
    ck_assert(heap_page->timestamp == 0);
    ck_assert(manager->used_size == 2 * PICO_MEM_PAGE_SIZE);

    /* Check extra manager page heap */
    block = (struct pico_mem_block*) (heap_page + 1);
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == size1);
    byteptr = (uint8_t*) block;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += size1;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.size == size1);

    pico_free(manager->manager_extra);
    pico_free(manager);
}
END_TEST

START_TEST (test_init_page)
{
    uint8_t*byteptr;
    uint32_t*lenptr;
    uint32_t**doublelenptr = &lenptr;
    int vlag = 0;
    int i;
    struct pico_mem_block*intermediate_heap_block;
    struct pico_mem_page*page0;
    struct pico_mem_block*block;
    struct pico_mem_page*page1;
    struct pico_mem_page*page2;
    struct pico_mem_block*slab;
    struct pico_tree_node*tree_node;
    struct pico_mem_slab_node*slab_node;
    uint32_t slabsize1;
    uint32_t slabsize2;

    /* Dependencies: */
    /* >picotree_findNode */
    /* >pico_mem_page0_zalloc */
    printf("\n***************Running test_init_page***************\n\n");

    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->first_page = page0;
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 2 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;
    page0->next_page = NULL;

    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block);

    page1 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page2 = pico_zalloc(PICO_MEM_PAGE_SIZE);

    slabsize1 = PICO_MEM_DEFAULT_SLAB_SIZE;
    /* Slabsize 975 => 4 slab blocks fit in the page with 44 heap size */
    /* with a minimum heap size of 100, one slab block will be used as heapspace */
    slabsize2 = 975;

    _pico_mem_init_page(page1, slabsize1);
    _pico_mem_init_page(page2, slabsize2);

    /* Check the housekeeping of page1 */
    ck_assert(page1->slab_size == slabsize1);
    ck_assert(page1->slabs_max == (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + slabsize1));
    ck_assert(page1->slabs_free == page1->slabs_max);
    ck_assert(page1->timestamp == 0);
    ck_assert(page1->heap_max_size == (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - page1->slabs_max * (sizeof(struct pico_mem_block) + slabsize1)));
    ck_assert(page1->heap_max_free_space == page1->heap_max_size);

    /* Check the housekeeping of page2 */
    ck_assert(page2->slab_size == slabsize2);
    ck_assert(page2->slabs_max == (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + slabsize2));
    ck_assert(page2->slabs_free == page2->slabs_max);
    ck_assert(page2->timestamp == 0);
    ck_assert(page2->heap_max_size == (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - page2->slabs_max * (sizeof(struct pico_mem_block) + slabsize2)));
    ck_assert(page2->heap_max_free_space == page2->heap_max_size);

    /* Check the housekeeping of the manager, and the page linked list */
    ck_assert(manager->first_page == page2);
    ck_assert(page2->next_page == page1);
    ck_assert(page1->next_page == page0);
    ck_assert(page0->next_page == NULL);

    /* Check the slab_node double linked list for all slabs of page1 */
    byteptr = (uint8_t*) (page1 + 1);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += page1->heap_max_size;
    slab = (struct pico_mem_block*) byteptr;

    lenptr = &slabsize1;
    tree_node = pico_tree_findNode(&manager->tree, &doublelenptr);
    ck_assert(tree_node != NULL);
    slab_node = tree_node->keyValue;
    while(slab_node != NULL)
    {
        if(slab_node->slab == slab)
        {
            vlag = 1;
            break;
        }

        slab_node = slab_node->next;
    }
    ck_assert(vlag != 0);
    vlag = 0;
    for(i = 0; i < page1->slabs_max - 1; i++)
    {
        byteptr += sizeof(struct pico_mem_block);
        byteptr += page1->slab_size;
        slab = (struct pico_mem_block*) byteptr;
        slab_node = tree_node->keyValue;
        while(slab_node != NULL)
        {
            if(slab_node->slab == slab)
            {
                vlag = 1;
                break;
            }

            slab_node = slab_node->next;
        }
        ck_assert(vlag != 0);
        vlag = 0;
    }
    /* Check the slab_node double linked list for all slabs of page2 */
    byteptr = (uint8_t*) (page2 + 1);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += page2->heap_max_size;
    slab = (struct pico_mem_block*) byteptr;

    lenptr = &slabsize2;
    tree_node = pico_tree_findNode(&manager->tree, &doublelenptr);
    ck_assert(tree_node != NULL);
    slab_node = tree_node->keyValue;
    while(slab_node != NULL)
    {
        if(slab_node->slab == slab)
        {
            vlag = 1;
            break;
        }

        slab_node = slab_node->next;
    }
    ck_assert(vlag != 0);
    vlag = 0;
    for(i = 0; i < page2->slabs_max - 1; i++)
    {
        byteptr += sizeof(struct pico_mem_block);
        byteptr += page2->slab_size;
        slab = (struct pico_mem_block*) byteptr;
        slab_node = tree_node->keyValue;
        while(slab_node != NULL)
        {
            if(slab_node->slab == slab)
            {
                vlag = 1;
                break;
            }

            slab_node = slab_node->next;
        }
        ck_assert(vlag != 0);
        vlag = 0;
    }
    /* DEPENDENCY ON CLEANUP */
    pico_mem_deinit();

    /* Extra scenario: Managerheap almost full (enough space for a slab_node, but not the necessary tree node), try to init a page */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->first_page = page0;
    manager->size = 3 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 3 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;
    page0->next_page = NULL;

    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block) - (sizeof(struct pico_mem_block) + sizeof(struct pico_tree_node)) - (sizeof(struct pico_mem_block) + sizeof(struct pico_mem_slab_node));
    byteptr = (uint8_t*) (block + 1);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = sizeof(struct pico_mem_slab_node);
    intermediate_heap_block = block;
    byteptr = (uint8_t*) (block + 1);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = sizeof(struct pico_tree_node);

    page1 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    _pico_mem_init_page(page1, slabsize1);

    /* Check the housekeeping of page1 */
    ck_assert(page1->slab_size == slabsize1);
    ck_assert(page1->slabs_max == 0);
    ck_assert(page1->slabs_free == page1->slabs_max);
    ck_assert(page1->timestamp == 0);
    ck_assert(page1->heap_max_size == (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - 2 * (sizeof(struct pico_mem_block) + slabsize1)));
    ck_assert(page1->heap_max_free_space == page1->heap_max_size);
    ck_assert(page1->next_page == page0);
    ck_assert(intermediate_heap_block->internals.heap_block.free == HEAP_BLOCK_FREE);

    /* Extra scenario: Managerheap almost full (enough space for a slab_node and a tree node), try to init a page */
    manager->first_page = page0;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    _pico_mem_init_page(page1, slabsize1);

    /* Check the housekeeping of page1 */
    ck_assert(page1->slab_size == slabsize1);
    ck_assert(page1->slabs_max == 1);
    ck_assert(page1->slabs_free == page1->slabs_max);
    ck_assert(page1->timestamp == 0);
    ck_assert(page1->heap_max_size == (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - 2 * (sizeof(struct pico_mem_block) + slabsize1)));
    ck_assert(page1->heap_max_free_space == page1->heap_max_size);
    ck_assert(page1->next_page == page0);
    ck_assert(intermediate_heap_block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);

    /* DEPENDENCY ON CLEANUP */
    pico_mem_deinit();
}
END_TEST

START_TEST (test_mem_init_whitebox)
{
    struct pico_mem_page*page;
    int amountOfSlabs;

    /* Dependencies: */
    /* >pico_zalloc */
    /* >_pico_mem_init_page */
    /* >PICO_FREE */
    printf("\n***************Running test test_mem_init_whitebox***************\n\n");

    /* No manager should be instantiated */
    ck_assert(manager == NULL);

    /* Init memory segment that is too small */
    pico_err = 0;
    pico_mem_init(2);
    ck_assert(pico_err == PICO_ERR_ENOMEM);
    ck_assert(manager == NULL);

    /* Init 10 pages of memory */
    pico_err = 0;
    pico_mem_init(10 * PICO_MEM_PAGE_SIZE);
    ck_assert(pico_err == 0);

    ck_assert(manager != NULL);
    ck_assert(manager->first_page != NULL);
    ck_assert(manager->manager_extra == NULL);
    ck_assert(manager->size == 10 * PICO_MEM_PAGE_SIZE);
    ck_assert(manager->used_size == 2 * PICO_MEM_PAGE_SIZE);

    page = manager->first_page;
    amountOfSlabs = (PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block)) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(page->heap_max_size == (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - ((size_t)amountOfSlabs) * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    ck_assert(page->heap_max_free_space == page->heap_max_size);
    ck_assert(page->next_page == NULL);
    ck_assert(page->slab_size == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(page->slabs_max == amountOfSlabs);
    /* printf("free = %u ?= %u = max\n", page->slabs_free, page->slabs_max); */
    ck_assert(page->slabs_free == page->slabs_max);

    pico_mem_deinit();
}
END_TEST

START_TEST (test_free_and_merge_heap_block)
{

    uint8_t*byteptr;
    struct pico_mem_block*block;
    uint16_t size = 50;
    uint32_t sizeLeft;
    struct pico_mem_block*block1;
    struct pico_mem_block*block2;
    struct pico_mem_block*block3;
    struct pico_mem_block*block4;
    struct pico_mem_page*page;

    /* Dependencies: none */
    printf("\n***************Running test_free_and_merge_heap_block***************\n\n");

    /* Scenario's to test: Structure: |block1|block2|block3|block4|-------|slabs */
    /* free block1 (no merging) */
    /* free block2, check whitespace in block1 (merging before the block) */
    /* free block4, check whitespace after block3 (merging after the block) */
    /* free block3, check whitespace in block1 (merging before and after the block) */


    page = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    page->heap_max_free_space = page->heap_max_size;
    sizeLeft = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Block 1: */
    byteptr = (uint8_t*) (page + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block1 = block;
    /* Block 2: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block2 = block;
    /* Block 3: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block3 = block;
    /* Block 4: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block4 = block;
    /* Free space: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    /* Slab block 1 housekeeping */
    block = (struct pico_mem_block*) byteptr;
    block->type = SLAB_BLOCK_TYPE;
    /* Rest: don't care */

    /* Free Block1: */
    _pico_mem_free_and_merge_heap_block(page, block1);
    ck_assert(block1->type == HEAP_BLOCK_TYPE);
    ck_assert(block1->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block1->internals.heap_block.size == size);

    /* Free Block2: */
    _pico_mem_free_and_merge_heap_block(page, block2);
    ck_assert(block1->type == HEAP_BLOCK_TYPE);
    ck_assert(block1->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block1->internals.heap_block.size == sizeof(struct pico_mem_block) + (size_t)(2 * size));

    /* Free Block4: */
    _pico_mem_free_and_merge_heap_block(page, block4);
    ck_assert(block4->type == HEAP_BLOCK_TYPE);
    ck_assert(block4->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block4->internals.heap_block.size == sizeof(struct pico_mem_block) + size + sizeLeft);

    /* Free Block3: */
    _pico_mem_free_and_merge_heap_block(page, block3);
    ck_assert(block1->type == HEAP_BLOCK_TYPE);
    ck_assert(block1->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block1->internals.heap_block.size == page->heap_max_size);
    /* printf("page->heap_max_size=%u ?= block1.size=%u\n", page->heap_max_size, block1->internals.heap_block.size); */

    pico_free(page);

    /* Additional scenario to test: |block1|block2|block3|slabs */
    page = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    page->heap_max_free_space = page->heap_max_size;
    sizeLeft = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Block 1: */
    byteptr = (uint8_t*) (page + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block) - 2 * (sizeof(struct pico_mem_block) + size));
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block1 = block;
    /* Block 2: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block2 = block;
    /* Block 3: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block3 = block;
    /* Slab block 1 housekeeping */
    block = (struct pico_mem_block*) byteptr;
    block->type = SLAB_BLOCK_TYPE;
    /* Rest: don't care */

    /* Free block3 */
    _pico_mem_free_and_merge_heap_block(page, block3);
    ck_assert(block3->type == HEAP_BLOCK_TYPE);
    ck_assert(block3->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block3->internals.heap_block.size == size);

    /* Free block2 */
    _pico_mem_free_and_merge_heap_block(page, block2);
    ck_assert(block2->type == HEAP_BLOCK_TYPE);
    ck_assert(block2->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block2->internals.heap_block.size == size + sizeof(struct pico_mem_block) + size);

    /* Free block1 */
    _pico_mem_free_and_merge_heap_block(page, block1);
    ck_assert(block1->type == HEAP_BLOCK_TYPE);
    ck_assert(block1->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block1->internals.heap_block.size == page->heap_max_free_space);

    pico_free(page);
}
END_TEST

START_TEST (test_determine_max_free_space)
{
    uint32_t temp;
    uint8_t*byteptr;
    struct pico_mem_block*block;
    uint16_t size = 50;
    uint32_t sizeLeft;
    struct pico_mem_block*block1;
    struct pico_mem_block*block2;
    struct pico_mem_block*block3;
    struct pico_mem_block*block4;
    struct pico_mem_page*page;

    /* Dependencies: none */
    printf("\n***************Running test_determine_max_free_space***************\n\n");

    /* Scenario's to test: Structure: |size 50 f|size 100 nf|size 25 f|size 75 nf|nf|slabs */
    /* block4 with size 100 becomes f, previous max free size 50 */

    /* Page housekeeping */
    page = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    page->heap_max_free_space = size;
    sizeLeft = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Block 1: */
    byteptr = (uint8_t*) (page + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block1 = block;
    /* Block 2: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(2 * size);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block2 = block;
    /* Block 3: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = size / 2;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block3 = block;
    /* Block 4: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(3 * size / 2);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block4 = block;
    /* Rest of the space */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    /* Slab block 1 housekeeping */
    block = (struct pico_mem_block*) byteptr;
    block->type = SLAB_BLOCK_TYPE;
    /* Rest: don't care */

    ck_assert(page->heap_max_free_space == size);
    _pico_mem_determine_max_free_space(page);
    ck_assert(page->heap_max_free_space == 3 * size / 2);

    /* All blocks full: max_free_space = 0 */
    block1->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block2->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block3->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block4->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    temp = _pico_mem_determine_max_free_space(page);
    ck_assert(temp == 0);
    ck_assert(page->heap_max_free_space == 0);

    pico_free(page);
}
END_TEST

START_TEST (test_free_slab_block)
{

    struct pico_mem_page*page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    struct pico_mem_page*page1 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    struct pico_mem_slab_node*slab_node;
    struct pico_mem_slab_node*original_slab_node;
    struct pico_mem_block*block;
    struct pico_mem_block*slab_block1;
    struct pico_mem_block*original_slab_block;
    struct pico_mem_block*slab_block2;
    struct pico_tree_node*tree_node;
    uint32_t size = 900;
    uint32_t*lenptr;
    uint32_t**doublelenptr;
    uint8_t*byteptr;


    /* Dependencies: */
    /* >pico_mem_page0_zalloc */
    /* >pico_tree_findNode */
    /* >pico_tree_insert */
    printf("\n***************Running test_free_slab_block***************\n\n");

    /* Scenario's to test: */
    /* Freeing a block with an existing pico_tree_node */
    /* Freeing a block without an existing pico_tree_node */

    /* Manager and page housekeepings */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);


    manager->first_page = page0;
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 3 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;
    page0->next_page = page1;
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;

    page1->next_page = NULL;
    page1->slab_size = size;
    page1->slabs_max = 4;
    page1->slabs_free = 0;
    lenptr = &size;
    doublelenptr = &lenptr;

    /* Manager heap space available */
    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block);

    /* Page 0: one slab free (slab_node exists in tree, for this size) */
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->slabs_max = 2;
    page0->slabs_free = 1;
    original_slab_block = pico_zalloc(sizeof(struct pico_mem_block));
    original_slab_block->type = SLAB_BLOCK_TYPE;
    original_slab_block->internals.slab_block.page = page0;
    original_slab_node = pico_mem_page0_zalloc(sizeof(struct pico_mem_slab_node));
    original_slab_block->internals.slab_block.slab_node = original_slab_node;
    original_slab_node->slab = original_slab_block;
    original_slab_node->prev = NULL;
    original_slab_node->next = NULL;
    /* pico_tree_insert(&manager->tree, original_slab_node); */
    manager_tree_insert(&manager->tree, original_slab_node);

    /* Page 0: one slab not free */
    slab_block1 = pico_zalloc(sizeof(struct pico_mem_block));
    slab_block1->type = SLAB_BLOCK_TYPE;
    slab_block1->internals.slab_block.page = page0;
    slab_block1->internals.slab_block.slab_node = NULL;

    /* Page 1: all slabs not free, this one will be freed (no node in the tree for this size) */
    slab_block2 = pico_zalloc(sizeof(struct pico_mem_block));
    slab_block2->type = SLAB_BLOCK_TYPE;
    slab_block2->internals.slab_block.page = page1;
    slab_block2->internals.slab_block.slab_node = NULL;

    /* Free slabs, check page housekeepings */
    _pico_mem_free_slab_block(slab_block1);
    _pico_mem_free_slab_block(slab_block2);
    ck_assert(page0->slabs_free == page0->slabs_max);
    ck_assert(page1->slabs_free == 1);

    /* Check the pico_tree, two nodes should exist, one with 2 slab_nodes, the other with 1 slab_node */
    tree_node = pico_tree_findNode(&manager->tree, original_slab_node);
    ck_assert(tree_node != NULL);
    ck_assert(tree_node->keyValue != NULL);
    slab_node = (struct pico_mem_slab_node*) tree_node->keyValue;
    ck_assert(slab_node->prev == NULL);
    ck_assert(slab_node->next == original_slab_node);
    ck_assert(slab_node->slab == slab_block1);
    ck_assert(slab_node->next->prev == slab_node);
    ck_assert(slab_node->next->next == NULL);
    ck_assert(slab_node->next->slab == original_slab_block);

    tree_node = pico_tree_findNode(&manager->tree, &doublelenptr);
    ck_assert(tree_node != NULL);
    ck_assert(tree_node->keyValue != NULL);
    slab_node = (struct pico_mem_slab_node*) tree_node->keyValue;
    ck_assert(slab_node->prev == NULL);
    ck_assert(slab_node->next == NULL);
    ck_assert(slab_node->slab == slab_block2);

    pico_free(slab_block1);
    pico_free(slab_block2);
    pico_free(original_slab_block);
    pico_mem_deinit();

    /* Extra scenario: Managerheap almost full (enough space for a slab_node, but not the necessary tree node), try to free the slab block */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->first_page = page0;
    manager->size = 2 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 2 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;
    page0->next_page = NULL;

    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block) - (sizeof(struct pico_mem_block) + sizeof(struct pico_mem_slab_node));
    byteptr = (uint8_t*) (block + 1);
    byteptr += block->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = sizeof(struct pico_mem_slab_node);

    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->slabs_max = 2;
    page0->slabs_free = 1;
    slab_block1 = pico_zalloc(sizeof(struct pico_mem_block));
    slab_block1->type = SLAB_BLOCK_TYPE;
    slab_block1->internals.slab_block.page = page0;
    slab_block1->internals.slab_block.slab_node = NULL;

    _pico_mem_free_slab_block(slab_block1);

    /* Check the housekeeping of page0 */
    ck_assert(page0->slab_size == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(page0->slabs_max == 2);
    ck_assert(page0->slabs_free == 2);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(manager->tree.root == &LEAF);

    /* Extra scenario: Managerheap full (not enough space for the slab_node), try to free the slab block */
    block->internals.heap_block.size = sizeof(struct pico_mem_slab_node) - 1;
    page0->slabs_free = 1;

    _pico_mem_free_slab_block(slab_block1);

    /* Check the housekeeping of page0 */
    ck_assert(page0->slab_size == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(page0->slabs_max == 2);
    ck_assert(page0->slabs_free == 2);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_FREE);

    pico_free(slab_block1);
    /* DEPENDENCY ON CLEANUP */
    pico_mem_deinit();
}
END_TEST

START_TEST (test_zero_initialize)
{

    size_t i;
    size_t size = 100;
    size_t leftBound = 5;
    size_t rightBound = 5;
    size_t uninitialized = 0;
    size_t initialized = 0;
    char*bytestream;

    /* Dependencies: none */
    printf("\n***************Running test_zero_initialize***************\n\n");

    /* Scenario's to test: */
    /* >Zero-initializing a NULL pointer */
    /* >Zero-initializing a piece of memory like this: 11111|111111111111111111111|11111 => 11111|0000000000000000000000|11111 */

    bytestream = pico_zalloc(size);
    memset(bytestream, 'a', size);

    _pico_mem_zero_initialize(bytestream + leftBound, size - leftBound - rightBound);
    for(i = 0; i < size; i++)
    {
        if(i < leftBound || i >= size - rightBound)
        {
            /* printf("Bytestream[%i] = '%c' ?= '%c'\n", i, bytestream[i], 'a'); */
            ck_assert(bytestream[i] == 'a');
            uninitialized++;
        }
        else
        {
            /* printf("Bytestream[%i] = '%c' ?= '%c'\n", i, bytestream[i], 0); */
            ck_assert(bytestream[i] == 0);
            initialized++;
        }
    }
    ck_assert(uninitialized == leftBound + rightBound);
    ck_assert(initialized == size - leftBound - rightBound);

    pico_free(bytestream);
}
END_TEST

START_TEST (test_find_heap_block)
{

    uint8_t*byteptr;
    struct pico_mem_block*block;
    uint16_t size = 50;
    uint32_t sizeLeft;
    uint8_t*noData;
    uint32_t block2Size;
    uint8_t*startOfData2;
    uint8_t*startOfData1;
    struct pico_mem_block*block2;
    struct pico_mem_block*block4;
    struct pico_mem_page*page;

    /* Dependencies: */
    /* pico_mem_zero_initialize */
    /* pico_mem_determine_max_free_space */
    printf("\n***************Running test_find_heap_block***************\n\n");

    /* Scenario's to test: Structure: [size 25 f| size 50 nf | size 60 f | size 50 nf | free space] */
    /* >Searching for a heap block of len > max_free_space */
    /* >Searching for a heap block of len < max_free_space, block cannot be split up in smaller blocks */
    /* >Searching for a heap block of len < max_free_space, block split up in smaller blocks */

    /* Page housekeeping */
    page = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    page->heap_max_free_space = page->heap_max_size;
    sizeLeft = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Block 0: */
    byteptr = (uint8_t*) (page + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = size / 2;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Block 1: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Block 2: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(size + size / 5);
    block2Size = block->internals.heap_block.size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block2 = block;
    /* Block 3: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    /* Free space: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    block4 = block;
    /* Slab block 1 housekeeping */
    block = (struct pico_mem_block*) byteptr;
    block->type = SLAB_BLOCK_TYPE;
    /* Rest: don't care */

    page->heap_max_free_space = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));
    noData = _pico_mem_find_heap_block(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    startOfData1 = _pico_mem_find_heap_block(page, size);
    startOfData2 = _pico_mem_find_heap_block(page, size);

    ck_assert(noData == NULL);

    ck_assert(block2->type == HEAP_BLOCK_TYPE);
    ck_assert(block2->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block2->internals.heap_block.size == block2Size);
    ck_assert((uint8_t*) (block2 + 1) == startOfData1);

    ck_assert(block4->type == HEAP_BLOCK_TYPE);
    ck_assert(block4->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);
    ck_assert(block4->internals.heap_block.size == size);
    ck_assert((uint8_t*) (block4 + 1) == startOfData2);

    byteptr = (uint8_t*) (block4 + 1);
    byteptr += block4->internals.heap_block.size;
    sizeLeft -= block4->internals.heap_block.size;
    block = (struct pico_mem_block*) byteptr;
    ck_assert(block->type == HEAP_BLOCK_TYPE);
    ck_assert(block->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block->internals.heap_block.size == sizeLeft - sizeof(struct pico_mem_block));

    pico_free(page);
}
END_TEST

START_TEST (test_find_slab)
{
    uint8_t*startOfData2;
    uint8_t*noData;
    uint32_t size = 900;
    uint8_t*startOfData1;
    struct pico_mem_block*slab_block1;
    struct pico_mem_block*slab_block2;
    struct pico_mem_page*page0;
    struct pico_mem_block*block;
    struct pico_mem_slab_node*slab_node1;
    struct pico_mem_slab_node*slab_node2;

    /* Dependencies: */
    /* pico_tree_findNode */
    /* pico_tree_delete */
    /* pico_mem_zero_initialize */
    /* pico_mem_page0_free */
    printf("\n***************Running test_find_slab***************\n\n");

    /* Scenario's to test */
    /* >The size you request has no slab_nodes available, it returns NULL */
    /* >The size you request has multiple slab nodes available, it returns one */
    /* >The size you request has one slab node available, it returns it and deletes the tree_node */

    /* Manager housekeeping */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->first_page = page0;
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 2 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;

    /* Manager heap: free */
    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block);

    /* Page 0 housekeeping */
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->slabs_max = 2;
    page0->slabs_free = 2;
    page0->timestamp = 12345;
    page0->next_page = NULL;

    /* Build tree with two slab nodes */
    slab_block1 = pico_zalloc(sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE);
    slab_block1->type = SLAB_BLOCK_TYPE;
    slab_block1->internals.slab_block.page = page0;
    slab_node1 = pico_mem_page0_zalloc(sizeof(struct pico_mem_slab_node));
    slab_block1->internals.slab_block.slab_node = slab_node1;
    slab_node1->slab = slab_block1;
    slab_node1->prev = NULL;
    /* pico_tree_insert(&manager->tree, slab_node1); */
    manager_tree_insert(&manager->tree, slab_node1);

    slab_block2 = pico_zalloc(sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE);
    slab_block2->type = SLAB_BLOCK_TYPE;
    slab_block2->internals.slab_block.page = page0;
    slab_node2 = pico_mem_page0_zalloc(sizeof(struct pico_mem_slab_node));
    slab_node1->next = slab_node2;
    slab_block2->internals.slab_block.slab_node = slab_node2;
    slab_node2->slab = slab_block2;
    slab_node2->prev = slab_node1;
    slab_node2->next = NULL;

    /* Find slab with a size for which no tree_node exists */
    noData = _pico_mem_find_slab(size);
    /* Find the existing slabs */
    startOfData1 = _pico_mem_find_slab(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(page0->slabs_free == 1);
    ck_assert(page0->timestamp == 0);
    startOfData2 = _pico_mem_find_slab(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(page0->slabs_free == 0);

    ck_assert(noData == NULL);
    /* printf("startOfData1 = %p ?= %p\n", startOfData1, ((uint8_t*) (slab_block1)) + sizeof(pico_mem_block)); */
    ck_assert(startOfData1 == ((uint8_t*) (slab_block1)) + sizeof(struct pico_mem_block));
    /* printf("startOfData2 = %p ?= %p\n", startOfData2, ((uint8_t*) (slab_block2)) + sizeof(pico_mem_block)); */
    ck_assert(startOfData2 == ((uint8_t*) (slab_block2)) + sizeof(struct pico_mem_block));

    /* printf("root=%p, LEAF=%p\n", manager->tree.root, &LEAF); */
    /* TODO: ????? */
    ck_assert(manager->tree.root == &LEAF);

    /* DEPENDENCY ON CLEANUP */
    pico_mem_deinit();
    pico_free(slab_block1);
    pico_free(slab_block2);
}
END_TEST

START_TEST (test_free)
{
    uint8_t*byteptr;
    uint32_t sizeLeft2;
    uint32_t sizeLeft1;
    uint32_t size = 50;
    struct pico_mem_block*block;
    struct pico_mem_block*block1;
    struct pico_mem_block*block2;
    struct pico_mem_page*page1;
    struct pico_mem_page*page0;
    struct pico_mem_block*slab_block1;

    /* Dependencies */
    /* >_pico_mem_free_slab_block */
    /* >_pico_mem_free_and_merge_heap_block */
    /* >_pico_mem_determine_max_free_space */

    printf("\n***************Running test_free***************\n\n");
    /* Scenario's: */
    /* Request to free a slab block: pico_mem_free_slab_block must be called => cover one case, if it works, then the forwarding has happened correctly */
    /* Request to free a heap block: correct page must be determined and the corresponding heap functions must be called => cover 2 cases in different pages to verify the page search */

    /* Manager housekeeping */
    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page1 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->first_page = page0;
    manager->size = 10 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 3 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;

    /* Manager heap: free */
    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block);

    /* Page 0 housekeeping */
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->timestamp = 12345;
    page0->next_page = page1;
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page0->slabs_free = page0->slabs_max;
    page0->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page0->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    page0->heap_max_free_space = page0->heap_max_size;
    sizeLeft1 = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page0->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Page 1 housekeeping */
    page1->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page1->timestamp = 12345;
    page1->next_page = NULL;
    page1->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page1->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page1->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page1->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    page1->heap_max_free_space = page1->heap_max_size;
    sizeLeft2 = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page1->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Set up the slab block */
    slab_block1 = pico_zalloc(sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE);
    slab_block1->type = SLAB_BLOCK_TYPE;
    slab_block1->internals.slab_block.page = page0;
    slab_block1->internals.slab_block.slab_node = NULL;
    page0->slabs_free--;
    /*
       pico_mem_slab_node* slab_node1 = pico_mem_page0_zalloc(sizeof(pico_mem_slab_node));
       slab_block1->internals.slab_block.slab_node = slab_node1;
       slab_node1->slab = slab_block1;
       slab_node1->prev = NULL;
       slab_node1->next = NULL;
       pico_tree_insert(&manager->tree, slab_node1);
     */

    /* Set up the two heap blocks */
    /* Block 1: */
    byteptr = (uint8_t*) (page0 + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft1 -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft1 -= block->internals.heap_block.size;
    block1 = block;
    /* Free space: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft1 - sizeof(struct pico_mem_block));
    sizeLeft1 -= (uint32_t)sizeof(struct pico_mem_block);
    byteptr += (uint32_t)sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    /* Block 2: */
    byteptr = (uint8_t*) (page1 + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft2 -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft2 -= block->internals.heap_block.size;
    block2 = block;
    /* Free space: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft2 - sizeof(struct pico_mem_block));
    sizeLeft2 -= (uint32_t)sizeof(struct pico_mem_block);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;

    /* Free the slab block and check it */
    ck_assert(page0->slabs_free == page0->slabs_max - 1);
    pico_mem_free(slab_block1 + 1);
    ck_assert(page0->slabs_free == page0->slabs_max);

    /* Free heap block 1 and check it */
    pico_mem_free(block1 + 1);
    ck_assert(block1->type == HEAP_BLOCK_TYPE);
    ck_assert(block1->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block1->internals.heap_block.size != size);
    ck_assert(block2->internals.heap_block.free == HEAP_BLOCK_NOT_FREE);

    /* Free heap block 2 and check it */
    pico_mem_free(block2 + 1);
    ck_assert(block2->type == HEAP_BLOCK_TYPE);
    ck_assert(block2->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(block2->internals.heap_block.size != size);

    /* DEPENDENCY ON CLEANUP */
    pico_mem_deinit();
    pico_free(slab_block1);
}
END_TEST

START_TEST (test_determine_slab_size)
{
    uint32_t slab_size = 1000;
    uint32_t slab_size2 = 1400;
    size_t result;

    /* Dependencies: */
    /* >_pico_mem_reset_slab_statistics */
    printf("\n***************Running test_determine_slab_size***************\n\n");
    /* Scenario's to test: */
    /* 1: Asking for another slabsize 3 times => switch slab size */
    /* 2: Asking for a bigger slab size => return the bigger slab size, but don't switch the default yet */
    /* 3: After 3 times, switch the size again */

    _pico_mem_reset_slab_statistics();
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);

    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == 1200);
    ck_assert(slab_size_global == 1200);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == 1200);
    ck_assert(slab_size_global == 1200);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == 1200);
    ck_assert(slab_size_global == 1200);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == 1200);
    ck_assert(slab_size_global == 1200);
    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == 1200);
    ck_assert(slab_size_global == 1200);

    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1200);
    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1200);
    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1200);

    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1400);

    result = _pico_mem_determine_slab_size(slab_size);
    ck_assert(result == 1400);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == 1400);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == 1400);

    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
    result = _pico_mem_determine_slab_size(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);

    result = _pico_mem_determine_slab_size(slab_size2);
    ck_assert(result == PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(slab_size_global == PICO_MEM_DEFAULT_SLAB_SIZE);
}
END_TEST

START_TEST (test_zalloc)
{

    uint8_t*byteptr;
    uint32_t oldHeapSize;
    uint32_t sizeLeft1;
    uint32_t size = 50;
    uint32_t slabsize = 1200;
    struct pico_mem_block*block;
    struct pico_mem_block*slab_block;
    struct pico_mem_page*page2;
    struct pico_mem_page*page0;
    struct pico_mem_page*page1;
    struct pico_mem_slab_node*slab_node1;

    /* Dependencies: */
    /* >_pico_mem_determine_slab_size */
    /* >_pico_mem_find_slab */
    /* >_pico_zalloc */
    /* >_pico_mem_init_page */
    /* >_pico_mem_find_heap_block */
    printf("\n***************Running test_zalloc***************\n\n");
    /* Scenario's to test: */
    /* >0: Manager NULL or len>PICO_MAX_SLAB_SIZE */
    /* >1: Alloc for a slab: 1 exists */
    /* >2: Alloc for a slab: none exists but new page can be created */
    /* >3: Alloc for a slab: none exists and no new pages can be created */
    /* >4: Alloc for a heap block: 1 exists in a page somewhere */
    /* >5: Alloc for a heap block: none exists but new page can be created */
    /* >6: Alloc for a heap block: none exists and no new pages can be created, and a slab block is free (then we know the correct function is called, no need to test the case of a non-existing slab) */
    /* >7: Another default slabsize; a new page must be created with this size */
    /* >8: Request for a heap size of less than the minimum object size must still result in an allocation of the minimum object size */


    /* Scenario 0, part 1: manager = NULL */
    printf("SCENARIO 0\n");
    byteptr = pico_mem_zalloc(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(byteptr == NULL);

    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);
    page0 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->first_page = page0;
    manager->size = 3 * PICO_MEM_PAGE_SIZE;
    manager->used_size = 2 * PICO_MEM_PAGE_SIZE;
    manager->tree.compare = compare_slab_keys;
    manager->tree.root = &LEAF;
    manager->manager_extra = NULL;


    block = (struct pico_mem_block*) (manager + 1);
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_FREE;
    block->internals.heap_block.size = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager) - sizeof(struct pico_mem_block);

    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->timestamp = 12345;
    page0->next_page = NULL;
    page0->slab_size = PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->slabs_max = ((PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - PICO_MIN_HEAP_SIZE) / (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE));
    page0->slabs_free = page0->slabs_max;
    page0->heap_max_size = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - sizeof(struct pico_mem_block) - (page0->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));
    /* page0->heap_max_free_space = page0->heap_max_size; */
    page0->heap_max_free_space = 0;
    sizeLeft1 = (uint32_t)(PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_page) - (page0->slabs_max * (sizeof(struct pico_mem_block) + PICO_MEM_DEFAULT_SLAB_SIZE)));

    /* Set up the blocks */
    /* Block 1: */
    byteptr = (uint8_t*) (page0 + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft1 -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft1 -= block->internals.heap_block.size;
    /* Free space: */
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft1 - sizeof(struct pico_mem_block));
    sizeLeft1 -= (uint32_t)sizeof(struct pico_mem_block);
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    /* Slab block 1: */
    slab_block = (struct pico_mem_block*) byteptr;
    slab_block->type = SLAB_BLOCK_TYPE;
    slab_block->internals.slab_block.page = page0;
    slab_block->internals.slab_block.slab_node = NULL;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += PICO_MEM_DEFAULT_SLAB_SIZE;
    page0->slabs_free--;
    /* Slab slab_block 2: */
    slab_block = (struct pico_mem_block*) byteptr;
    /* TODO: INVALID WRITE HERE: */
    slab_block->type = SLAB_BLOCK_TYPE;
    slab_block->internals.slab_block.page = page0;
    slab_node1 = pico_mem_page0_zalloc(sizeof(struct pico_mem_slab_node));
    slab_node1->slab = slab_block;
    slab_node1->next = NULL;
    slab_node1->prev = NULL;
    slab_block->internals.slab_block.slab_node = slab_node1;
    /* DEPENDENCY */
    /* pico_tree_insert(&manager->tree, slab_node1); */
    manager_tree_insert(&manager->tree, slab_node1);

    /* Scenario 0, part 2: len>PICO_MAX_SLAB_SIZE */
    byteptr = pico_mem_zalloc(PICO_MAX_SLAB_SIZE + 1);
    ck_assert(byteptr == NULL);
    /* Scenario 1: Ask for an existing slab block */
    printf("SCENARIO 1\n");
    byteptr = pico_mem_zalloc(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(byteptr == (uint8_t*) (slab_block + 1));
    /* Scenario 2: Ask for another slab block; a new page can be created */
    printf("SCENARIO 2\n");
    byteptr = pico_mem_zalloc(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(manager->used_size == 3 * PICO_MEM_PAGE_SIZE);
    page1 = manager->first_page;
    ck_assert(page1->next_page == page0);
    ck_assert((uint8_t*) page1 < byteptr);
    ck_assert(byteptr < ((uint8_t*) page1) + PICO_MEM_PAGE_SIZE);
    /* Setup for scenario 3: */
    pico_mem_zalloc(PICO_MEM_DEFAULT_SLAB_SIZE);
    /* Scenario 3: Ask for another slab block: no new page can be created, NULL should be returned */
    printf("SCENARIO 3\n");
    byteptr = pico_mem_zalloc(PICO_MEM_DEFAULT_SLAB_SIZE);
    ck_assert(byteptr == NULL);
    ck_assert(manager->used_size == 3 * PICO_MEM_PAGE_SIZE);
    /* Scenario 4: Ask for an existing heap block */
    printf("SCENARIO 4\n");
    byteptr = pico_mem_zalloc(page1->heap_max_free_space);
    /* TODO: Why? */
    /* byteptr = pico_mem_zalloc(page1->heap_max_free_space%4); */
    ck_assert(page1->heap_max_free_space == 0);
    ck_assert((uint8_t*) page1 < byteptr);
    ck_assert(byteptr < ((uint8_t*) page1) + PICO_MEM_PAGE_SIZE);
    /* Setup for scenario 5: */
    manager->size += PICO_MEM_PAGE_SIZE;
    /* Scenario 5; Ask for a heap block: none are available but a new page can be created */
    printf("SCENARIO 5\n");
    byteptr = pico_mem_zalloc(page1->heap_max_size);
    /* TODO: Why? */
    /* byteptr = pico_mem_zalloc(page1->heap_max_size%4); */
    ck_assert(manager->used_size == 4 * PICO_MEM_PAGE_SIZE);
    page2 = manager->first_page;
    ck_assert(page2->next_page == page1);
    ck_assert(page2->heap_max_free_space == 0);
    ck_assert((uint8_t*) page2 < byteptr);
    ck_assert(byteptr < ((uint8_t*) page2) + PICO_MEM_PAGE_SIZE);
    /* Scenario 6: Ask for a heap block: none are available and no new page can be created, but a slab block is available */
    printf("SCENARIO 6\n");
    byteptr = pico_mem_zalloc(page1->heap_max_size);
    ck_assert((uint8_t*) page2 < byteptr);
    ck_assert(byteptr < ((uint8_t*) page2) + PICO_MEM_PAGE_SIZE);
    /* Scenario 7: A new page with a new slabsize must be created */
    printf("SCENARIO 7\n");
    manager->size += 3 * PICO_MEM_PAGE_SIZE;
    byteptr = pico_mem_zalloc(slabsize);
    block = (struct pico_mem_block*) (byteptr - sizeof(struct pico_mem_block));
    ck_assert(block->internals.slab_block.page->slab_size == PICO_MEM_DEFAULT_SLAB_SIZE);
    byteptr = pico_mem_zalloc(slabsize);
    block = (struct pico_mem_block*) (byteptr - sizeof(struct pico_mem_block));
    ck_assert(block->internals.slab_block.page->slab_size == PICO_MEM_DEFAULT_SLAB_SIZE);
    byteptr = pico_mem_zalloc(slabsize);
    block = (struct pico_mem_block*) (byteptr - sizeof(struct pico_mem_block));
    ck_assert(block->internals.slab_block.page->slab_size == PICO_MEM_DEFAULT_SLAB_SIZE);
    /* At this point, a new page should be created with the correct size */
    byteptr = pico_mem_zalloc(slabsize);
    block = (struct pico_mem_block*) (byteptr - sizeof(struct pico_mem_block));
    ck_assert(block->internals.slab_block.page->slab_size < PICO_MEM_DEFAULT_SLAB_SIZE);
    /* Scenario 8: A request for a heap block of less than PICO_MEM_MINIMUM_OBJECT_SIZE will have its size enlargened */
    printf("SCENARIO 8\n");
    oldHeapSize = manager->first_page->heap_max_free_space;
    byteptr = pico_mem_zalloc(1);
    ck_assert(oldHeapSize == manager->first_page->heap_max_free_space + sizeof(struct pico_mem_block) + PICO_MEM_MINIMUM_OBJECT_SIZE);

    /*
       //TODO: Testing of profiling
       struct profiling_data profiling_struct;
       pico_mem_profile_collect_data(&profiling_struct);
       printf("Struct: \n\tfree_heap_space = %u\n\tfree_slab_space = %u\n\tused_heap_space = %u\n\tused_slab_space = %u\n", profiling_struct.free_heap_space, profiling_struct.free_slab_space, profiling_struct.used_heap_space, profiling_struct.used_slab_space);
       pico_mem_profile_scan_data();
     */

    pico_mem_deinit();
}
END_TEST

START_TEST (test_page0_free)
{

    uint32_t sizeLeft;
    uint8_t*byteptr;
    struct pico_mem_block*block;
    struct pico_mem_block*block1;
    struct pico_mem_block*block2;
    struct pico_mem_block*block3;
    struct pico_mem_manager_extra*heap_page;
    struct pico_mem_manager_extra*heap_page2;
    uint32_t size = 50;
    uint32_t blockAmount = 5;
    uint32_t blockAmount2 = 8;

    /* Dependencies: none */
    printf("\n***************Running test_page0_free***************\n\n");
    /* Scenario's to test: */
    /* >1: Freeing a block in the manager heap */
    /* >2: Freeing a block in an extra manager page */

    manager = pico_zalloc(PICO_MEM_PAGE_SIZE);

    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager);
    byteptr = (uint8_t*) (manager + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block1 = block;

    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));

    heap_page = pico_zalloc(PICO_MEM_PAGE_SIZE);
    heap_page2 = pico_zalloc(PICO_MEM_PAGE_SIZE);
    manager->manager_extra = heap_page;
    heap_page->next = heap_page2;
    heap_page->blocks = blockAmount;
    heap_page2->blocks = blockAmount2;
    heap_page2->next = NULL;

    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra);
    byteptr = (uint8_t*) (heap_page + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block2 = block;

    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));

    sizeLeft = PICO_MEM_PAGE_SIZE - sizeof(struct pico_mem_manager_extra);
    byteptr = (uint8_t*) (heap_page2 + 1);
    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = size;
    byteptr += sizeof(struct pico_mem_block);
    byteptr += block->internals.heap_block.size;
    sizeLeft -= (uint32_t)sizeof(struct pico_mem_block);
    sizeLeft -= block->internals.heap_block.size;
    block3 = block;

    block = (struct pico_mem_block*) byteptr;
    block->type = HEAP_BLOCK_TYPE;
    block->internals.heap_block.free = HEAP_BLOCK_NOT_FREE;
    block->internals.heap_block.size = (uint32_t)(sizeLeft - sizeof(struct pico_mem_block));

    /* Scenario 1 */
    pico_mem_page0_free(block1 + 1);
    ck_assert(block1->type == HEAP_BLOCK_TYPE);
    ck_assert(block1->internals.heap_block.free == HEAP_BLOCK_FREE);

    /* Scenario 2: */
    pico_mem_page0_free(block2 + 1);
    ck_assert(block2->type == HEAP_BLOCK_TYPE);
    ck_assert(block2->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(heap_page->blocks == blockAmount - 1);

    pico_mem_page0_free(block3 + 1);
    ck_assert(block3->type == HEAP_BLOCK_TYPE);
    ck_assert(block3->internals.heap_block.free == HEAP_BLOCK_FREE);
    ck_assert(heap_page2->blocks == blockAmount2 - 1);

    /* Cleanup */
    pico_free(manager);
    pico_free(heap_page);
    pico_free(heap_page2);
}
END_TEST

START_TEST (test_cleanup)
{
    /* Dependencies: */
    /* >pico_tree_findNode */
    /* >pico_tree_delete */
    /* >pico_mem_page0_free */
    /* >PICO_FREE */
    uint32_t timestamp = 1;
    struct pico_mem_page*page;
    struct pico_mem_manager_extra*heap_page;

    printf("\n***************Running test_cleanup***************\n\n");


    timestamp = 1000;
    /* Initialized manager has 1 completely empty page */
    pico_mem_init(21 * PICO_MEM_PAGE_SIZE);
    /* Page 2: extra page with 1 slab occupied */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    page->slabs_free--;
    /* Page 3: 1 extra page with some heap occupied */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    page->heap_max_free_space--;
    /* Page 4: 1 extra page with old timestamp */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    page->timestamp = 500;
    /* Page 5: 1 extra page with recent timestamp */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    page->timestamp = 950;
    /* Page 6: 1 extra page with wrong timestamp */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    page->timestamp = 1500;
    /* Page 7: 1 extra page with same timestamp */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, PICO_MEM_DEFAULT_SLAB_SIZE);
    page->timestamp = 1000;
    /* Page 8: 1 extra page with 1 slab occupied, slabsize 1200 */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, 1200);
    page->slabs_free--;
    /* Page 9: 1 extra empty page, slabsize 1200 */
    page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    _pico_mem_init_page(page, 1200);
    /* 1 empty extra manager page */
    heap_page = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    manager->manager_extra = heap_page;
    heap_page->blocks = 0;
    heap_page->timestamp = 0;
    /* 1 non-empty extra manager page */
    heap_page->next = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    heap_page = heap_page->next;
    heap_page->blocks = 1;
    heap_page->timestamp = 0;
    /* 1 empty extra manager page with old timestamp */
    heap_page->next = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    heap_page = heap_page->next;
    heap_page->blocks = 0;
    heap_page->timestamp = 500;
    /* 1 empty manager page with recent timestamp */
    heap_page->next = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    heap_page = heap_page->next;
    heap_page->blocks = 0;
    heap_page->timestamp = 950;
    /* 1 empty manager page with wrong timestamp */
    heap_page->next = malloc(PICO_MEM_PAGE_SIZE);
    manager->used_size += PICO_MEM_PAGE_SIZE;
    heap_page = heap_page->next;
    heap_page->blocks = 0;
    heap_page->timestamp = 1500;
    /* END OF MANAGER PAGES */
    heap_page->next = NULL;

    /* Run 1 cleanup */
    pico_mem_cleanup(timestamp);
    /* Check all pages and manager pages */
    page = manager->first_page;
    /* Page 9: empty with timestamp 0 */
    ck_assert(page->timestamp == timestamp);
    page = page->next_page;
    /* Page 8: not empty, 1 slab free, slabsize 1200 */
    ck_assert(page->timestamp == 0);
    ck_assert(page->slab_size == 1200);
    ck_assert(page->slabs_free == page->slabs_max - 1);
    page = page->next_page;
    /* Page 7: empty with same timestamp */
    ck_assert(page->timestamp == timestamp);
    page = page->next_page;
    /* Page 6: empty with wrong timestamp */
    ck_assert(page->timestamp == timestamp);
    page = page->next_page;
    /* Page 5: empty with recent timestamp */
    ck_assert(page->timestamp != timestamp);
    page = page->next_page;
    /* Page 4: empty with old timestamp: removed */
    /* Page 3: not empty with 1B less heap */
    ck_assert(page->timestamp == 0);
    ck_assert(page->heap_max_free_space == page->heap_max_size - 1);
    page = page->next_page;
    /* Page 2: not empty with 1 slab occupied */
    ck_assert(page->timestamp == 0);
    ck_assert(page->slabs_free == page->slabs_max - 1);
    page = page->next_page;
    /* Page 1: was empty with timestamp 0 */
    ck_assert(page->timestamp == timestamp);
    ck_assert(page->next_page == NULL);
    /* Check all manager pages */
    heap_page = manager->manager_extra;
    /* Page 1: was empty with timestamp 0 */
    ck_assert(heap_page->timestamp == timestamp);
    heap_page = heap_page->next;
    /* Page 2: not empty with 1 block occupied */
    ck_assert(heap_page->blocks == 1);
    ck_assert(heap_page->timestamp == 0);
    heap_page = heap_page->next;
    /* Page 3: empty with old timestamp: removed */
    /* Page 4: empty with recent timestamp */
    ck_assert(heap_page->timestamp != timestamp);
    heap_page = heap_page->next;
    /* Page 5: empty with wrong timestamp */
    ck_assert(heap_page->timestamp == timestamp);
    ck_assert(heap_page->next == NULL);

    /* Advance timestamp, run another cleanup */
    timestamp += 500;
    pico_mem_cleanup(timestamp);
    /* Check all pages and manager pages */
    page = manager->first_page;
    /* Page 9: empty with timestamp 0 */
    /* Page 8: not empty with 1 slab occupied, slabsize 1200 */
    ck_assert(page->timestamp == 0);
    ck_assert(page->slab_size == 1200);
    ck_assert(page->slabs_free == page->slabs_max - 1);
    page = page->next_page;
    /* Page 7: empty with same timestamp */
    /* Page 6: empty with wrong timestamp */
    /* Page 5: empty with recent timestamp */
    /* Page 4: empty with old timestamp: removed */
    /* Page 3: not empty with 1B less heap */
    ck_assert(page->timestamp == 0);
    ck_assert(page->heap_max_free_space == page->heap_max_size - 1);
    page = page->next_page;
    /* Page 2: not empty with 1 slab occupied */
    ck_assert(page->timestamp == 0);
    ck_assert(page->slabs_free == page->slabs_max - 1);
    ck_assert(page->next_page == NULL);
    /* Page 1: was empty with timestamp 0 */
    /* Check all manager pages */
    heap_page = manager->manager_extra;
    /* Page 1: was empty with timestamp 0 */
    /* Page 2: not empty with 1 block occupied */
    ck_assert(heap_page->blocks == 1);
    ck_assert(heap_page->timestamp == 0);
    ck_assert(heap_page->next == NULL);
    /* Page 3: empty with old timestamp: removed */
    /* Page 4: empty with recent timestamp */
    /* Page 5: empty with wrong timestamp */

    /* Still in use: manager page + 1 extra manager page + 3 normal pages */
    ck_assert(manager->used_size == 5 * PICO_MEM_PAGE_SIZE);

    /* Free extra manager page */
    manager->manager_extra->blocks = 0;

    timestamp += 500;
    pico_mem_cleanup(timestamp);
    ck_assert(manager->used_size == 5 * PICO_MEM_PAGE_SIZE);
    ck_assert(manager->manager_extra->timestamp == timestamp);
    timestamp += 500;
    pico_mem_cleanup(timestamp);
    ck_assert(manager->used_size == 4 * PICO_MEM_PAGE_SIZE);
    ck_assert(manager->manager_extra == NULL);

    /* Free normal pages */
    page = manager->first_page;
    page->slabs_free = page->slabs_max;
    page = page->next_page;
    page->heap_max_free_space = page->heap_max_size;
    page = page->next_page;
    page->slabs_free = page->slabs_max;

    timestamp += 500;
    pico_mem_cleanup(timestamp);
    ck_assert(manager->used_size == 4 * PICO_MEM_PAGE_SIZE);
    page = manager->first_page;
    ck_assert(page->timestamp == timestamp);
    page = page->next_page;
    ck_assert(page->timestamp == timestamp);
    page = page->next_page;
    ck_assert(page->timestamp == timestamp);

    timestamp += 500;
    pico_mem_cleanup(timestamp);
    ck_assert(manager->used_size == PICO_MEM_PAGE_SIZE);

    pico_mem_deinit();
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *mm = tcase_create("Memory_Manager");

    tcase_add_test(mm, test_compare_slab_keys);
    tcase_add_test(mm, test_manager_extra_alloc);
    tcase_add_test(mm, test_page0_zalloc);
    tcase_add_test(mm, test_init_page);
    tcase_add_test(mm, test_mem_init_whitebox );
    tcase_add_test(mm, test_free_and_merge_heap_block);
    tcase_add_test(mm, test_determine_max_free_space);
    tcase_add_test(mm, test_free_slab_block);
    tcase_add_test(mm, test_zero_initialize);
    tcase_add_test(mm, test_find_heap_block);
    tcase_add_test(mm, test_find_slab);
    tcase_add_test(mm, test_free);
    tcase_add_test(mm, test_determine_slab_size);
    tcase_add_test(mm, test_zalloc);
    tcase_add_test(mm, test_page0_free);
    tcase_add_test(mm, test_cleanup);
    suite_add_tcase(s, mm);

    return s;
}

int main(void)
{
    int fails;
    Suite *s = pico_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    fails = srunner_ntests_failed(sr);
    srunner_free(sr);
    return fails;
}
