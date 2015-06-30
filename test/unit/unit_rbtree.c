/* RB tree unit test */
typedef struct
{
    int value;
}elem;

int compare(void *a, void *b)
{
    return ((elem *)a)->value - ((elem *)b)->value;
}

PICO_TREE_DECLARE(test_tree, compare);
PICO_TREE_DECLARE(test_tree2, compare);
#define RBTEST_SIZE 20000

START_TEST (test_rbtree2)
{
    struct pico_tree_node  *s;
    elem *e;
    int i, last;
    struct timeval start, end;
    gettimeofday(&start, 0);

    srand48(RBTEST_SIZE); /* use test-size as salt */
    for (i = 0; i < (RBTEST_SIZE >> 1); i++)
    {
        e = malloc(sizeof(elem));
        e->value = lrand48() % RBTEST_SIZE;
        if (pico_tree_findKey(&test_tree2, e)) {
            free(e);
        } else {
            pico_tree_insert(&test_tree2, e);
        }
    }
    gettimeofday(&end, 0);
    printf("Rbtree test 2 inserted %d entries in %d milliseconds\n", RBTEST_SIZE,
           (int)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000));
    last = 0;
    pico_tree_foreach(s, &test_tree2){
        fail_if (last > ((elem *)(s->keyValue))->value, "error");
        last = ((elem *)(s->keyValue))->value;
    }

    gettimeofday(&end, 0);
    printf("Rbtree test 2 duration with %d entries: %d milliseconds\n", RBTEST_SIZE,
           (int)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000));
    printf("Test finished.\n");
}
END_TEST

START_TEST (test_rbtree)
{
    struct pico_tree_node  *s, *tmp;
    elem t, *e;
    int i;
    struct timeval start, end;
    printf("Started test...\n");
    gettimeofday(&start, 0);

    for (i = 0; i < (RBTEST_SIZE >> 1); i++) {
        e = malloc(sizeof(elem));
        e->value = i;
        pico_tree_insert(&test_tree, e);
        /* RB_INSERT(rbtree, &RBTREE, e); */
        e = malloc(sizeof(elem));
        e->value = (RBTEST_SIZE - 1) - i;
        pico_tree_insert(&test_tree, e);
    }
    i = 0;
    pico_tree_foreach(s, &test_tree){
        fail_if (i++ != ((elem *)(s->keyValue))->value, "error");
    }
    t.value = RBTEST_SIZE >> 2;

    e = pico_tree_findKey(&test_tree, &t);
    fail_if(!e, "Search failed...");
    fail_if(e->value != t.value, "Wrong element returned...");

    pico_tree_foreach_reverse_safe(s, &test_tree, tmp){
        fail_if(!s, "Reverse safe returned null");
        e = (elem *)pico_tree_delete(&test_tree, s->keyValue);
        free(e);
    }

    fail_if(!pico_tree_empty(&test_tree), "Not empty");
    gettimeofday(&end, 0);
    printf("Rbtree test duration with %d entries: %d milliseconds\n", RBTEST_SIZE,
           (int)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000));
    printf("Test finished...\n");
}
END_TEST
