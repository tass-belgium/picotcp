#include "unity.h"
#include "Mockpico_mm.h"
#include "pico_vector.h"
#include "pico_zmtp.c"
#include "Mockpico_socket.h"
#include <stdint.h>
#include "Mockpico_tree.h"


volatile pico_err_t pico_err;
#define BLACK 1
struct pico_tree_node LEAF = {
        NULL, /* key */
            &LEAF, &LEAF, &LEAF, /* parent, left,right */
                BLACK, /* color */
};



void setUp(void)
{
}

void tearDown(void)
{
}

void test_testfile(void)
{

    TEST_IGNORE();
}
