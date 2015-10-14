#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_common.h"
#include "pico_tree.h"
#include "modules/pico_dns_common.c"
#include "check.h"

START_TEST(tc_dns_rdata_cmp) /* MARK: dns_rdata_cmp */
{
    uint8_t rdata1[10] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    };
    uint8_t rdata2[10] = {
        1, 2, 3, 3, 5, 6, 7, 8, 9, 10
    };
    uint8_t rdata3[1] = {
        2
    };
    uint8_t rdata4[1] = {
        1
    };
    uint8_t rdata5[11] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 9
    };
    uint8_t rdata6[12] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
    };

    uint8_t rdata7[5] = {
        72, 69, 76, 76, 79
    };

    uint8_t rdata8[5] = {
        104, 101, 108, 108, 111
    };

    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Check equal data and size */
    ret = pico_dns_rdata_cmp(rdata1, rdata1, 10, 10, 0);
    fail_unless(!ret, "dns_rdata_cmp failed with equal data and size, case-sensitive!\n");

    /* Check smaller data and equal size */
    ret = pico_dns_rdata_cmp(rdata1, rdata2, 10, 10, 0);
    fail_unless(ret > 0, "dns_rdata_cmp failed with smaller data and equal size, case-sensitive!\n");

    /* Check larger data and smaller size */
    ret = pico_dns_rdata_cmp(rdata1, rdata3, 10, 1, 0);
    fail_unless(ret < 0, "dns_rdata_cmp failed with larger data and smaller size, case-sensitive!\n");

    /* Check equal data and smaller size */
    ret = pico_dns_rdata_cmp(rdata1, rdata4, 10, 1, 0);
    fail_unless(ret > 0, "dns_rdata_cmp failed with equal data and smaller size, case-sensitive!\n");

    /* Check smaller data and larger size */
    ret = pico_dns_rdata_cmp(rdata1, rdata5, 10, 11, 0);
    fail_unless(ret < 0, "dns_rdata_cmp failed with equal data and larger size, case-sensitive!\n");

    /* Check larger data and larger size */
    ret = pico_dns_rdata_cmp(rdata1, rdata6, 10, 12, 0);
    fail_unless(ret < 0, "dns_rdata_cmp failed with larger data and larger size, case-sensitive!\n");

    /* Check for tolower effect */
    ret = pico_dns_rdata_cmp(rdata7, rdata8, 5, 5, 0);
    fail_unless(ret < 0, "dns_rdata_cmp failed with check for tolower effect, case-sensitive!\n");

    //now check with case-insensitive

    /* Check equal data and size */
    ret = pico_dns_rdata_cmp(rdata1, rdata1, 10, 10, 1);
    fail_unless(!ret, "dns_rdata_cmp failed with equal data and size, case-insensitive!\n");

    /* Check smaller data and equal size */
    ret = pico_dns_rdata_cmp(rdata1, rdata2, 10, 10, 1);
    fail_unless(ret > 0, "dns_rdata_cmp failed with smaller data and equal size, case-insensitive!\n");

    /* Check larger data and smaller size */
    ret = pico_dns_rdata_cmp(rdata1, rdata3, 10, 1, 1);
    fail_unless(ret < 0, "dns_rdata_cmp failed with larger data and smaller size, case-insensitive!\n");

    /* Check equal data and smaller size */
    ret = pico_dns_rdata_cmp(rdata1, rdata4, 10, 1, 1);
    fail_unless(ret > 0, "dns_rdata_cmp failed with equal data and smaller size, case-insensitive!\n");

    /* Check smaller data and larger size */
    ret = pico_dns_rdata_cmp(rdata1, rdata5, 10, 11, 1);
    fail_unless(ret < 0, "dns_rdata_cmp failed with equal data and larger size, case-insensitive!\n");

    /* Check larger data and larger size */
    ret = pico_dns_rdata_cmp(rdata1, rdata6, 10, 12, 1);
    fail_unless(ret < 0, "dns_rdata_cmp failed with larger data and larger size, case-insensitive!\n");

    /* Check for tolower effect */
    ret = pico_dns_rdata_cmp(rdata7, rdata8, 5, 5, 1);
    fail_unless(ret == 0, "dns_rdata_cmp failed with check for tolower effect, case-insensitive!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_question_cmp) /* MARK: dns_question_cmp */
{
    printf("*********************** starting %s * \n", __func__);
    struct pico_dns_question *a = NULL, *b = NULL;
    const char *url1 = "host (2).local";
    const char *url3 = "host.local";
    const char *url2 = "192.168.2.1";
    uint16_t len = 0;
    int ret = 0;

    a = pico_dns_question_create(url1, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Question A could not be created!\n");
    b = pico_dns_question_create(url3, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Question B could not be created!\n");

    ret = pico_dns_question_cmp((void *)a, (void *)b);
    fail_unless(ret > 0, "Question is lexicographically smaller");
    pico_dns_question_delete((void **)&a);
    pico_dns_question_delete((void **)&b);

    a = pico_dns_question_create(url2, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_PTR,
                                 PICO_DNS_CLASS_IN, 1);
    fail_if(!a, "Question A could not be created!\n");
    b = pico_dns_question_create(url2, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_PTR,
                                 PICO_DNS_CLASS_IN, 1);
    fail_if(!b, "Question B could not be created!\n");

    ret = pico_dns_question_cmp((void *)a, (void *)b);
    fail_unless(!ret, "Question A and B should be equal!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_qtree_insert) /* MARK: dns_qtree_insert*/
{
    printf("*********************** starting %s * \n", __func__);
    char *url = "host.local";
    char *url2 = "host (2).local";
    char *url3 = "host (3).local";
    struct pico_dns_question *a = NULL, *b = NULL, *c = NULL;
    uint16_t qlen = 0;
    PICO_DNS_QTREE_DECLARE(qtree);
    PICO_DNS_QTREE_DECLARE(qtree2);

    a = pico_dns_question_create(url, &qlen, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!a || !(a->qname) || !(a->qsuffix), "Could not create question A!\n");
    b = pico_dns_question_create(url2, &qlen, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!b || !(b->qname) || !(b->qsuffix), "Coud not create question B!\n");

    pico_tree_insert(&qtree, a);
    fail_unless(pico_tree_count(&qtree) == 1,
                "pico_tree_insert failed with tree 1 question A!\n");

    pico_tree_insert(&qtree, b);
    fail_unless(2 == pico_tree_count(&qtree),
                "pico_tree_insert failed with tree 1 question B!\n");

    PICO_DNS_QTREE_DESTROY(&qtree);
    fail_unless(0 == pico_tree_count(&qtree),
                "Question tree not properly destroyed!\n");
    c = pico_dns_question_create(url3, &qlen, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!c || !(c->qname) || !(c->qsuffix), "Coud not create question B!\n");
    pico_tree_insert(&qtree2, c);
    fail_unless(1 == pico_tree_count(&qtree2),
                "pico_tree_insert failed with tree 2 question B!\n");
    PICO_DNS_QTREE_DESTROY(&qtree2);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_record_cmp) /* MARK: dns_record_cmp */
{
    struct pico_dns_record *a = NULL;
    struct pico_dns_record *b = NULL;
    const char *url1 = "foo.local";
    const char *url3 = "a.local";
    struct pico_ip4 rdata = {
        0
    };
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create test records */
    a = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Record A could not be created!\n");
    b = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Record B could not be created!\n");

    /* Try to compare equal records */
    ret = pico_dns_record_cmp((void *) a, (void *) b);
    fail_unless(!ret, "dns_record_cmp failed with equal records - %d!\n", ret);
    pico_dns_record_delete((void **)&a);
    pico_dns_record_delete((void **)&b);

    /* Create different test records */
    a = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_AAAA,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Record A could not be created!\n");
    b = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Record B could not be created!\n");

    /* Try to compare records with equal rname but different type */
    ret = pico_dns_record_cmp((void *) a, (void *) b);
    fail_unless(ret > 0, "dns_record_cmp failed with same name, different types!\n");
    pico_dns_record_delete((void **)&a);
    pico_dns_record_delete((void **)&b);

    /* Create different test records */
    a  = pico_dns_record_create(url3, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Record A could not be created!\n");
    b  = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Record B could not be created!\n");

    /* Try to compare records with different rname but equal type */
    ret = pico_dns_record_cmp((void *) a, (void *) b);
    fail_unless(ret < 0, "mdns_cmp failed with different name, same types!\n");
    pico_dns_record_delete((void **)&a);
    pico_dns_record_delete((void **)&b);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_rtree_insert) /* MARK: dns_rtree_insert*/
{
    PICO_DNS_RTREE_DECLARE(rtree);
    PICO_DNS_RTREE_DECLARE(rtree2);
    struct pico_dns_record *a = NULL;
    struct pico_dns_record *b = NULL, *c = NULL;
    const char *url1 = "foo.local";
    const char *url3 = "a.local";
    struct pico_ip4 rdata = {
        0
    };
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create test records */
    a = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_AAAA,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Record A could not be created!\n");
    b = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Record B could not be created!\n");

    pico_tree_insert(&rtree, a);
    pico_tree_insert(&rtree, b);

    PICO_DNS_RTREE_DESTROY(&rtree);
    fail_unless(pico_tree_count(&rtree) == 0,
                "Record tree not properly destroyed!\n");

    c = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!c, "Record C could not be created!\n");
    pico_tree_insert(&rtree2, c);

    PICO_DNS_RTREE_DESTROY(&rtree2);
    fail_unless(pico_tree_count(&rtree2) == 0,
                "Record tree not properly destroyed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_record_cmp_name_type) /* MARK: dns_record_cmp_name_type */
{
    struct pico_dns_record *a = NULL;
    struct pico_dns_record *b = NULL;
    const char *url1 = "foo.local";
    const char *url3 = "a.local";
    struct pico_ip4 rdata = {
        0
    };
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create different test records */
    a = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_AAAA,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Record A could not be created!\n");
    b = pico_dns_record_create(url1, &rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Record B could not be created!\n");

    /* Try to compare records with equal rname but different type */
    ret = pico_dns_record_cmp_name_type((void *) a, (void *) b);
    fail_unless(ret > 0, "dns_record_cmp failed with same name, different types!\n");
    pico_dns_record_delete(&a);
    pico_dns_record_delete(&b);

    /* Create exactly the same test records */
    a  = pico_dns_record_create(url3, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "Record A could not be created!\n");
    b  = pico_dns_record_create(url3, &rdata, 4, &len, PICO_DNS_TYPE_A,
                                PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "Record B could not be created!\n");

    /* Try to compare records with different rname but equal type */
    ret = pico_dns_record_cmp_name_type((void *) a, (void *) b);
    fail_unless(!ret, "dns_record_cmp_name_type failed with same names, same types!\n");
    pico_dns_record_delete(&a);
    pico_dns_record_delete(&b);

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_header) /* MARK: dns_fill_packet_header */
{
    struct pico_dns_header *header = NULL;
    uint8_t answer_buf[12] = {
        0x00, 0x00,
        0x85, 0x00,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x01
    };
    uint8_t query_buf[12] = {
        0x00, 0x00,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x01
    };

    printf("*********************** starting %s * \n", __func__);

    header = (struct pico_dns_header *)
             PICO_ZALLOC(sizeof(struct pico_dns_header));

    fail_if(NULL == header, "Not enough space!\n");

    /* Create a query header */
    pico_dns_fill_packet_header(header, 1, 1, 1, 1);

    int i;
    for (i = 0; i < 12; i++)
        printf("### %02x :: %02x\n", ((uint8_t*)header)[i], query_buf[i]);
    fail_unless(0 == memcmp((void *)header, (void *)query_buf, 12),
                "Comparing query header failed!\n");

    /* Create a answer header */
    pico_dns_fill_packet_header(header, 0, 1, 1, 1);

    fail_unless(0 == memcmp((void *)header, (void *)answer_buf, 12),
                "Comparing answer header failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_rr_section) /* MARK: dns_fill_packet_rr_section */
{
    printf("*********************** starting %s * \n", __func__);

    /* TODO: Insert test here */

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_rr_sections) /* MARK: dns_fill_packet_rr_sections */
{
    pico_dns_packet *packet = NULL;
    PICO_DNS_QTREE_DECLARE(qtree);
    PICO_DNS_RTREE_DECLARE(antree);
    PICO_DNS_RTREE_DECLARE(nstree);
    PICO_DNS_RTREE_DECLARE(artree);
    struct pico_dns_record *record = NULL;
    const char *rname = "picotcp.com";
    uint8_t rdata[4] = {
        10, 10, 0, 1
    };
    uint8_t cmp_buf[39] = {
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x78u,
        0x00u, 0x04u,
        10u, 10u, 0u, 1u
    };
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create a new A record */
    record = pico_dns_record_create(rname, rdata, 4, &len, PICO_DNS_TYPE_A,
                                    PICO_DNS_CLASS_IN, 120);
    fail_if(!record, "dns_record_create failed!\n");

    /* Add the record to a tree */
    pico_tree_insert(&antree, record);

    /* Try to fill the rr sections with packet as a NULL-pointer */
    ret = pico_dns_fill_packet_rr_sections(packet, &qtree, &antree,
                                           &nstree, &artree);
    fail_unless(ret, "Checking of params failed!\n");

    len = (uint16_t)sizeof(struct pico_dns_header);
    pico_tree_size(&qtree, &len, &pico_dns_question_size);
    pico_tree_size(&antree, &len, &pico_dns_record_size);
    pico_tree_size(&nstree, &len, &pico_dns_record_size);
    pico_tree_size(&artree, &len, &pico_dns_record_size);
    printf("Packet len: %d\n", len);

    /* Allocate the packet with the right size */
    packet = (pico_dns_packet *)PICO_ZALLOC((size_t)len);
    fail_if(NULL == packet, "Allocating packet failed!\n");
    fail_if(pico_dns_fill_packet_rr_sections(packet, &qtree, &antree, &nstree,
                                             &artree),
            "Filling of rr sections failed!\n");

    fail_unless(memcmp((void *)packet, (void *)cmp_buf, 39) == 0,
                "Filling of rr sections went wrong!\n");
    PICO_FREE(packet);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_fill_packet_question_section) /* MARK: dns_fill_packet_question_section */
{
    pico_dns_packet *packet = NULL;
    PICO_DNS_QTREE_DECLARE(qtree);
    struct pico_dns_question *a = NULL, *b = NULL;
    const char *qurl = "picotcp.com";
    uint8_t cmp_buf[45] = {
        0x00u, 0x00u,                     /* 2 */
        0x00u, 0x00u,                     /* 2 */
        0x00u, 0x00u,                     /* 2 */
        0x00u, 0x00u,                     /* 2 */
        0x00u, 0x00u,                     /* 2 */
        0x00u, 0x00u,                     /* 2 //12 */
        0x06u, 'g', 'o', 'o', 'g', 'l', 'e',                /* 7 */
        0x03u, 'c', 'o', 'm',                   /* 4 */
        0x00u,                     /* 1 //12 */
        0x00u, 0x01u,
        0x00u, 0x01u,                     /* 4 */
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',               /* 8 */
        0x03u, 'c', 'o', 'm',                   /* 4 */
        0x00u,                     /* 1 //13 */
        0x00u, 0x01u,
        0x00u, 0x01u
    };                                     /* 4 */
    uint16_t len = 0, i = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Create DNS questions and a vector of them */
    a = pico_dns_question_create(qurl, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(NULL == a, "dns_question_create failed!\n");
    b = pico_dns_question_create("google.com", &len, PICO_PROTO_IPV4,
                                 PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(NULL == b, "dns_question_create failed!\n");

    pico_tree_insert(&qtree, a);
    pico_tree_insert(&qtree, b);

    /* Determine the length of the packet and provide space */
    len = (uint16_t)sizeof(struct pico_dns_header);
    pico_tree_size(&qtree, &len, &pico_dns_question_size);
    printf("Packet len: %d - 45\n", len);
    packet = (pico_dns_packet *)PICO_ZALLOC((size_t)len);

    fail_if(NULL == packet, "Allocating packet failed!\n");
    fail_if(pico_dns_fill_packet_question_section(packet, &qtree),
            "Filling of rr sections failed!\n");

    fail_unless(memcmp((void *)packet, (void *)cmp_buf, 45) == 0,
                "Filling of question sesction went wrong!\n");
    PICO_FREE(packet);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_packet_compress_find_ptr) /* MARK: dns_packet_compress_find_ptr */
{
    uint8_t *data = (uint8_t *)"abcdef\5local\0abcdef\4test\5local";
    uint8_t *name = (uint8_t *)(data + 24);
    uint16_t len = 31;
    uint8_t *ptr = NULL;

    printf("*********************** starting %s * \n", __func__);

    ptr = pico_dns_packet_compress_find_ptr(name, data, len);
    fail_unless(ptr == (data + 6), "Finding compression ptr failed %p - %p!\n", ptr,
                data + 6);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_packet_compress_name) /* MARK: dns_packet_compress_name */
{
    uint8_t buf[46] = {
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u
    };

    uint8_t *name = buf + 29u;
    uint16_t len = 46;
    int ret = 0;
    printf("*********************** starting %s * \n", __func__);

    ret = pico_dns_packet_compress_name(name, buf, &len);
    fail_unless(ret == 0, "dns_packet_compress_name returned error!\n");
    fail_unless(len == (46 - 11), "packet_compress_name return wrong length!\n");
    fail_unless(memcmp(name, "\xc0\x0c", 2) == 0, "packet_compress_name failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_packet_compress) /* MARK: dns_packet_compress */
{
    uint8_t buf[83] = {
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x01u,
        0x00u, 0x00u,
        0x00u, 0x02u,
        0x00u, 0x00u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00, 0x0A,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x0A, 0x0A,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00, 0x0A,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x0A, 0x0A
    };
    uint8_t cmp_buf[61] = {
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x01u,
        0x00u, 0x00u,
        0x00u, 0x02u,
        0x00u, 0x00u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0xC0u, 0x0Cu,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00, 0x0A,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x0A, 0x0A,
        0xC0u, 0x0Cu,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00, 0x0A,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x0A, 0x0A
    };
    pico_dns_packet *packet = (pico_dns_packet *)buf;
    uint16_t len = 83;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    ret = pico_dns_packet_compress(packet, &len);

    fail_unless(ret == 0, "dns_packet_compress returned error!\n");
    fail_unless(len == (83 - 22), "packet_compress returned length %u!\n", len);
    fail_unless(memcmp(packet, cmp_buf, 61) == 0, "packet_compress_name failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_question_fill_qsuffix) /* MARK: dns_question_fill_suffix */
{
    struct pico_dns_question_suffix suffix;
    printf("*********************** starting %s * \n", __func__);

    pico_dns_question_fill_suffix(&suffix, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN);

    fail_unless((suffix.qtype == short_be(PICO_DNS_TYPE_A)) &&
                (suffix.qclass == short_be(PICO_DNS_CLASS_IN)),
                "Filling qsuffix failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_question_delete) /* MARK: dns_question_delete */
{
    const char *qurl = "picotcp.com";
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    printf("*********************** starting %s * \n", __func__);

    ret = pico_dns_question_delete((void **)&a);

    fail_unless(ret == 0, "dns_question_delete returned error!\n");
    fail_unless(a == NULL, "dns_question_delete failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_question_create) /* MARK: dns_quesiton_create */
{
    const char *qurl = "picotcp.com";
    const char *qurl2 = "1.2.3.4";
    const char *qurl3 = "2001:0db8:0000:0000:0000:0000:0000:0000";
    char buf[13] = {
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03u, 'c', 'o', 'm',
        0x00u
    };
    char buf2[22] = {
        0x01u, '4',
        0x01u, '3',
        0x01u, '2',
        0x01u, '1',
        0x07u, 'i', 'n', '-', 'a', 'd', 'd', 'r',
        0x04u, 'a', 'r', 'p', 'a',
        0x00u
    };
    char buf3[74] = {
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '8', 0x01u, 'b', 0x01u, 'd', 0x01u, '0',
        0x01u, '1', 0x01u, '0', 0x01u, '0', 0x01u, '2',
        0x03u, 'I', 'P', '6',
        0x04u, 'A', 'R', 'P', 'A',
        0x00u
    };
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    /* First, plain A record */
    struct pico_dns_question *a = pico_dns_question_create(qurl, &len,
                                                           PICO_PROTO_IPV4,
                                                           PICO_DNS_TYPE_A,
                                                           PICO_DNS_CLASS_IN,
                                                           0);
    fail_if(a == NULL, "dns_question_created returned NULL!\n");
    fail_unless(strcmp(a->qname, buf) == 0, "url not converted correctly!\n");
    fail_unless(short_be(a->qsuffix->qtype) == PICO_DNS_TYPE_A,
                "qtype not properly set!\n");
    fail_unless(short_be(a->qsuffix->qclass) == PICO_DNS_CLASS_IN,
                "qclass not properly set!\n");
    pico_dns_question_delete((void **)&a);

    /* Reverse PTR record for IPv4 address */
    a = pico_dns_question_create(qurl2, &len, PICO_PROTO_IPV4,
                                 PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN, 1);
    fail_unless(strcmp(a->qname, buf2) == 0, "url2 not converted correctly! %s\n", a->qname);
    fail_unless(short_be(a->qsuffix->qtype) == PICO_DNS_TYPE_PTR,
                "qtype2 not properly set!\n");
    fail_unless(short_be(a->qsuffix->qclass) == PICO_DNS_CLASS_IN,
                "qclass2 not properly set!\n");
    pico_dns_question_delete((void **)&a);

    /* Reverse PTR record for IPv6 address */
    a = pico_dns_question_create(qurl3, &len, PICO_PROTO_IPV6,
                                 PICO_DNS_TYPE_PTR, PICO_DNS_CLASS_IN, 1);
    fail_unless(strcmp(a->qname, buf3) == 0, "url3 not converted correctly!\n");
    fail_unless(short_be(a->qsuffix->qtype) == PICO_DNS_TYPE_PTR,
                "qtype3 not properly set!\n");
    fail_unless(short_be(a->qsuffix->qclass) == PICO_DNS_CLASS_IN,
                "qclass3 not properly set!\n");
    pico_dns_question_delete((void **)&a);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_query_create) /* MARK: dns_query_create */
{
    pico_dns_packet *packet = NULL;
    PICO_DNS_QTREE_DECLARE(qtree);
    const char *qurl = "picotcp.com";
    const char *qurl2 = "google.com";
    uint8_t buf[42] = {
        0x00u, 0x00u,
        0x01u, 0x00u,
        0x00u, 0x02u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x06u, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0xc0u, 0x13u,
        0x00u, 0x01u,
        0x00u, 0x01u
    };
    uint16_t len = 0;
    int ret = 0;
    struct pico_dns_question *a = NULL, *b = NULL;

    printf("*********************** starting %s * \n", __func__);


    a = pico_dns_question_create(qurl, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!a, "dns_question_create failed!\n");
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");
    b = pico_dns_question_create(qurl2, &len, PICO_PROTO_IPV4, PICO_DNS_TYPE_A,
                                 PICO_DNS_CLASS_IN, 0);
    fail_if(!b, "dns_question_create failed!\n");
    fail_unless(ret == 0, "dns_question_vector_add returned error!\n");

    pico_tree_insert(&qtree, a);
    pico_tree_insert(&qtree, b);

    packet = pico_dns_query_create(&qtree, NULL, NULL, NULL, &len);
    fail_if(packet == NULL, "dns_query_create returned NULL!\n");
    fail_unless(0 == memcmp(buf, (void *)packet, 42),
                "dns_query_created failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_record_fill_suffix) /* MARK: dns_record_fill_suffix */
{

    printf("*********************** starting %s * \n", __func__);

    struct pico_dns_record_suffix *suffix = NULL;
    pico_dns_record_fill_suffix(&suffix, PICO_DNS_TYPE_A, PICO_DNS_CLASS_IN,
                                120, 4);

    fail_unless((suffix->rtype == short_be(PICO_DNS_TYPE_A) &&
                 suffix->rclass == short_be(PICO_DNS_CLASS_IN) &&
                 suffix->rttl == long_be(120) &&
                 suffix->rdlength == short_be(4)),
                "Filling rsuffix failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_record_copy_flat) /* MARK: dns_record_copy_flat */
{
    struct pico_dns_record *record = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = {
        10, 10, 0, 1
    };
    uint8_t buf[128] = {
        0
    };
    uint8_t *ptr = NULL;
    uint8_t cmp_buf[27] = {
        0x07, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x78,
        0x00, 0x04,
        0x0A, 0x0A, 0x00, 0x01
    };
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    record = pico_dns_record_create(url, (void *)rdata, 4,
                                    &len, PICO_DNS_TYPE_A,
                                    PICO_DNS_CLASS_IN, 120);
    fail_if(!record, "dns_record_create failed!\n");

    *ptr = buf + 20;

    /* Try to copy the record to a flat buffer */
    ret = pico_dns_record_copy_flat(record, &ptr);

    fail_unless(ret == 0, "dns_record_copy_flat returned error!\n");
    fail_unless(memcmp(buf + 20, cmp_buf, 27) == 0,
                "dns_record_copy_flat failed!\n");

    /* FREE memory */
    pico_dns_record_delete(&record);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_record_copy) /* MARK: dns_record_copy */
{
    struct pico_dns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = {
        10, 10, 0, 1
    };
    uint16_t len = 0;

    a = pico_dns_record_create(url, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create failed!\n");

    printf("*********************** starting %s * \n", __func__);

    /* Try to copy the first DNS record */
    b = pico_dns_record_copy(a);
    fail_unless(b != NULL, "dns_record_copy returned NULL!\n");
    fail_unless(a != b, "pointers point to same struct!\n");
    fail_unless(strcmp(a->rname, b->rname) == 0,
                "dns_record_copy failed copying names!\n");
    fail_unless(a->rsuffix->rtype == b->rsuffix->rtype,
                "dns_record_copy failed copying rtype!\n");
    fail_unless(a->rsuffix->rclass == b->rsuffix->rclass,
                "dns_record_copy failed copying rclass!\n");
    fail_unless(a->rsuffix->rttl == b->rsuffix->rttl,
                "dns_record_copy failed copying rttl!\n");
    fail_unless(a->rsuffix->rdlength == b->rsuffix->rdlength,
                "dns_record_copy failed copying rdlenth!\n");
    fail_unless(memcmp(a->rdata, b->rdata, short_be(b->rsuffix->rdlength)) == 0,
                "dns_record_copy failed copying rdata!\n");

    /* FREE memory */
    pico_dns_record_delete(&a);
    pico_dns_record_delete(&b);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_record_delete) /* MARK: dns_record_delete */
{
    struct pico_dns_record *a = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = {
        10, 10, 0, 1
    };
    uint16_t len = 0;
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);


    a = pico_dns_record_create(url, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create failed!\n");

    /* Try to delete the created record */
    ret = pico_dns_record_delete(&a);
    fail_unless(ret == 0, "pico_dns_record_delete returned NULL!\n");
    fail_unless(a == NULL, "pico_dns_record_delete failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_record_create) /* MARK: dns_record_create */
{
    struct pico_dns_record *a = NULL;
    const char *url = "picotcp.com";
    uint8_t rdata[4] = {
        10, 10, 0, 1
    };
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    a = pico_dns_record_create(url, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    fail_unless(strcmp(a->rname, "\x7picotcp\x3com"),
                "dns_record_create didn't convert url %s properly!\n",
                a->rname);
    fail_unless(a->rsuffix->rtype == short_be(PICO_DNS_TYPE_A),
                "dns_record_create failed setting rtype!\n");
    fail_unless(a->rsuffix->rclass == short_be(PICO_DNS_CLASS_IN),
                "dns_record_create failed setting rclass!\n");
    fail_unless(a->rsuffix->rttl == long_be(120),
                "dns_record_create failed setting rttl!\n");
    fail_unless(a->rsuffix->rdlength == short_be(4),
                "dns_record_create failed setting rdlenth!\n");
    fail_unless(memcmp(a->rdata, rdata, 4) == 0,
                "dns_record_create failed setting rdata!\n");

    /* TODO: Test PTR records */

    pico_dns_record_delete(&a);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_answer_create) /* MARK: dns_answer_create */
{
    pico_dns_packet *packet = NULL;
    PICO_DNS_RTREE_DECLARE(rtree);
    struct pico_dns_record *a = NULL, *b = NULL;
    const char *url = "picotcp.com";
    const char *url2 = "google.com";
    uint8_t rdata[4] = {
        10, 10, 0, 1
    };
    uint16_t len = 0;
    int ret = 0, i = 0;
    uint8_t buf[62] = {
        0x00u, 0x00u,
        0x85u, 0x00u,
        0x00u, 0x00u,
        0x00u, 0x02u,
        0x00u, 0x00u,
        0x00u, 0x00u,
        0x06u, 'g', 'o', 'o', 'g', 'l', 'e',
        0x03u, 'c', 'o', 'm',
        0x00u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x78u,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x00u, 0x01u,
        0x07u, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0xc0u, 0x13u,
        0x00u, 0x01u,
        0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x78u,
        0x00u, 0x04u,
        0x0Au, 0x0Au, 0x00u, 0x01u
    };

    printf("*********************** starting %s * \n", __func__);

    a = pico_dns_record_create(url, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");
    b = pico_dns_record_create(url2, (void *)rdata, 4, &len, PICO_DNS_TYPE_A,
                               PICO_DNS_CLASS_IN, 120);
    fail_if(!a, "dns_record_create returned NULL!\n");

    pico_tree_insert(&rtree, a);
    pico_tree_insert(&rtree, b);

    /* Try to create an answer packet */
    packet = pico_dns_answer_create(&rtree, NULL, NULL, &len);
    fail_if (packet == NULL, "dns_answer_create returned NULL!\n");
    fail_unless(0 == memcmp((void *)packet, (void *)buf, len),
                "dns_answer_create failed!\n");

    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_namelen_comp) /* MARK: dns_namelen_comp */
{
    char name[] = "\3www\4tass\2be\0";
    char name_comp[] = "\3www\4tass\2be\xc0\x02";  /* two bytes ofset from start of buf */
    unsigned int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    /* name without compression */
    ret = pico_dns_namelen_comp(name);
    fail_unless(ret == 12, "Namelength is wrong!\n");

    /* name with compression */
    ret = pico_dns_namelen_comp(name_comp);
    fail_unless(ret == 13, "Namelength is wrong!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_decompress_name) /* MARK: dns_decompress_name */
{
    char name[] = "\4mail\xc0\x02";
    char name2[] = "\xc0\x02";
    char buf[] = "00\6google\3com";
    char *ret;

    printf("*********************** starting %s * \n", __func__);

    /* Test normal DNS name compression */
    ret = pico_dns_decompress_name(name, (pico_dns_packet *)buf);

    /* Fail conditions */
    fail_unless(ret != NULL, "Name ptr returned is NULL");
    fail_unless(strcmp(ret, "\4mail\6google\3com") == 0, "Not correctly decompressed: '%s'!\n", ret);

    /* Free memory */
    PICO_FREE(ret);
    ret = NULL;

    /* Test when there is only a pointer */
    ret = pico_dns_decompress_name(name2, (pico_dns_packet *)buf);

    /* Fail conditions */
    fail_unless(ret != NULL, "Name ptr returned is NULL");
    fail_unless(strcmp(ret, "\6google\3com") == 0, "Not correctly decompressed: '%s'!\n", ret);

    /* Free memory */
    PICO_FREE(ret);
    ret = NULL;
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_url_get_reverse_len) /* MARK: dns_url_get_reverse_len */
{
    const char *url_ipv4 = "10.10.0.1";
    const char *url_ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0000";
    uint16_t arpalen = 0;
    uint16_t len = 0;

    printf("*********************** starting %s * \n", __func__);

    /* Try to determine the reverse length of the IPv4 URL */
    len = pico_dns_url_get_reverse_len(url_ipv4, &arpalen, PICO_PROTO_IPV4);
    fail_unless(len == (9 + 2) && arpalen == 13,
                "dns_url_get_reverse_len failed with IPv4 URL!\n");

    /* Try to determine the reverse length of the IPv6 URL */
    len = pico_dns_url_get_reverse_len(url_ipv6, &arpalen, PICO_PROTO_IPV6);
    fail_unless(len == (63 + 2) && arpalen == 9,
                "dns_url_get_reverse_len failed with IPv4 URL!\n");

    len = pico_dns_url_get_reverse_len(NULL, NULL, PICO_PROTO_IPV4);
    fail_unless(len == 0, "dns_url_get_reverse_len with NULL-ptrs failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_url_to_reverse_qname) /* MARK: dns_url_to_reverse_qname */
{
    const char *url_ipv4 = "10.10.0.1";
    const char *url_ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0000";
    const char *qname = NULL;
    char cmp_buf1[24] = {
        0x01, '1',
        0x01, '0',
        0x02, '1', '0',
        0x02, '1', '0',
        0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
        0x04, 'a', 'r', 'p', 'a',
        0x00
    };
    char cmp_buf[74] = {
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '0', 0x01u, '0', 0x01u, '0', 0x01u, '0',
        0x01u, '8', 0x01u, 'b', 0x01u, 'd', 0x01u, '0',
        0x01u, '1', 0x01u, '0', 0x01u, '0', 0x01u, '2',
        0x03u, 'I', 'P', '6',
        0x04u, 'A', 'R', 'P', 'A',
        0x00u
    };

    printf("*********************** starting %s * \n", __func__);

    /* Try to reverse IPv4 URL */
    qname = pico_dns_url_to_reverse_qname(url_ipv4, PICO_PROTO_IPV4);
    fail_unless(qname != NULL, "dns_url_to_reverse_qname returned NULL!\n");
    fail_unless(strcmp(qname, cmp_buf1) == 0,
                "dns_url_to_reverse_qname failed with IPv4 %s!\n", qname);
    PICO_FREE(qname);

    /* Try to reverse IPv6 URL */
    qname = pico_dns_url_to_reverse_qname(url_ipv6, PICO_PROTO_IPV6);
    fail_unless(qname != NULL, "dns_url_to_reverse_qname returned NULL!\n");
    fail_unless(strcmp(qname, cmp_buf) == 0,
                "dns_url_to_reverse_qname failed with IPv6!\n");
    PICO_FREE(qname);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_qname_to_url) /* MARK: dns_qname_to_url */
{
    char qname[24] = {
        0x01, '1',
        0x01, '0',
        0x02, '1', '0',
        0x02, '1', '0',
        0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
        0x04, 'a', 'r', 'p', 'a',
        0x00
    };
    char qname2[13] = {
        0x07, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03, 'c', 'o', 'm',
        0x00
    };
    char qname3[14] = {
        0x08, 'p', 'i', 'c', 'o', '\.', 't', 'c', 'p',
        0x03, 'c', 'o', 'm',
        0x00
    };
    char *url = NULL;

    printf("*********************** starting %s * \n", __func__);

    /* Try to convert qname to url */
    url = pico_dns_qname_to_url(qname);
    fail_unless(url != NULL, "dns_qname_to_url returned NULL!\n");
    fail_unless(strcmp(url, "1.0.10.10.in-addr.arpa") == 0,
                "dns_qname_to_url failed %s!\n", url);
    PICO_FREE(url);

    /* Try to convert qname2 to url */
    url = pico_dns_qname_to_url(qname2);
    fail_unless(url != NULL, "dns_qname_to_url returned NULL!\n");
    fail_unless(strcmp(url, "picotcp.com") == 0,
                "dns_qname_to_url failed %s!\n", url);
    PICO_FREE(url);

    /* Try to convert qname2 to url */
    url = pico_dns_qname_to_url(qname3);
    fail_unless(url != NULL, "dns_qname_to_url returned NULL!\n");
    fail_unless(strcmp(url, "pico.tcp.com") == 0,
                "dns_qname_to_url failed %s!\n", url);
    PICO_FREE(url);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_url_to_qname) /* MARK: dns_url_to_qname */
{
    char qname1[24] = {
        0x01, '1',
        0x01, '0',
        0x02, '1', '0',
        0x02, '1', '0',
        0x07, 'i', 'n', '-', 'a', 'd', 'd', 'r',
        0x04, 'a', 'r', 'p', 'a',
        0x00
    };
    char qname2[13] = {
        0x07, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03, 'c', 'o', 'm',
        0x00
    };
    char *qname = NULL;

    printf("*********************** starting %s * \n", __func__);

    /* Try to convert url to qname1 */
    qname = pico_dns_url_to_qname("1.0.10.10.in-addr.arpa");
    fail_unless(qname != NULL, "dns_url_to_qname returned NULL!\n");
    fail_unless(strcmp(qname, qname1) == 0,
                "dns_url_to_qname failed %s!\n", qname);
    PICO_FREE(qname);

    /* Try to convert url to qname2 */
    qname = pico_dns_url_to_qname("picotcp.com");
    fail_unless(qname != NULL, "dns_url_to_qname returned NULL!\n");
    fail_unless(strcmp(qname, qname2) == 0,
                "dns_url_to_qname failed %s!\n", qname);
    PICO_FREE(qname);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_name_to_dns_notation) /* MARK: dns_name_to_dns_notation */
{
    char qname1[13] = {
        0x07, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03, 'c', 'o', 'm',
        0x00
    };
    char url1[13] = {
        0, 'p', 'i', 'c', 'o', 't', 'c', 'p', '.', 'c', 'o', 'm', 0x00
    };
    char url2[13] = {
        'a', 'p', 'i', 'c', 'o', 't', 'c', 'p', '.', 'c', 'o', 'm', 0x00
    };
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    ret = pico_dns_name_to_dns_notation(url1, strlen(url1));
    fail_unless(ret == -1, "dns_name_to_dns_notation didn't check correct!\n");

    ret = pico_dns_name_to_dns_notation(url2, strlen(url2));
    fail_unless(ret == 0, "dns_name_to_dns_notation returned error!\n");
    fail_unless(strcmp(url2, qname1) == 0,
                "dns_name_to_dns_notation failed! %s\n", url2);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_notation_to_name) /* MARK: dns_notation_to_name */
{
    char qname1[13] = {
        0x07, 'p', 'i', 'c', 'o', 't', 'c', 'p',
        0x03, 'c', 'o', 'm',
        0x00
    };
    char url1[13] = {
        '.', 'p', 'i', 'c', 'o', 't', 'c', 'p', '.', 'c', 'o', 'm', 0x00
    };
    int ret = 0;

    printf("*********************** starting %s * \n", __func__);

    ret = pico_dns_notation_to_name(qname1, strlen(qname1));
    fail_unless(ret == 0, "dns_notation_to_name returned error!\n");
    fail_unless(strcmp(url1, qname1) == 0,
                "dns_notation_to_name failed! %s\n", qname1);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_mirror_addr) /* MARK: dns_mirror_addr */
{
    char url[12] = "192.168.0.1";
    int8_t ret = 0;

    printf("*********************** starting %s * \n", __func__);

    ret = pico_dns_mirror_addr(url);
    fail_unless(ret == 0, "dns_mirror_addr returned error!\n");
    fail_unless(strcmp(url, "1.0.168.192") == 0,
                "dns_mirror_addr failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_ptr_ip6_nibble_lo) /* MARK: dns_ptr_ip6_nibble_lo */
{
    uint8_t byte = 0x34;
    char nibble_lo = 0;

    printf("*********************** starting %s * \n", __func__);

    nibble_lo = dns_ptr_ip6_nibble_lo(byte);
    fail_unless(nibble_lo == '4', "dns_ptr_ip6_nibble_lo failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_dns_ptr_ip6_nibble_hi) /* MARK: dns_ptr_ip6_nibble_hi */
{
    uint8_t byte = 0x34;
    char nibble_hi = 0;

    printf("*********************** starting %s * \n", __func__);

    nibble_hi = dns_ptr_ip6_nibble_hi(byte);
    fail_unless(nibble_hi == '3', "dns_ptr_ip6_nibble_hi failed! '%c'\n",
                nibble_hi);
    printf("*********************** ending %s * \n", __func__);
}
END_TEST
START_TEST(tc_pico_dns_ipv6_set_ptr) /* MARK: dns_ipv6_set_ptr */
{
    const char *url_ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0000";

    char cmpbuf[65] = {
        '0', '.', '0', '.', '0', '.', '0', '.',
        '0', '.', '0', '.', '0', '.', '0', '.',
        '0', '.', '0', '.', '0', '.', '0', '.',
        '0', '.', '0', '.', '0', '.', '0', '.',
        '0', '.', '0', '.', '0', '.', '0', '.',
        '0', '.', '0', '.', '0', '.', '0', '.',
        '8', '.', 'b', '.', 'd', '.', '0', '.',
        '1', '.', '0', '.', '0', '.', '2', '.', 0x00
    };
    char buf[65] = {};

    printf("*********************** starting %s * \n", __func__);

    pico_dns_ipv6_set_ptr(url_ipv6, buf);
    fail_unless(strcmp(buf, cmpbuf) == 0,
                "dns_ipv6_set_ptr failed!\n");
    printf("*********************** ending %s * \n", __func__);
}
END_TEST

Suite *pico_suite(void)
{
    Suite *s = suite_create("PicoTCP");

    TCase *TCase_dns_rdata_cmp = tcase_create("Unit test for dns_rdata_cmp");
    TCase *TCase_dns_question_cmp = tcase_create("Unit test for dns_question_cmp");
    TCase *TCase_dns_qtree_insert = tcase_create("Unit test for dns_qtree_insert");
    TCase *TCase_dns_record_cmp = tcase_create("Unit test for dns_record_cmp");
    TCase *TCase_dns_rtree_insert = tcase_create("Unit test for dns_rtree_insert");
    TCase *TCase_dns_record_cmp_name_type = tcase_create("Unit test for dns_record_cmp_name_type");

    /* DNS packet section filling */
    TCase *TCase_pico_dns_fill_packet_header = tcase_create("Unit test for 'pico_dns_fill_packet_header'");
    TCase *TCase_pico_dns_fill_packet_rr_sections = tcase_create("Unit test for 'pico_dns_fill_packet_rr_sections'");
    TCase *TCase_pico_dns_fill_packet_question_section = tcase_create("Unit test for 'pico_dns_fill_packet_question_sections'");

    /* DNS packet compression */
    TCase *TCase_pico_dns_packet_compress_find_ptr = tcase_create("Unit test for 'pico_dns_packet_compress_find_ptr'");
    TCase *TCase_pico_dns_packet_compress_name = tcase_create("Unit test for 'pico_dns_packet_compress_name'");
    TCase *TCase_pico_dns_packet_compress = tcase_create("Unit test for 'pico_dns_packet_compress'");

    /* DNS question functions */
    TCase *TCase_pico_dns_question_fill_qsuffix = tcase_create("Unit test for 'pico_dns_question_fill_qsuffix'");
    TCase *TCase_pico_dns_question_delete = tcase_create("Unit test for 'pico_dns_question_delete'");
    TCase *TCase_pico_dns_question_create = tcase_create("Unit test for 'pico_dns_question_create'");

    /* DNS query packet creation */
    TCase *TCase_pico_dns_query_create = tcase_create("Unit test for 'pico_dns_query_create'");

    /* DNS resource record functions */
    TCase *TCase_pico_dns_record_fill_suffix = tcase_create("Unit test for 'pico_dns_record_fill_suffix'");
    TCase *TCase_pico_dns_record_copy_flat = tcase_create("Unit test for 'pico_dns_record_copy_flat'");
    TCase *TCase_pico_dns_record_copy = tcase_create("Unit test for 'pico_dns_record_copy'");
    TCase *TCase_pico_dns_record_delete = tcase_create("Unit test for 'pico_dns_record_delete'");
    TCase *TCAse_pico_dns_record_create = tcase_create("Unit test for 'pico_dns_record_create'");

    /* DNS answer packet creation */
    TCase *TCase_pico_dns_answer_create = tcase_create("Unit test for 'pico_dns_answer_create'");

    /* Name conversion and compression function */
    TCase *TCase_pico_dns_namelen_comp = tcase_create("Unit test for 'pico_dns_namelen_comp'");
    TCase *TCase_pico_dns_decompress_name = tcase_create("Unit test for 'pico_dns_decompress_name'");
    TCase *TCase_pico_dns_url_get_reverse_len = tcase_create("Unit test for 'pico_dns_url_get_reverse_len'");
    TCase *TCase_pico_dns_url_to_reverse_qname = tcase_create("Unit test for 'pico_dns_url_to_reverse_qname'");
    TCase *TCase_pico_dns_qname_to_url = tcase_create("Unit test for 'pico_dns_qname_to_url'");
    TCase *TCase_pico_dns_url_to_qname = tcase_create("Unit test for 'pico_dns_url_to_qname'");
    TCase *TCase_pico_dns_name_to_dns_notation = tcase_create("Unit test for 'pico_dns_name_to_dns_notation'");
    TCase *TCase_pico_dns_notation_to_name = tcase_create("Unit test for 'pico_dns_notation_to_name'");
    TCase *TCase_pico_dns_mirror_addr = tcase_create("Unit test for 'pico_dns_mirror_addr'");
    TCase *TCase_dns_ptr_ip6_nibble_lo = tcase_create("Unit test for 'dns_ptr_ip6_nibble_lo'");
    TCase *TCase_dns_ptr_ip6_nibble_hi = tcase_create("Unit test for 'dns_ptr_ip6_nibble_hi'");
    TCase *TCase_pico_dns_ipv6_set_ptr = tcase_create("Unit test for 'pico_dns_ipv6_set_ptr'");

    tcase_add_test(TCase_dns_rdata_cmp, tc_dns_rdata_cmp);
    tcase_add_test(TCase_dns_question_cmp, tc_dns_question_cmp);
    tcase_add_test(TCase_dns_qtree_insert, tc_dns_qtree_insert);
    tcase_add_test(TCase_dns_record_cmp, tc_dns_record_cmp);
    tcase_add_test(TCase_dns_rtree_insert, tc_dns_rtree_insert);
    tcase_add_test(TCase_dns_record_cmp_name_type, tc_dns_record_cmp_name_type);
    tcase_add_test(TCase_pico_dns_fill_packet_header, tc_pico_dns_fill_packet_header);
    tcase_add_test(TCase_pico_dns_fill_packet_rr_sections, tc_pico_dns_fill_packet_rr_sections);
    tcase_add_test(TCase_pico_dns_fill_packet_question_section, tc_pico_dns_fill_packet_question_section);
    tcase_add_test(TCase_pico_dns_packet_compress_find_ptr, tc_pico_dns_packet_compress_find_ptr);
    tcase_add_test(TCase_pico_dns_packet_compress_name, tc_pico_dns_packet_compress_name);
    tcase_add_test(TCase_pico_dns_packet_compress, tc_pico_dns_packet_compress);
    tcase_add_test(TCase_pico_dns_question_fill_qsuffix, tc_pico_dns_question_fill_qsuffix);
    tcase_add_test(TCase_pico_dns_question_delete, tc_pico_dns_question_delete);
    tcase_add_test(TCase_pico_dns_question_create, tc_pico_dns_question_create);
    tcase_add_test(TCase_pico_dns_query_create, tc_pico_dns_query_create);
    tcase_add_test(TCase_pico_dns_record_fill_suffix, tc_pico_dns_record_fill_suffix);
    tcase_add_test(TCase_pico_dns_record_copy_flat, tc_pico_dns_record_copy_flat);
    tcase_add_test(TCase_pico_dns_record_copy, tc_pico_dns_record_copy);
    tcase_add_test(TCase_pico_dns_record_delete, tc_pico_dns_record_delete);
    tcase_add_test(TCAse_pico_dns_record_create, tc_pico_dns_record_create);
    tcase_add_test(TCase_pico_dns_answer_create, tc_pico_dns_answer_create);
    tcase_add_test(TCase_pico_dns_namelen_comp, tc_pico_dns_namelen_comp);
    tcase_add_test(TCase_pico_dns_decompress_name, tc_pico_dns_decompress_name);
    tcase_add_test(TCase_pico_dns_url_get_reverse_len, tc_pico_dns_url_get_reverse_len);
    tcase_add_test(TCase_pico_dns_url_to_reverse_qname, tc_pico_dns_url_to_reverse_qname);
    tcase_add_test(TCase_pico_dns_qname_to_url, tc_pico_dns_qname_to_url);
    tcase_add_test(TCase_pico_dns_url_to_qname, tc_pico_dns_url_to_qname);
    tcase_add_test(TCase_pico_dns_name_to_dns_notation, tc_pico_dns_name_to_dns_notation);
    tcase_add_test(TCase_pico_dns_notation_to_name, tc_pico_dns_notation_to_name);
    tcase_add_test(TCase_pico_dns_mirror_addr, tc_pico_dns_mirror_addr);
    tcase_add_test(TCase_dns_ptr_ip6_nibble_lo, tc_dns_ptr_ip6_nibble_lo);
    tcase_add_test(TCase_dns_ptr_ip6_nibble_hi, tc_dns_ptr_ip6_nibble_hi);
    tcase_add_test(TCase_pico_dns_ipv6_set_ptr, tc_pico_dns_ipv6_set_ptr);

    suite_add_tcase(s, TCase_dns_rdata_cmp);
    suite_add_tcase(s, TCase_dns_question_cmp);
    suite_add_tcase(s, TCase_dns_qtree_insert);
    suite_add_tcase(s, TCase_dns_record_cmp);
    suite_add_tcase(s, TCase_dns_rtree_insert);
    suite_add_tcase(s, TCase_dns_record_cmp_name_type);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_header);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_rr_sections);
    suite_add_tcase(s, TCase_pico_dns_fill_packet_question_section);
    suite_add_tcase(s, TCase_pico_dns_packet_compress_find_ptr);
    suite_add_tcase(s, TCase_pico_dns_packet_compress_name);
    suite_add_tcase(s, TCase_pico_dns_packet_compress);
    suite_add_tcase(s, TCase_pico_dns_question_fill_qsuffix);
    suite_add_tcase(s, TCase_pico_dns_question_delete);
    suite_add_tcase(s, TCase_pico_dns_question_create);
    suite_add_tcase(s, TCase_pico_dns_query_create);
    suite_add_tcase(s, TCase_pico_dns_record_fill_suffix);
    suite_add_tcase(s, TCase_pico_dns_record_copy);
    suite_add_tcase(s, TCase_pico_dns_record_delete);
    suite_add_tcase(s, TCAse_pico_dns_record_create);
    suite_add_tcase(s, TCase_pico_dns_answer_create);
    suite_add_tcase(s, TCase_pico_dns_namelen_comp);
    suite_add_tcase(s, TCase_pico_dns_decompress_name);
    suite_add_tcase(s, TCase_pico_dns_url_get_reverse_len);
    suite_add_tcase(s, TCase_pico_dns_url_to_reverse_qname);
    suite_add_tcase(s, TCase_pico_dns_qname_to_url);
    suite_add_tcase(s, TCase_pico_dns_url_to_qname);
    suite_add_tcase(s, TCase_pico_dns_name_to_dns_notation);
    suite_add_tcase(s, TCase_pico_dns_notation_to_name);
    suite_add_tcase(s, TCase_pico_dns_mirror_addr);
    suite_add_tcase(s, TCase_dns_ptr_ip6_nibble_lo);
    suite_add_tcase(s, TCase_dns_ptr_ip6_nibble_hi);
    suite_add_tcase(s, TCase_pico_dns_ipv6_set_ptr);

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

