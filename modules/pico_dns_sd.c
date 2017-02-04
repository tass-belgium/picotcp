/*********************************************************************
   PicoTCP. Copyright (c) 2014-2017 Altran Intelligent Systems. Some rights reserved.
   See COPYING, LICENSE.GPLv2 and LICENSE.GPLv3 for usage.
   .
   Author: Jelle De Vleeschouwer
 *********************************************************************/

#include "pico_dns_sd.h"

#ifdef PICO_SUPPORT_DNS_SD

/* --- Debugging --- */
#ifdef DEBUG_DNS_SD
    #define dns_sd_dbg dbg
#else
    #define dns_sd_dbg(...) do {} while(0)
#endif

/* --- PROTOTYPES --- */
key_value_pair_t *
pico_dns_sd_kv_vector_get( kv_vector *vector, uint16_t index );
int
pico_dns_sd_kv_vector_erase( kv_vector *vector );
/* ------------------- */

typedef PACKED_STRUCT_DEF pico_dns_srv_record_prefix
{
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
} pico_dns_srv_record;

/* ****************************************************************************
 *  Determines the length of the resulting string when a string would be
 *  created from a key-value pair vector.
 *
 *  @param vector Key-Value pair vector to determine the length of.
 *  @return The length of the key-value pair vector in bytes as if it would be
 *			converted to a string.
 * ****************************************************************************/
static uint16_t
pico_dns_sd_kv_vector_strlen( kv_vector *vector )
{
    key_value_pair_t *iterator = NULL;
    uint16_t i = 0, len = 0;

    /* Check params */
    if (!vector) {
        pico_err = PICO_ERR_EINVAL;
        return 0;
    }

    /* Iterate over the key-value pairs */
    for (i = 0; i < vector->count; i++) {
        iterator = pico_dns_sd_kv_vector_get(vector, i);
        len = (uint16_t) (len + 1u + /* Length byte */
                          strlen(iterator->key) /* Length of the key */);
        if (iterator->value) {
            len = (uint16_t) (len + 1u /* '=' char */ +
                              strlen(iterator->value) /* Length of value */);
        }
    }
    return len;
}

/* ****************************************************************************
 *  Creates an mDNS record with the SRV record format.
 *
 *  @param url        Name of the SRV record in URL format.
 *  @param priority   Priority, should be 0.
 *  @param weight     Weight, should be 0.
 *  @param port       Port to register the service on.
 *  @param target_url Hostname of the service-target, in URL-format
 *  @param ttl        TTL of the SRV Record
 *  @param flags      mDNS record flags to set specifications of the record.
 *  @return Pointer to newly created record on success, NULL on failure.
 * ****************************************************************************/
static struct pico_mdns_record *
pico_dns_sd_srv_record_create( const char *url,
                               uint16_t priority,
                               uint16_t weight,
                               uint16_t port,
                               const char *target_url,
                               uint32_t ttl,
                               uint8_t flags )
{
    struct pico_mdns_record *record = NULL;
    pico_dns_srv_record *srv_data = NULL;
    char *target_rname = NULL;
    uint16_t srv_length = 0;

    /* Check params */
    if (!url || !target_url) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Determine the length the rdata buf needs to be */
    srv_length = (uint16_t) (6u + strlen(target_url) + 2u);

    /* Provide space for the data-buf */
    if (!(srv_data = (pico_dns_srv_record *) PICO_ZALLOC(srv_length))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Set the fields */
    srv_data->priority = short_be(priority);
    srv_data->weight = short_be(weight);
    srv_data->port = short_be(port);

    /* Copy in the URL and convert to DNS notation */
    if (!(target_rname = pico_dns_url_to_qname(target_url))) {
        dns_sd_dbg("Could not convert URL to qname!\n");
        PICO_FREE(srv_data);
        return NULL;
    }

    strcpy((char *)srv_data + 6u, target_rname);
    PICO_FREE(target_rname);

    /* Create and return new mDNS record */
    record = pico_mdns_record_create(url, srv_data, srv_length,
                                     PICO_DNS_TYPE_SRV,
                                     ttl, flags);
    PICO_FREE(srv_data);
    return record;
}

/* ****************************************************************************
 *  Creates an mDNS record with the TXT record format.
 *
 *  @param url             Name of the TXT record in URL format.
 *  @param key_value_pairs Key-Value pair vector to generate the data from.
 *  @param ttl             TTL of the TXT record.
 *  @param flags           mDNS record flags to set specifications of the record
 *  @return Pointer to newly created record on success, NULL on failure.
 * ****************************************************************************/
static struct pico_mdns_record *
pico_dns_sd_txt_record_create( const char *url,
                               kv_vector key_value_pairs,
                               uint32_t ttl,
                               uint8_t flags )
{
    struct pico_mdns_record *record = NULL;
    key_value_pair_t *iterator = NULL;
    char *txt = NULL;
    uint16_t i = 0, txt_i = 0, pair_len = 0, key_len = 0, value_len = 0;

    /* Determine the length of the string to fit in all pairs */
    uint16_t len = (uint16_t)(pico_dns_sd_kv_vector_strlen(&key_value_pairs) + 1u);

    /* If kv-vector is empty don't bother to create a TXT record */
    if (len <= 1) {
        return NULL;
    }

    /* Provide space for the txt buf */
    if (!(txt = (char *)PICO_ZALLOC(len))) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Iterate over all the key-value pairs */
    for (i = 0; i < key_value_pairs.count; i++) {
        iterator = pico_dns_sd_kv_vector_get(&key_value_pairs, i);

        /* Determine the length of the key */
        key_len = (uint16_t) strlen(iterator->key);
        pair_len = key_len;

        /* If value is not a NULL-ptr */
        if (iterator->value) {
            value_len = (uint16_t) strlen(iterator->value);
            pair_len = (uint16_t) (pair_len + 1u + value_len);
        }

        /* Set the pair length label */
        txt[txt_i] = (char)pair_len;

        /* Copy the key */
        strcpy(txt + txt_i + 1u, iterator->key);

        /* Copy the value if it is not a NULL-ptr */
        if (iterator->value) {
            strcpy(txt + txt_i + 1u + key_len, "=");
            strcpy(txt + txt_i + 2u + key_len, iterator->value);
            txt_i = (uint16_t) (txt_i + 2u + key_len + value_len);
        } else {
            txt_i = (uint16_t) (txt_i + 1u + key_len);
        }
    }
    record = pico_mdns_record_create(url, txt, (uint16_t)(len - 1u), PICO_DNS_TYPE_TXT, ttl, flags);
    PICO_FREE(txt);

    return record;
}

/* ****************************************************************************
 *  Deletes a single key-value pair instance
 *
 *  @param kv_pair Pointer-pointer to to delete instance
 *  @return Returns 0 on success, something else on failure.
 * ****************************************************************************/
static int
pico_dns_sd_kv_delete( key_value_pair_t **kv_pair )
{
    /* Check params */
    if (!kv_pair || !(*kv_pair)) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    /* Delete the fields */
    if ((*kv_pair)->key)
        PICO_FREE((*kv_pair)->key);

    if ((*kv_pair)->value)
        PICO_FREE((*kv_pair)->value);

    PICO_FREE(*kv_pair);
    *kv_pair = NULL;
    kv_pair = NULL;

    return 0;
}

/* ****************************************************************************
 *  Creates a single key-value pair-instance
 *
 *  @param key    Key of the pair, cannot be NULL.
 *  @param value  Value of the pair, can be NULL, empty ("") or filled ("qkejq")
 *  @return Pointer to newly created KV-instance on success, NULL on failure.
 * ****************************************************************************/
static key_value_pair_t *
pico_dns_sd_kv_create( const char *key, const char *value )
{
    key_value_pair_t *kv_pair = NULL;

    /* Check params */
    if (!key || !(kv_pair = PICO_ZALLOC(sizeof(key_value_pair_t)))) {
        pico_dns_sd_kv_delete(&kv_pair);
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    /* Provide space to copy the values */
    if (!(kv_pair->key = PICO_ZALLOC((size_t)(strlen(key) + 1)))) {
        pico_err = PICO_ERR_ENOMEM;
        pico_dns_sd_kv_delete(&kv_pair);
        return NULL;
    }

    strcpy(kv_pair->key, key);

    if (value) {
        if (!(kv_pair->value = PICO_ZALLOC((size_t)(strlen(value) + 1)))) {
            pico_err = PICO_ERR_ENOMEM;
            pico_dns_sd_kv_delete(&kv_pair);
            return NULL;
        }

        strcpy(kv_pair->value, value);
    } else
        kv_pair->value = NULL;

    return kv_pair;
}

/* ****************************************************************************
 *  Checks whether the type is correctly formatted ant it's label length are
 *  between the allowed boundaries.
 *
 *  @param type Servicetype to check the format of.
 *  @return Returns 0 when the type is correctly formatted, something else when
 *			it's not.
 * ****************************************************************************/
static int
pico_dns_sd_check_type_format( const char *type )
{
    uint16_t first_lbl = 0;
    int8_t subtype_present = 0;

    /* Check params */
    if (!(first_lbl = pico_dns_first_label_length(type)))
        return -1;

    subtype_present = !memcmp(type + first_lbl + 1, "_sub", 4);

    /* Check if there is a subtype present */
    if (subtype_present && (first_lbl > 63))
        return -1;
    else if (subtype_present)
        /* Get the length of the service name */
        first_lbl = pico_dns_first_label_length(type + first_lbl + 6);
    else {
        /* Check if type is not greater then 21 bytes (22 - 1, since the length
           byte of the service name isn't included yet) */
        if (strlen(type) > (size_t) 21)
            return -1;
    }

    /* Check if the service name is not greater then 16 bytes (17 - 1) */
    return (first_lbl > ((uint16_t) 16u));
}

/* ****************************************************************************
 *  Checks whether the service instance name is correctly formatted and it's
 *  label length falls between the allowed boundaries.
 *
 *  @param name Instance name to check the format of.
 *  @return Returns 0 when the name is correctly formatted, something else when
 *			it's not.
 * ****************************************************************************/
static int
pico_dns_sd_check_instance_name_format( const char *name )
{
    /* First of all check if the total length is larger than 63 bytes */
    if (pico_dns_strlen(name) > 63 || !pico_dns_strlen(name))
        return -1;

    return 0;
}

/* ****************************************************************************
 *  Append the instance name adn service type to create a '.local' service SIN.
 *
 *  @param name Instance Name of the service, f.e. "Printer 2nd Floor".
 *  @param type ServiceType of the service, f.e. "_http._tcp".
 *  @return Pointer to newly created SIN on success, NULL on failure.
 * ****************************************************************************/
static char *
pico_dns_sd_create_service_url( const char *name,
                                const char *type )
{
    char *url = NULL;
    uint16_t len = 0, namelen = 0, typelen = 0;

    if (pico_dns_sd_check_type_format(type)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    if (pico_dns_sd_check_instance_name_format(name)) {
        pico_err = PICO_ERR_EINVAL;
        return NULL;
    }

    namelen = (uint16_t)strlen(name);
    typelen = (uint16_t)strlen(type);

    /* Determine the length that the URL needs to be */
    len = (uint16_t)(namelen + 1u /* for '.'*/ +
                     typelen + 7u /* for '.local\0' */);
    url = (char *)PICO_ZALLOC(len);
    if (!url) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    /* Append the parts together */
    strcpy(url, name);
    strcpy(url + namelen, ".");
    strcpy(url + namelen + 1, type);
    strcpy(url + namelen + 1 + typelen, ".local");

    return url;
}

/* ****************************************************************************
 *  This function actually does exactly the same as pico_mdns_init();
 * ****************************************************************************/
int
pico_dns_sd_init( const char *_hostname,
                  struct pico_ip4 address,
                  void (*callback)(pico_mdns_rtree *,
                                   char *,
                                   void *),
                  void *arg )
{
    return pico_mdns_init(_hostname, address, callback, arg);
}

/* ****************************************************************************
 *  Just calls pico_mdns_init in its turn to initialise the mDNS-module.
 *  See pico_mdns.h for description.
 * ****************************************************************************/
int
pico_dns_sd_register_service( const char *name,
                              const char *type,
                              uint16_t port,
                              kv_vector *txt_data,
                              uint16_t ttl,
                              void (*callback)(pico_mdns_rtree *,
                                               char *,
                                               void *),
                              void *arg)
{
    PICO_MDNS_RTREE_DECLARE(rtree);
    struct pico_mdns_record *srv_record = NULL;
    struct pico_mdns_record *txt_record = NULL;
    const char *hostname = pico_mdns_get_hostname();
    char *url = NULL;

    /* Try to create a service URL to create records with */
    if (!(url = pico_dns_sd_create_service_url(name, type)) || !txt_data || !hostname) {
        if (url) {
            PICO_FREE(url);
        }

        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    dns_sd_dbg("\n>>>>>>>>>> Target: %s <<<<<<<<<<\n\n", hostname);

    /* Create the SRV record */
    srv_record = pico_dns_sd_srv_record_create(url, 0, 0, port, hostname, ttl, PICO_MDNS_RECORD_UNIQUE);
    if (!srv_record) {
        PICO_FREE(url);
        return -1;
    }

    /* Create the TXT record */
    txt_record = pico_dns_sd_txt_record_create(url, *txt_data, ttl, PICO_MDNS_RECORD_UNIQUE);
    PICO_FREE(url);

    /* Erase the key-value pair vector, it's no longer needed */
    pico_dns_sd_kv_vector_erase(txt_data);

    if (txt_record) {
        if (pico_tree_insert(&rtree, txt_record) == &LEAF) {
            PICO_MDNS_RTREE_DESTROY(&rtree);
            pico_mdns_record_delete((void **)&txt_record);
            pico_mdns_record_delete((void **)&srv_record);
            return -1;
        }
    }

    if (pico_tree_insert(&rtree, srv_record) == &LEAF) {
        PICO_MDNS_RTREE_DESTROY(&rtree);
        pico_mdns_record_delete((void **)&srv_record);
		return -1;
	}

    if (pico_mdns_claim(rtree, callback, arg)) {
        PICO_MDNS_RTREE_DESTROY(&rtree);
        return -1;
    }

    /* Only destroy the tree, not its elements since they still exist in another tree */
    pico_tree_destroy(&rtree, NULL);
    return 0;
}

/* ****************************************************************************
 *  Does nothing for now.
 *
 *  @param type     Type to browse for.
 *  @param callback Callback to call when something particular happens.
 *  @return When the module successfully started browsing the servicetype.
 * ****************************************************************************/
int
pico_dns_sd_browse_service( const char *type,
                            void (*callback)(pico_mdns_rtree *,
                                             char *,
                                             void *),
                            void *arg )
{
    IGNORE_PARAMETER(type);
    IGNORE_PARAMETER(callback);
    IGNORE_PARAMETER(arg);
    return 0;
}

/* ****************************************************************************
 *  Add a key-value pair the a key-value pair vector.
 *
 *  @param vector Vector to add the pair to.
 *  @param key    Key of the pair, cannot be NULL.
 *  @param value  Value of the pair, can be NULL, empty ("") or filled ("qkejq")
 *  @return Returns 0 when the pair is added successfully, something else on
 *			failure.
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_add( kv_vector *vector, char *key, char *value )
{
    key_value_pair_t *kv_pair = NULL;
    key_value_pair_t **new_pairs = NULL;
    uint16_t i = 0;

    /* Check params */
    if (!vector || !key || !(kv_pair = pico_dns_sd_kv_create(key, value))) {
        pico_err = PICO_ERR_EINVAL;
        pico_dns_sd_kv_delete(&kv_pair);
        return -1;
    }

    /* Provide enough space for the new pair pointers */
    if (!(new_pairs = PICO_ZALLOC(sizeof(key_value_pair_t *) *
                                  (vector->count + 1u)))) {
        pico_err = PICO_ERR_ENOMEM;
        pico_dns_sd_kv_delete(&kv_pair);
        return -1;
    }

    /* Copy previous pairs and add new one */
    for (i = 0; i < vector->count; i++)
        new_pairs[i] = vector->pairs[i];
    new_pairs[i] = kv_pair;

    /* Free the previous array */
    if (vector->pairs)
        PICO_FREE(vector->pairs);

    vector->pairs = new_pairs;
    vector->count++;

    return 0;
}

/* ****************************************************************************
 *  Gets a single key-value pair form a Key-Value pair vector @ certain index.
 *
 *  @param vector Vector to get KV-pair from.
 *  @param index  Index of the KV-pair.
 *  @return key_value_pair_t* on success, NULL on failure.
 * ****************************************************************************/
key_value_pair_t *
pico_dns_sd_kv_vector_get( kv_vector *vector, uint16_t index )
{
    /* Check params */
    if (!vector)
        return NULL;

    /* Return record with conditioned index */
    if (index < vector->count)
        return vector->pairs[index];

    return NULL;
}

/* ****************************************************************************
 *  Erase all the contents of a key-value pair vector.
 *
 *  @param vector Key-Value pair vector.
 *  @return 0 on success, something else on failure.
 * ****************************************************************************/
int
pico_dns_sd_kv_vector_erase( kv_vector *vector )
{
    uint16_t i = 0;

    /* Iterate over each key-value pair */
    for (i = 0; i < vector->count; i++) {
        if (pico_dns_sd_kv_delete(&(vector->pairs[i])) < 0) {
            dns_sd_dbg("Could not delete key-value pairs from vector");
            return -1;
        }
    }
    PICO_FREE(vector->pairs);
    vector->pairs = NULL;
    vector->count = 0;

    return 0;
}

#endif
