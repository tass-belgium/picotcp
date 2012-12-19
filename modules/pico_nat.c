/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Kristof Roelants
*********************************************************************/

#include "pico_nat.h"

struct pico_nat_key {
  uint32_t private_addr;
  uint16_t private_port;
  uint8_t proto;
  uint32_t nat_addr;
  uint16_t nat_port;
 
  /* Connector for trees */
  RB_ENTRY(pico_nat_key) node;
};

int nat_cmp(struct pico_nat_key *a, struct pico_nat_key *b)
{
  if (a->nat_port < b->nat_port) {
    return -1;
  }
  else if (a->nat_port > b->nat_port) {
    return 1;
  }
  else {
    if (a->proto < b->proto) {
      return -1;
    }
    else if (a->proto > b->proto) {
      return 1;
    }
	else {
      /* a and b are identical */
      return 0;
    }
  }
}

RB_HEAD(nat_table, pico_nat_key);
RB_PROTOTYPE_STATIC(nat_table, pico_nat_key, node, nat_cmp);
RB_GENERATE_STATIC(nat_table, pico_nat_key, node, nat_cmp);

static struct nat_table KEYTable;

static struct pico_nat_key *pico_ipv4_nat_get_key(uint8_t proto, uint16_t nat_port)
{
  struct pico_nat_key test, *found = NULL;
  test.proto = proto;
  test.nat_port = nat_port;
  /* returns NULL if test can not be found */
  return RB_FIND(nat_table, &KEYTable, &test);
}

int pico_ipv4_nat_find(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint16_t nat_port)
{
  struct pico_nat_key *k = NULL;
  RB_FOREACH(k, nat_table, &KEYTable) {
    if (k->private_addr == private_addr || private_addr == 0)
      if (k->private_port == private_port || private_port == 0)
        if (k->nat_port == nat_port || nat_port == 0)
          if (k->proto == proto)
            return 0;
  }
  return -1;
}

int pico_ipv4_nat_add(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint32_t nat_addr, uint16_t nat_port)
{
  struct pico_nat_key *key = pico_zalloc(sizeof(struct pico_nat_key));
  if (!key) {
    //pico_err = PICO_ERR_ENOMEM;
    return -1;
  }

  dbg("Creating nat_table entry\n");
  key->private_addr = private_addr;
  key->private_port = private_port;
  key->proto = proto;
  key->nat_addr = nat_addr;
  key->nat_port = nat_port;

  if (RB_INSERT(nat_table, &KEYTable, key))
    return -1; /* Element key already exists */
  else
    return 0; /* New element added */
}

int pico_ipv4_nat_del(uint8_t proto, uint16_t nat_port)
{
  struct pico_nat_key *key = NULL;
  key = pico_ipv4_nat_get_key(proto, nat_port);
  if (!key) {
    dbg("DEL: key not found: proto %u | nat_port %u\n", proto, nat_port);
    return -1;
  }
  else {
    dbg("DEL: key found: proto %u | nat_port %u\n", proto, nat_port);  
    if (!RB_REMOVE(nat_table, &KEYTable, key))
      return -1; /* Error on removing element, do not free! */
    
	pico_free(key);
  }

  return 0;
}

void pico_ipv4_nat_print_table(void)
{
  struct pico_nat_key *k = NULL;
  RB_FOREACH(k, nat_table, &KEYTable) {
    dbg("NAT entry: private_addr %08X | private_port %u | proto %u | nat_addr %08X | nat_port %u\n",
          k->private_addr, k->private_port, k->proto, k->nat_addr, k->nat_port);
  }
}

