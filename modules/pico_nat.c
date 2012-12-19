/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Authors: Kristof Roelants, Brecht Van Cauwenberghe,
         Simon Maes, Philippe Mariman
*********************************************************************/

#include "pico_stack.h"
#include "pico_frame.h"
#include "pico_tcp.h"
#include "pico_udp.h"
#include "pico_ipv4.h"
#include "pico_addressing.h"
#include "pico_nat.h"


struct __attribute__((packed)) tcp_pseudo_hdr_ipv4
{
  struct pico_ip4 src;
  struct pico_ip4 dst;
  uint16_t tcp_len;
  uint8_t res;
  uint8_t proto;
};


struct pico_nat_key {
  uint32_t private_addr;
  uint16_t private_port;
  uint8_t proto;
  uint32_t nat_addr;
  uint16_t nat_port;
 
  /* Connector for trees */
  RB_ENTRY(pico_nat_key) node;
};


struct pico_ipv4_link
{
  struct pico_device *dev;
  struct pico_ip4 address;
  struct pico_ip4 netmask;
  RB_ENTRY(pico_ipv4_link) node;
};


static struct pico_ipv4_link nat_link;


static int nat_cmp(struct pico_nat_key *a, struct pico_nat_key *b)
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


struct pico_nat_key *pico_ipv4_nat_get_key(uint8_t proto, uint16_t nat_port)
{
  struct pico_nat_key test;
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


int pico_ipv4_nat_generate_key(struct pico_nat_key* nk, struct pico_frame* f, struct pico_ip4 nat_addr)
{
  uint16_t portkey = 0;
  struct pico_trans *trans_hdr = NULL;  /* forced to use pico_trans */
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;
  
  do {
    /* 1. generate valid new NAT port entry */
    while (portkey < 1024) {
      portkey = (uint16_t)(0x0000FFF & pico_rand());    
    }
    
    /* 2. check if already in table, if no exit */
    if (pico_ipv4_nat_find(0,0,proto,portkey) == -1)
      break;
  
  } while (1);
  

  if (proto == PICO_PROTO_TCP) {  
    trans_hdr = (struct pico_trans *) f->transport_hdr;
    if (!trans_hdr)
      return -1;
  } else if (proto == PICO_PROTO_UDP) {
    trans_hdr = (struct pico_trans *) f->transport_hdr;
    if (!trans_hdr)
      return -1;
  }

  nk->private_addr = ipv4_hdr->src.addr;
  nk->private_port = trans_hdr->sport;
  nk->proto = f->proto;
  nk->nat_addr = nat_addr.addr; /* get public ip address from device */
  nk->nat_port = portkey;

  if (pico_ipv4_nat_add(nk->private_addr,nk->private_port,nk->proto,nk->nat_addr,nk->nat_port) < 0)
    return -1;
  else
    return 0;
}


static int pico_nat_tcp_checksum(struct pico_frame *f)
{
  struct pico_tcp_hdr *trans_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr;
  //struct pico_socket *s = f->sock;
  struct tcp_pseudo_hdr_ipv4 pseudo;
  if (!trans_hdr || !net_hdr)
    return -1;

  pseudo.src.addr = net_hdr->src.addr;
  pseudo.dst.addr = net_hdr->dst.addr;
  pseudo.res = 0;
  pseudo.proto = PICO_PROTO_TCP;
  pseudo.tcp_len = short_be(f->transport_len);

  trans_hdr->crc = 0;
  trans_hdr->crc = pico_dualbuffer_checksum(&pseudo, sizeof(struct tcp_pseudo_hdr_ipv4), trans_hdr, f->transport_len);
  trans_hdr->crc = short_be(trans_hdr->crc);
  return 0;
}


int pico_ipv4_nat_translate(struct pico_nat_key* nk, struct pico_frame* f)
{
  struct pico_trans *trans_hdr = NULL;

  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;
  
  if (proto == PICO_PROTO_TCP) {
    trans_hdr = (struct pico_trans *) f->transport_hdr;
    if (!trans_hdr)
      return -1;
  } else if (proto == PICO_PROTO_UDP) {  
    trans_hdr = (struct pico_trans *) f->transport_hdr;
    if (!trans_hdr)
      return -1;
  }

  //if(f->proto == PICO_PROTO_ICMP){
  //}

  ipv4_hdr->src.addr = nk->nat_addr;
  trans_hdr->sport = nk->nat_port;

  if (proto == PICO_PROTO_TCP) {
    pico_nat_tcp_checksum(f);
  } else if (proto == PICO_PROTO_UDP){
    pico_udp_checksum(f);
  }

  // pico_ipv4_checksum(f);
  ipv4_hdr->crc = 0;
  ipv4_hdr->crc = short_be(pico_checksum(ipv4_hdr, PICO_SIZE_IP4HDR));

  return 0;
}


int pico_ipv4_nat_port_forward(struct pico_frame* f)
{
  struct pico_nat_key *nk = NULL;
  struct pico_trans *trans_hdr = NULL;

  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1;

  uint8_t proto = ipv4_hdr->proto; 

  if (proto == PICO_PROTO_TCP) {
    trans_hdr = (struct pico_trans *) f->transport_hdr;
    if (!trans_hdr)
      return -1;
  } else if (proto == PICO_PROTO_UDP) {  
    trans_hdr = (struct pico_trans *) f->transport_hdr;
    if (!trans_hdr)
      return -1;
  }

  /* get nat key on basis of NATPORT and NATPROTO */
  nk = pico_ipv4_nat_get_key(proto,trans_hdr->dport);

  if (!nk)
    return -1;

  /* change destination parameters from nat key */
  ipv4_hdr->dst.addr = nk->private_addr;
  trans_hdr->dport = nk->private_port;

  if (proto == PICO_PROTO_TCP) {
    pico_nat_tcp_checksum(f);
  } else if (proto == PICO_PROTO_UDP) {
    pico_udp_checksum(f);
  }

  ipv4_hdr->crc = 0;
  ipv4_hdr->crc = short_be(pico_checksum(ipv4_hdr, PICO_SIZE_IP4HDR));
 
  return 0; 
}



int pico_ipv4_nat(struct pico_frame *f, struct pico_ip4 nat_addr)
{
  /*do nat---------*/
  struct pico_nat_key *nk = NULL;
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr; 
  struct pico_trans *trans_hdr = (struct pico_trans *) f->transport_hdr; 
  int ret;
  uint8_t proto = net_hdr->proto;
  uint16_t portkey = trans_hdr->dport;

  /* TODO DELME check if IN */
  if (nat_addr.addr == net_hdr->dst.addr) {
    ret = pico_ipv4_nat_port_forward(f);  /* our OUT definition */
  } else {
    ret = pico_ipv4_nat_find(0,0,proto,portkey);
    
    if (ret != 0)
      pico_ipv4_nat_generate_key(nk, f, nat_addr); 

    pico_ipv4_nat_translate(nk, f);       /* our OUT definition */
  } 

  return 0;
}


int pico_ipv4_nat_enable(struct pico_ipv4_link *link)
{
   nat_link = *link;

  return 0;
}


int pico_ipv4_nat_isenabled_out(struct pico_ipv4_link *link)
{
  // is nat_linl = *link
  if (nat_link.address.addr == link->address.addr)
    return 0;
  else
    return -1;
}


int pico_ipv4_nat_isenabled_in(struct pico_frame *f)
{
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr; 
  struct pico_trans *trans_hdr = (struct pico_trans *) f->transport_hdr; 
  int ret;
  uint8_t proto = net_hdr->proto;
  uint16_t portkey = trans_hdr->dport;

  ret = pico_ipv4_nat_find(0,0,proto,portkey);

  if (ret == 0)
    return 0;
  else
    return -1;
}
