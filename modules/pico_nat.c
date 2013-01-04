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


#define nat_dbg(...) do{}while(0)
//#define nat_dbg dbg

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
	uint16_t del_flags; 
  /* Connector for trees */
  RB_ENTRY(pico_nat_key) node;
};


static struct pico_ipv4_link nat_link;

static int nat_cmp_nat_port(struct pico_nat_key *a, struct pico_nat_key *b)
{
  nat_dbg(">nat_cmp_nat_port\n");
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

static int nat_cmp_priv_port(struct pico_nat_key *a, struct pico_nat_key *b)
{
  nat_dbg(">nat_cmp_priv_port\n");
  if (a->private_addr < b->private_addr) {
    return -1;
  }
  else if (a->private_addr > b->private_addr) {
    return 1;
  }
  else {
    if (a->private_port < b->private_port) {
      return -1;
    }
    else if (a->private_port > b->private_port) {
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
}

static int nat_cmp(struct pico_nat_key *a, struct pico_nat_key *b)
{
  nat_dbg(">nat_cmp\n");
  /* Structure elements left blank have to be zeroed */
  if (a->private_port)
    return nat_cmp_priv_port(a,b);
  else
    return nat_cmp_nat_port(a,b);
}


RB_HEAD(nat_table, pico_nat_key);
RB_PROTOTYPE_STATIC(nat_table, pico_nat_key, node, nat_cmp);
RB_GENERATE_STATIC(nat_table, pico_nat_key, node, nat_cmp);


static struct nat_table KEYTable;

/* 
  2 options: 
    find on proto and nat_port 
    find on private_addr, private_port and proto 
  zero the unused parameters 
*/
static struct pico_nat_key *pico_ipv4_nat_find_key(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint16_t nat_port)
{
  nat_dbg(">pico_ipv4_nat_find_key called...\n");
  struct pico_nat_key test = {0};
  test.private_addr = private_addr;
  test.private_port = private_port;
  test.proto = proto;
  test.nat_port = nat_port;
  /* returns NULL if test can not be found */ 
  return RB_FIND(nat_table, &KEYTable, &test);
}

int pico_ipv4_nat_find(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint16_t nat_port)
{
  nat_dbg(">pico_ipv4_nat_find called...\n");
  struct pico_nat_key *k = NULL;

  k = pico_ipv4_nat_find_key(private_addr, private_port, proto, nat_port); 
  if (k)
    return 0;
  else
    return -1;
}

int pico_ipv4_nat_add(uint32_t private_addr, uint16_t private_port, uint8_t proto, uint32_t nat_addr, uint16_t nat_port)
{
  nat_dbg(">pico_ipv4_nat_add called\n");
  struct pico_nat_key *key = pico_zalloc(sizeof(struct pico_nat_key));
  if (!key) {
    //pico_err = PICO_ERR_ENOMEM;
    return -1;
  }

  key->private_addr = private_addr;
  key->private_port = private_port;
  key->proto = proto;
  key->nat_addr = nat_addr;
  key->nat_port = nat_port;
  key->del_flags = 0x0001; /* set conn active to 1, other flags to 0 */

  if (RB_INSERT(nat_table, &KEYTable, key))
    return -1; /* Element key already exists */
  else
    return 0; /* New element added */
}


int pico_ipv4_nat_del(uint8_t proto, uint16_t nat_port)
{
  nat_dbg(">pico_ipv4_nat_del\n");
  struct pico_nat_key *key = NULL;
  key = pico_ipv4_nat_find_key(0,0,proto, nat_port);
  if (!key) {
    nat_dbg("DEL: key not found: proto %u | nat_port %u\n", proto, nat_port);
    return -1;
  }
  else {
    nat_dbg("DEL: key found: proto %u | nat_port %u\n", proto, nat_port);  
    if (!RB_REMOVE(nat_table, &KEYTable, key))
      return -1; /* Error on removing element, do not free! */
	pico_free(key);
  }
  return 0;
}


void pico_ipv4_nat_print_table(void)
{
  nat_dbg(">pico_ipv4_nat_print_table\n");
  struct pico_nat_key *k = NULL;
  uint16_t i = 0;

  nat_dbg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  nat_dbg("+                                                NAT table                                                 +\n");
  nat_dbg("+----------------------------------------------------------------------------------------------------------+\n");
  nat_dbg("+  nr  | private_addr | private_port | proto | nat_addr | nat_port | conn active | FIN1 | FIN2 | SYN | RST +\n");
  nat_dbg("+----------------------------------------------------------------------------------------------------------+\n");

  RB_FOREACH(k, nat_table, &KEYTable) {
    nat_dbg("+ %04d |   %08X   |     %04u     |  %04u | %08X |   %04u   |     %03u     |   %u  |   %u  |  %u  |  %u  +\n", 
           i, k->private_addr, k->private_port, k->proto, k->nat_addr, k->nat_port, (k->del_flags)&0x01FF, 
           ((k->del_flags)&0x8000)>>15, ((k->del_flags)&0x4000)>>14, ((k->del_flags)&0x2000)>>13, ((k->del_flags)&0x1000)>>12);
    i++;
  }
  nat_dbg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

int pico_ipv4_nat_generate_key(struct pico_nat_key* nk, struct pico_frame* f, struct pico_ip4 nat_addr)
{
  nat_dbg(">pico_ipv4_nat_generate_key\n");
  uint16_t nat_port = 0;
  struct pico_tcp_hdr *tcp_hdr = NULL;  /* forced to use pico_trans */
  struct pico_udp_hdr *udp_hdr = NULL;  /* forced to use pico_trans */
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;
  do {
    do { 
      /* 1. generate valid new NAT port entry */
      nat_port = (uint16_t)(0x0000FFF & pico_rand());    
    } while (nat_port < 1024); 

    /* 2. check if already in table, if no exit */
    nat_dbg("check (nat_key, proto) -> (proto, src_ip, src_port)\n");
    if (pico_ipv4_nat_find(0,0,proto,nat_port) == -1)
      break;
  
  } while (1);
    
  nat_dbg("check for pico proto is tcp/udp: ");
  if (proto == PICO_PROTO_TCP) {  
    nat_dbg(" >>TCP\n");
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    nk->private_port = tcp_hdr->trans.sport; 
  } else if (proto == PICO_PROTO_UDP) {
    nat_dbg(" >>UDP\n");
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    nk->private_port = udp_hdr->trans.sport; 
  }

  nk->private_addr = ipv4_hdr->src.addr;
  nk->proto = ipv4_hdr->proto;
  nk->nat_addr = nat_addr.addr; /* get public ip address from device */
  nk->nat_port = nat_port;

  if (pico_ipv4_nat_add(nk->private_addr,nk->private_port,nk->proto,nk->nat_addr,nk->nat_port) < 0){
    return -1;
  }else{
    return 0;
  }
}


static int pico_nat_tcp_checksum(struct pico_frame *f)
{
  nat_dbg(">pico_ipv4_nat_tcp_checksum\n");
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
  nat_dbg(">pico_ipv4_nat_translate\n");
  //struct pico_trans *trans_hdr = NULL;

  struct pico_tcp_hdr *tcp_hdr = NULL;  /* forced to use pico_trans */
  struct pico_udp_hdr *udp_hdr = NULL;  /* forced to use pico_trans */

  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;
  
  if (proto == PICO_PROTO_TCP) {
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    tcp_hdr->trans.sport = nk->nat_port;
  } else if (proto == PICO_PROTO_UDP) {  
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    udp_hdr->trans.sport = nk->nat_port;
  }

  //if(f->proto == PICO_PROTO_ICMP){
  //}

  ipv4_hdr->src.addr = nk->nat_addr;

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
  nat_dbg(">pico_ipv4_nat_port_forward\n");
  struct pico_nat_key *nk = NULL;
  struct pico_tcp_hdr *tcp_hdr = NULL;
  struct pico_udp_hdr *udp_hdr = NULL; 
  uint16_t nat_port=0; 

  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1; 
  uint8_t proto = ipv4_hdr->proto; 
  
  if (proto == PICO_PROTO_TCP) {
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    nat_port= tcp_hdr->trans.dport;  
  } else if (proto == PICO_PROTO_UDP) {  
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    nat_port= udp_hdr->trans.dport;
  }

  nk = pico_ipv4_nat_find_key(0,0,proto,nat_port);

  if (!nk){
    nat_dbg("nk not found\n");
    return -1;
  }else{
    ipv4_hdr->dst.addr=nk->private_addr;
    if (proto == PICO_PROTO_TCP) {
       tcp_hdr->trans.dport=nk->private_port;
       pico_nat_tcp_checksum(f);
    } else if (proto == PICO_PROTO_UDP) {
      udp_hdr->trans.dport=nk->private_port;
      pico_udp_checksum(f);
    }
  }


  ipv4_hdr->crc = 0;
  ipv4_hdr->crc = short_be(pico_checksum(ipv4_hdr, PICO_SIZE_IP4HDR));
 
  return 0; 
}



int pico_ipv4_nat(struct pico_frame *f, struct pico_ip4 nat_addr)
{
  nat_dbg(">pico_ipv4_nat\n");
  /*do nat---------*/
  struct pico_nat_key *nk = NULL;
  struct pico_nat_key key;
  nk= &key;
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr; 

  struct pico_tcp_hdr *tcp_hdr = NULL;  
  struct pico_udp_hdr *udp_hdr = NULL;  
  struct pico_trans *trans_hdr = (struct pico_trans *) f->transport_hdr; 
  int ret;
  uint8_t proto = net_hdr->proto;
  uint16_t private_port = 0;

  uint32_t private_addr= net_hdr->src.addr;

  /* TODO DELME check if IN */
  if (nat_addr.addr == net_hdr->dst.addr) {
    nat_dbg("Forward\n");
    ret = pico_ipv4_nat_port_forward(f);  /* IN our  definition */
  } else {
    nat_dbg("Search if key allready exists in tree\n");
    if (net_hdr->proto == PICO_PROTO_TCP) {
      tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      private_port = tcp_hdr->trans.sport;
    } else if (net_hdr->proto == PICO_PROTO_UDP) {
      udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      private_port = udp_hdr->trans.sport;
    }
    ret = pico_ipv4_nat_find(private_addr,private_port,proto,0);
   pico_ipv4_nat_print_table(); 
    if (ret>=0){
      // Key is available in table
      nk = pico_ipv4_nat_find_key(private_addr,private_port,proto,0);
    }else{
      nat_dbg("Generate key\n");
      pico_ipv4_nat_generate_key(nk, f, nat_addr);
    }
    pico_ipv4_nat_translate(nk, f);       /* our OUT definition */
  } 
  nat_dbg("<pico_ipv4_nat\n");
  return 0;
}


int pico_ipv4_nat_enable(struct pico_ipv4_link *link)
{
  nat_dbg(">pico_ipv4_nat_enable\n");
  nat_link = *link;
  return 0;
}


int pico_ipv4_nat_isenabled_out(struct pico_ipv4_link *link)
{
  nat_dbg(">pico_ipv4_nat_isenabled_out\n");
  // is nat_linl = *link
  if (nat_link.address.addr == link->address.addr)
    return 0;
  else
    return -1;
}


int pico_ipv4_nat_isenabled_in(struct pico_frame *f)
{
  nat_dbg(">pico_ipv4_nat_isenabled_in\n");
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr; 
  struct pico_trans *trans_hdr = (struct pico_trans *) f->transport_hdr; 
  int ret;
  uint8_t proto = net_hdr->proto;
  uint16_t nat_port = trans_hdr->dport;
  nat_dbg("search proto , portkey -> ipsrc src port\n");
  ret = pico_ipv4_nat_find(0,0,proto,nat_port);

  if (ret == 0)
    return 0;
  else
    return -1;
}
