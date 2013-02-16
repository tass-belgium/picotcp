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

#ifdef PICO_SUPPORT_IPV4
#ifdef PICO_SUPPORT_NAT

#define nat_dbg(...) do{}while(0)
//#define nat_dbg dbg
#define NAT_TCP_TIMEWAIT 240000 /* 4mins (in msec) */
//#define NAT_TCP_TIMEWAIT 10000 /* 10 sec (in msec)  - for testing purposes only*/

struct __attribute__((packed)) tcp_pseudo_hdr_ipv4
{
  struct pico_ip4 src;
  struct pico_ip4 dst;
  uint16_t tcp_len;
  uint8_t res;
  uint8_t proto;
};

struct pico_nat_key {
  struct pico_ip4 pub_addr;
  uint16_t pub_port;
  struct pico_ip4 priv_addr;
  uint16_t priv_port;
  uint8_t proto;
  /*
  del_flags:
              1                   0 
    5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |F|B|S|R|P|~| CONNECTION ACTIVE |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  F: FIN from Forwarding packet
  B: FIN from Backwarding packet
  S: SYN 
  R: RST  
  P: Persistant
         
  */
  uint16_t del_flags;
  /* Connector for trees */
  RB_ENTRY(pico_nat_key) node_forward, node_backward;
};

static struct pico_ipv4_link pub_link;
static uint8_t enable_nat_flag = 0;

static int nat_cmp_backward(struct pico_nat_key *a, struct pico_nat_key *b)
{
  if (a->pub_port < b->pub_port) {
    return -1;
  }
  else if (a->pub_port > b->pub_port) {
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

static int nat_cmp_forward(struct pico_nat_key *a, struct pico_nat_key *b)
{
  if (a->priv_addr.addr < b->priv_addr.addr) {
    return -1;
  }
  else if (a->priv_addr.addr > b->priv_addr.addr) {
    return 1;
  }
  else {
    if (a->priv_port < b->priv_port) {
      return -1;
    }
    else if (a->priv_port > b->priv_port) {
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

RB_HEAD(nat_table_forward, pico_nat_key);
RB_PROTOTYPE_STATIC(nat_table_forward, pico_nat_key, node_forward, nat_cmp_forward);
RB_GENERATE_STATIC(nat_table_forward, pico_nat_key, node_forward, nat_cmp_forward);

RB_HEAD(nat_table_backward, pico_nat_key);
RB_PROTOTYPE_STATIC(nat_table_backward, pico_nat_key, node_backward, nat_cmp_backward);
RB_GENERATE_STATIC(nat_table_backward, pico_nat_key, node_backward, nat_cmp_backward);

static struct nat_table_forward KEYTable_forward;
static struct nat_table_backward KEYTable_backward;

/* 
  2 options: 
    find on proto and pub_port 
    find on priv_addr, priv_port and proto 
  zero the unused parameters 
*/
static struct pico_nat_key *pico_ipv4_nat_find_key(uint16_t pub_port, struct pico_ip4 *priv_addr, uint16_t priv_port, uint8_t proto)
{
  struct pico_nat_key test;
  test.pub_port = pub_port;
  test.priv_port = priv_port;
  test.proto = proto;
  if (priv_addr)
    test.priv_addr = *priv_addr;
  else
    test.priv_addr.addr = 0;

  /* returns NULL if test can not be found */ 
  if (!pub_port)
    return RB_FIND(nat_table_forward, &KEYTable_forward, &test);
  else
    return RB_FIND(nat_table_backward, &KEYTable_backward, &test);
}

int pico_ipv4_nat_find(uint16_t pub_port, struct pico_ip4 *priv_addr, uint16_t priv_port, uint8_t proto)
{
  struct pico_nat_key *k = NULL;

  k = pico_ipv4_nat_find_key(pub_port, priv_addr, priv_port, proto); 
  if (k)
    return 0;
  else
    return -1;
}

int pico_ipv4_nat_snif_forward(struct pico_nat_key *nk, struct pico_frame *f) {
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
 
  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;

  if (proto == PICO_PROTO_TCP) {
    struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    if (tcp_hdr->flags & PICO_TCP_FIN) {
      nk->del_flags |= PICO_DEL_FLAGS_FIN_FORWARD; //FIN from forwarding packet
    }
    if (tcp_hdr->flags & PICO_TCP_SYN) {
      nk->del_flags |= PICO_DEL_FLAGS_SYN; 
    }
    if (tcp_hdr->flags & PICO_TCP_RST) {
      nk->del_flags |= PICO_DEL_FLAGS_RST;
    }
  } else if (proto == PICO_PROTO_UDP) {
    /* set conn active to 1 */
    nk->del_flags &= 0xFE00; 
    nk->del_flags++;
  } 
  return 0; 
}


int pico_ipv4_nat_snif_backward(struct pico_nat_key *nk, struct pico_frame *f) {
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;

  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;

  if (proto == PICO_PROTO_TCP) {
    struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    if (tcp_hdr->flags & PICO_TCP_FIN) {
      nk->del_flags |= PICO_DEL_FLAGS_FIN_BACKWARD; //FIN from backwarding packet
    }
    if (tcp_hdr->flags & PICO_TCP_SYN) {
      nk->del_flags |= PICO_DEL_FLAGS_SYN;
    }
    if (tcp_hdr->flags & PICO_TCP_RST) {
      nk->del_flags |= PICO_DEL_FLAGS_RST;
    }
  } else if (proto == PICO_PROTO_UDP) {
    /* set conn active to 1 */
    nk->del_flags &= 0xFE00; 
    nk->del_flags++;
  }
  return 0;
}

void pico_ipv4_nat_table_cleanup(unsigned long now, void *_unused)
{
  nat_dbg("NAT: before table cleanup:\n");
  pico_ipv4_nat_print_table();

  struct pico_nat_key *k = NULL;
  struct pico_nat_key *tmp;
  RB_FOREACH_REVERSE_SAFE(k, nat_table_forward, &KEYTable_forward, tmp) {
    switch (k->proto)
    {
      case PICO_PROTO_TCP:
        if ((k->del_flags & 0x0800) >> 11) {
          /* entry is persistant */
          break;
        }
        else if ((k->del_flags & 0x01FF) == 0) {
          /* conn active is zero, delete entry */
          pico_ipv4_nat_del(k->pub_port, k->proto);
        }
        else if ((k->del_flags & 0x1000) >> 12) {
          /* RST flag set, set conn active to zero */
          k->del_flags &= 0xFE00;
        }
        else if (((k->del_flags & 0x8000) >> 15) && ((k->del_flags & 0x4000) >> 14)) {
          /* FIN1 and FIN2 set, set conn active to zero */
          k->del_flags &= 0xFE00; 
        }
        else if ((k->del_flags & 0x01FF) > 360) {
          /* conn is active for 24 hours, delete entry */
          pico_ipv4_nat_del(k->pub_port, k->proto);
        }
        else {
          k->del_flags++;
        } 
        break;

      case PICO_PROTO_UDP:
        if ((k->del_flags & 0x0800) >> 11) {
          /* entry is persistant */
          break;
        }
        else if ((k->del_flags & 0x01FF) > 1) {
          /* Delete entry when it has existed NAT_TCP_TIMEWAIT */
          pico_ipv4_nat_del(k->pub_port, k->proto);
        }
        else {
          k->del_flags++;
        }
        break;

      default:
        /* Unknown protocol in NAT table, delete when it has existed NAT_TCP_TIMEWAIT */
        if ((k->del_flags & 0x01FF) > 1) {
          pico_ipv4_nat_del(k->pub_port, k->proto);
        }
        else {
          k->del_flags++;
        }
    }
  }

  nat_dbg("NAT: after table cleanup:\n");
  pico_ipv4_nat_print_table();
  pico_timer_add(NAT_TCP_TIMEWAIT, pico_ipv4_nat_table_cleanup, NULL);
}

int pico_ipv4_nat_add(struct pico_ip4 pub_addr, uint16_t pub_port, struct pico_ip4 priv_addr, uint16_t priv_port, uint8_t proto)
{
  struct pico_nat_key *key = pico_zalloc(sizeof(struct pico_nat_key));
  if (!key) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }

  key->pub_addr = pub_addr;
  key->pub_port = pub_port;
  key->priv_addr = priv_addr;
  key->priv_port = priv_port;
  key->proto = proto;
  key->del_flags = 0x0001; /* set conn active to 1, other flags to 0 */

  /* RB_INSERT returns NULL when element added, pointer to the element if already in tree */
  if (!RB_INSERT(nat_table_forward, &KEYTable_forward, key) && !RB_INSERT(nat_table_backward, &KEYTable_backward, key)) {
    return 0; /* New element added */
  }
  else {
    pico_free(key);
    pico_err = PICO_ERR_EINVAL;
    return -1; /* Element key already exists */
  }
}


int pico_ipv4_nat_del(uint16_t pub_port, uint8_t proto)
{
  struct pico_nat_key *key = NULL;
  key = pico_ipv4_nat_find_key(pub_port, NULL, 0, proto);
  if (!key) {
    nat_dbg("NAT: key to delete not found: proto %u | pub_port %u\n", proto, pub_port);
    return -1;
  }
  else {
    nat_dbg("NAT: key to delete found: proto %u | pub_port %u\n", proto, pub_port);  
    /* RB_REMOVE returns pointer to removed element, NULL to indicate error */
    if (RB_REMOVE(nat_table_forward, &KEYTable_forward, key) && RB_REMOVE(nat_table_backward, &KEYTable_backward, key))
	  pico_free(key);
    else
      return -1; /* Error on removing element, do not free! */
  }
  return 0;
}

int pico_ipv4_port_forward(struct pico_ip4 pub_addr, uint16_t pub_port, struct pico_ip4 priv_addr, uint16_t priv_port, uint8_t proto, uint8_t persistant)
{
  struct pico_nat_key *key = NULL;

  switch (persistant)
  {
    case PICO_IPV4_FORWARD_ADD:
      if (pico_ipv4_nat_add(pub_addr, pub_port, priv_addr, priv_port, proto) != 0)
        return -1;  /* pico_err set in nat_add */
      key = pico_ipv4_nat_find_key(pub_port, &priv_addr, priv_port, proto);
      if (!key) {
        pico_err = PICO_ERR_EAGAIN;
        return -1;
      }
      key->del_flags = (key->del_flags & ~(0x1 << 11)) | (persistant << 11);
      break;

    case PICO_IPV4_FORWARD_DEL:
      return pico_ipv4_nat_del(pub_port, proto);

    default:
      pico_err = PICO_ERR_EINVAL;
      return -1;
  }
  pico_ipv4_nat_print_table();
  return 0;
}


void pico_ipv4_nat_print_table(void)
{
  struct pico_nat_key *k = NULL;
  uint16_t i = 0;

  nat_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  nat_dbg("+                                                       NAT table                                                       +\n");
  nat_dbg("+-----------------------------------------------------------------------------------------------------------------------+\n");
  nat_dbg("+  pointer   | private_addr | private_port | proto | pub_addr | pub_port | conn active | FIN1 | FIN2 | SYN | RST | PERS +\n");
  nat_dbg("+-----------------------------------------------------------------------------------------------------------------------+\n");

  RB_FOREACH(k, nat_table_forward, &KEYTable_forward) {
    nat_dbg("+ %10p |   %08X   |    %05u     |  %04u | %08X |  %05u   |     %03u     |   %u  |   %u  |  %u  |  %u  |   %u  +\n", 
           k, k->priv_addr.addr, k->priv_port, k->proto, k->pub_addr.addr, k->pub_port, (k->del_flags)&0x01FF, ((k->del_flags)&0x8000)>>15, 
           ((k->del_flags)&0x4000)>>14, ((k->del_flags)&0x2000)>>13, ((k->del_flags)&0x1000)>>12, ((k->del_flags)&0x0800)>>11);
    i++;
  }
  nat_dbg("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

int pico_ipv4_nat_generate_key(struct pico_nat_key* nk, struct pico_frame* f, struct pico_ip4 pub_addr)
{
  uint16_t pub_port = 0;
  struct pico_tcp_hdr *tcp_hdr = NULL;  /* forced to use pico_trans */
  struct pico_udp_hdr *udp_hdr = NULL;  /* forced to use pico_trans */
  struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1;
  uint8_t proto = ipv4_hdr->proto;
  do {
    /* 1. generate valid new NAT port entry */
    uint32_t rand = pico_rand();
    pub_port = (uint16_t) (rand & 0xFFFFU);
    pub_port = (uint16_t)(pub_port % (65535 - 1024)) + 1024U;

    /* 2. check if already in table, if no exit */
    nat_dbg("NAT: check if generated port %u is free\n", pub_port);
    if (pico_is_port_free(proto, pub_port))
      break;
  
  } while (1);
  nat_dbg("NAT: port %u is free\n", pub_port);
    
  if (proto == PICO_PROTO_TCP) {  
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    nk->priv_port = tcp_hdr->trans.sport; 
  } else if (proto == PICO_PROTO_UDP) {
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    nk->priv_port = udp_hdr->trans.sport; 
  } else if (proto == PICO_PROTO_ICMP4) {
    nk->priv_port = (uint16_t)(ipv4_hdr->src.addr & 0x00FF); 
    pub_port = (uint16_t)(ipv4_hdr->dst.addr & 0x00FF);
    if (!pico_is_port_free(proto, pub_port))
      return -1;
  }

  nk->pub_addr = pub_addr; /* get public ip address from device */
  nk->pub_port = pub_port;
  nk->priv_addr = ipv4_hdr->src;
  nk->proto = ipv4_hdr->proto;
  nk->del_flags = 0x0001; /* set conn active to 1 */
  if (pico_ipv4_nat_add(nk->pub_addr, nk->pub_port, nk->priv_addr, nk->priv_port, nk->proto) < 0) {
    return -1;
  } else {
    return 0;
  }
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
    tcp_hdr->trans.sport = nk->pub_port;
  } else if (proto == PICO_PROTO_UDP) {  
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    udp_hdr->trans.sport = nk->pub_port;
  }

  //if(f->proto == PICO_PROTO_ICMP){
  //} XXX no action

  ipv4_hdr->src = nk->pub_addr;

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
  struct pico_tcp_hdr *tcp_hdr = NULL;
  struct pico_udp_hdr *udp_hdr = NULL; 
  struct pico_icmp4_hdr *icmp_hdr = NULL;
  uint16_t pub_port = 0; 

  struct pico_ipv4_hdr* ipv4_hdr = (struct pico_ipv4_hdr *)f->net_hdr;
  if (!ipv4_hdr)
    return -1; 
  uint8_t proto = ipv4_hdr->proto; 
  
  if (proto == PICO_PROTO_TCP) {
    tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (!tcp_hdr)
      return -1;
    pub_port = tcp_hdr->trans.dport;  
  } else if (proto == PICO_PROTO_UDP) {  
    udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
    if (!udp_hdr)
      return -1;
    pub_port = udp_hdr->trans.dport;
  } else if (proto == PICO_PROTO_ICMP4) {
    icmp_hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
    if (!icmp_hdr)
      return -1;
    /* XXX PRELIMINARY ONLY LAST 16 BITS OF IP */
    pub_port = (uint16_t)(ipv4_hdr->src.addr & 0x00FF);
  }

  nk = pico_ipv4_nat_find_key(pub_port, 0, 0, proto);

  if (!nk) {
    nat_dbg("\nNAT: ERROR key not found in table\n");
    return -1;
  } else {
    pico_ipv4_nat_snif_forward(nk,f);
    ipv4_hdr->dst.addr = nk->priv_addr.addr;

    if (proto == PICO_PROTO_TCP) {
       tcp_hdr->trans.dport = nk->priv_port;
       pico_nat_tcp_checksum(f);
    } else if (proto == PICO_PROTO_UDP) {
      udp_hdr->trans.dport = nk->priv_port;
      pico_udp_checksum(f);
    }
  }


  ipv4_hdr->crc = 0;
  ipv4_hdr->crc = short_be(pico_checksum(ipv4_hdr, PICO_SIZE_IP4HDR));
 
  return 0; 
}



int pico_ipv4_nat(struct pico_frame *f, struct pico_ip4 pub_addr)
{
  /*do nat---------*/
  struct pico_nat_key *nk = NULL;
  struct pico_nat_key key;
  nk= &key;
  struct pico_ipv4_hdr *net_hdr = (struct pico_ipv4_hdr *) f->net_hdr; 

  struct pico_tcp_hdr *tcp_hdr = NULL;  
  struct pico_udp_hdr *udp_hdr = NULL;  
  int ret;
  uint8_t proto = net_hdr->proto;
  uint16_t priv_port = 0;
  struct pico_ip4 priv_addr= net_hdr->src;

  /* TODO DELME check if IN */
  if (pub_addr.addr == net_hdr->dst.addr) {
    nat_dbg("NAT: backward translation {dst.addr, dport}: {%08X,%u} ->", net_hdr->dst.addr, ((struct pico_trans *)f->transport_hdr)->dport);
    ret = pico_ipv4_nat_port_forward(f);  /* our IN definition */
    nat_dbg(" {%08X,%u}\n", net_hdr->dst.addr, ((struct pico_trans *)f->transport_hdr)->dport);
  } else {
    if (net_hdr->proto == PICO_PROTO_TCP) {
      tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      priv_port = tcp_hdr->trans.sport;
    } else if (net_hdr->proto == PICO_PROTO_UDP) {
      udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      priv_port = udp_hdr->trans.sport;
    } else if (net_hdr->proto == PICO_PROTO_ICMP4) {
      //udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      priv_port = (uint16_t)(net_hdr->src.addr & 0x00FF);
    }

    ret = pico_ipv4_nat_find(0, &priv_addr, priv_port, proto);
    if (ret >= 0) {
      // Key is available in table
      nk = pico_ipv4_nat_find_key(0, &priv_addr, priv_port, proto);
    } else {
      nat_dbg("NAT: key not found in NAT table -> generate key\n");
      pico_ipv4_nat_generate_key(nk, f, pub_addr);
    }
    pico_ipv4_nat_snif_backward(nk,f);
    nat_dbg("NAT: forward translation {src.addr, sport}: {%08X,%u} ->", net_hdr->src.addr, ((struct pico_trans *)f->transport_hdr)->sport);
    pico_ipv4_nat_translate(nk, f); /* our OUT definition */
    nat_dbg(" {%08X,%u}\n", net_hdr->src.addr, ((struct pico_trans *)f->transport_hdr)->sport);
  } 
  return 0;
}


int pico_ipv4_nat_enable(struct pico_ipv4_link *link)
{
  if (link == NULL) {
    pico_err = PICO_ERR_EINVAL;
    return -1;
  }

  pub_link = *link;
  pico_timer_add(NAT_TCP_TIMEWAIT, pico_ipv4_nat_table_cleanup, NULL);
  enable_nat_flag = 1;
  return 0;
}
 
int pico_ipv4_nat_disable(void)
{
  pub_link.address.addr = 0;
  enable_nat_flag = 0;   
  return 0;
}


int pico_ipv4_nat_isenabled_out(struct pico_ipv4_link *link)
{
  if (enable_nat_flag) {
    // is pub_link = *link
    if (pub_link.address.addr == link->address.addr)
      return 0;
    else
      return -1;
  } else {
    return -1;
  }
}


int pico_ipv4_nat_isenabled_in(struct pico_frame *f)
{
  if (enable_nat_flag) {
    struct pico_tcp_hdr *tcp_hdr = NULL;
    struct pico_udp_hdr *udp_hdr = NULL;
    uint16_t pub_port = 0;
    int ret;
 
    struct pico_ipv4_hdr *ipv4_hdr = (struct pico_ipv4_hdr *) f->net_hdr; 
    if (!ipv4_hdr)
      return -1;
    uint8_t proto = ipv4_hdr->proto;    

    if (proto == PICO_PROTO_TCP) {
      tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
      if (!tcp_hdr)
        return -1;
      pub_port= tcp_hdr->trans.dport;
    } else if (proto == PICO_PROTO_UDP) {
      udp_hdr = (struct pico_udp_hdr *) f->transport_hdr;
      if (!udp_hdr)
        return -1;
      pub_port= udp_hdr->trans.dport;
    } else if (proto == PICO_PROTO_ICMP4) {
      //icmp_hdr = (struct pico_icmp4_hdr *) f->transport_hdr;
      //if (!icmp_hdr)
      //  return -1;
      /* XXX PRELIMINARY ONLY LAST 16 BITS OF IP */
      pub_port = (uint16_t)(ipv4_hdr->src.addr & 0x00FF);
    }
    ret = pico_ipv4_nat_find(pub_port, NULL, 0, proto);
    if (ret == 0)
      return 0;
    else
      return -1;
  } else {
    return -1;    
  }
}
#endif
#endif

