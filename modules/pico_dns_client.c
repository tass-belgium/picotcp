/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.
  
Authors: Kristof Roelants
*********************************************************************/
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_addressing.h"
#include "pico_socket.h"
#include "pico_ipv4.h"

#ifdef PICO_SUPPORT_DNS_CLIENT

#define dns_dbg(...) do{}while(0)
//#define dns_dbg dbg

/* DNS response length */
#define PICO_DNS_MAX_RESPONSE_LEN 256

/* DNS client retransmission time (msec) + frequency */
#define PICO_DNS_CLIENT_RETRANS 4000
#define PICO_DNS_CLIENT_MAX_RETRANS 3

/* Nameservers */
#define PICO_DNS_NS_GOOGLE "8.8.8.8"

/* Nameserver port */
#define PICO_DNS_NS_PORT 53

/* FLAG values */
#define PICO_DNS_QR_QUERY 0
#define PICO_DNS_QR_RESPONSE 1
#define PICO_DNS_OPCODE_QUERY 0
#define PICO_DNS_OPCODE_IQUERY 1
#define PICO_DNS_OPCODE_STATUS 2
#define PICO_DNS_AA_NO_AUTHORITY 0
#define PICO_DNS_AA_IS_AUTHORITY 1
#define PICO_DNS_TC_NO_TRUNCATION 0
#define PICO_DNS_TC_IS_TRUNCATED 1
#define PICO_DNS_RD_NO_DESIRE 0
#define PICO_DNS_RD_IS_DESIRED 1
#define PICO_DNS_RA_NO_SUPPORT 0
#define PICO_DNS_RA_IS_SUPPORTED 1
#define PICO_DNS_RCODE_NO_ERROR 0
#define PICO_DNS_RCODE_EFORMAT 1
#define PICO_DNS_RCODE_ESERVER 2
#define PICO_DNS_RCODE_ENAME 3
#define PICO_DNS_RCODE_ENOIMP 4
#define PICO_DNS_RCODE_EREFUSED 5

/* QTYPE values */
#define PICO_DNS_TYPE_A 1
#define PICO_DNS_TYPE_PTR 12

/* QCLASS values */
#define PICO_DNS_CLASS_IN 1

/* Compression values */
#define PICO_DNS_LABEL 0
#define PICO_DNS_POINTER 3

/* TTL values */
#define PICO_DNS_MAX_TTL 604800 /* one week */

/* Header flags */
#define FLAG_QR(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0x1 << 15)) | (x << 15)) 
#define FLAG_OPCODE(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0xF << 11)) | (x << 11)) 
#define FLAG_AA(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0x1 << 10)) | (x << 10)) 
#define FLAG_TC(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0x1 << 9)) | (x << 9)) 
#define FLAG_RD(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0x1 << 8)) | (x << 8)) 
#define FLAG_RA(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0x1 << 7)) | (x << 7)) 
#define FLAG_Z(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0x7 << 4)) | (x << 4)) 
#define FLAG_RCODE(hdr, x) ((hdr)->flags = ((hdr)->flags & ~(0xF)) | x) 

#define GET_FLAG_QR(hdr) ((((hdr)->flags) & (1 << 15)) != 0) 
#define GET_FLAG_OPCODE(hdr) ((((hdr)->flags) & (0xF << 11)) >> 11) 
#define GET_FLAG_AA(hdr) ((((hdr)->flags) & (1 << 10)) != 0) 
#define GET_FLAG_TC(hdr) ((((hdr)->flags) & (1 << 9)) != 0) 
#define GET_FLAG_RD(hdr) ((((hdr)->flags) & (1 << 8)) != 0) 
#define GET_FLAG_RA(hdr) ((((hdr)->flags) & (1 << 7)) != 0) 
#define GET_FLAG_Z(hdr) ((((hdr)->flags) & (0x7 << 4)) >> 4) 
#define GET_FLAG_RCODE(hdr) (((hdr)->flags) & (0x0F)) 

/* RFC 1025 section 4. MESSAGES */
struct __attribute__((packed)) dns_message_hdr
{
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct __attribute__((packed)) dns_query_suffix
{
  /* NAME - domain name to which this resource record pertains */
  uint16_t qtype;
  uint16_t qclass;
};

struct __attribute__((packed)) dns_answer_suffix
{
  /* NAME - domain name to which this resource record pertains */
  uint16_t qtype;
  uint16_t qclass;
  uint32_t ttl;
  uint16_t rdlength;
  /* RDATA - variable length string of octets that describes the resource */
};

struct pico_dns_key
{
  void *q_hdr;
  uint16_t len;
  uint16_t id;
  uint16_t qtype;
  uint16_t qclass;
  uint8_t retrans;
  void (*callback)(char *);
  RB_ENTRY(pico_dns_key) node;
};

static int dns_cmp(struct pico_dns_key *a, struct pico_dns_key *b)
{
  if (a->id < b->id)
    return -1; 
  else if (a->id > b->id)
    return 1;
  else
    return 0;
} 
    
RB_HEAD(pico_dns_list, pico_dns_key);
RB_PROTOTYPE_STATIC(pico_dns_list, pico_dns_key, node, dns_cmp);
RB_GENERATE_STATIC(pico_dns_list, pico_dns_key, node, dns_cmp);

static struct pico_dns_list DNSTable;
 
static int pico_dns_client_strlen(const char *url)
{
  uint16_t len = 0;
  int p;

  if (!url)
    return -1;

  while ((p = *url++) != 0) {
    len++;
  }
  return len;
}

/* Replace '.' by the label length */
static int pico_dns_client_label(char *ptr)
{
  char *l;
  uint8_t lbl_len = 0;
  int p;

  if (!ptr)
    return -1;

  l = ptr++;
  while ((p = *ptr++) != 0){
    if (p == '.') {
      *l = lbl_len;
      l = ptr - 1;
      lbl_len = 0;
    } else {
      lbl_len++;
    }
  }
  *l = lbl_len;
  return 0;
}

/* Replace the label length by '.' */
static int pico_dns_client_reverse_label(char *ptr)
{
  char *l;
  int p;

  if(!ptr)
    return -1;

  l = ptr;
  while ((p = *ptr++) != 0){
    ptr += p;
    *l = '.';
    l = ptr;
  }
  return 0;
}

/* Seek the end of a string */
static void *pico_dns_client_seek(char *ptr)
{
  int p;

  while ((p = *ptr++) != 0);

  return ptr++;
}

static inline void pico_dns_client_construct_hdr(struct dns_message_hdr *hdr, uint16_t id)
{
  hdr->id = short_be(id);
  FLAG_QR(hdr, PICO_DNS_QR_QUERY); 
  FLAG_OPCODE(hdr, PICO_DNS_OPCODE_QUERY); 
  FLAG_AA(hdr, PICO_DNS_AA_NO_AUTHORITY); 
  FLAG_TC(hdr, PICO_DNS_TC_NO_TRUNCATION); 
  FLAG_RD(hdr, PICO_DNS_RD_IS_DESIRED); 
  FLAG_RA(hdr, PICO_DNS_RA_NO_SUPPORT); 
  FLAG_Z(hdr, 0); 
  FLAG_RCODE(hdr, PICO_DNS_RCODE_NO_ERROR); 
  hdr->flags = short_be(hdr->flags);
  hdr->qdcount = short_be(1);
  hdr->ancount = short_be(0);
  hdr->nscount = short_be(0);
  hdr->arcount = short_be(0);
}

static inline void pico_dns_client_hdr_ntoh(struct dns_message_hdr *hdr)
{
  hdr->id = short_be(hdr->id);
  hdr->flags = short_be(hdr->flags);
  hdr->qdcount = short_be(hdr->qdcount);
  hdr->ancount = short_be(hdr->ancount);
  hdr->nscount = short_be(hdr->nscount);
  hdr->arcount = short_be(hdr->arcount);
}

static inline int pico_is_digit(char c)
{
  if (c < '0' || c > '9')
    return 0;
  return 1;
}

static int pico_dns_client_mirror(char *ptr)
{
  unsigned char buf[4] = {0};
  char *m;
  int cnt = 0;
  int p, i;

  if (!ptr)
    return -1;

  m = ptr;
  while ((p = *ptr++) != 0)
  {
    if (pico_is_digit(p)) {
      buf[cnt] = (10 * buf[cnt]) + (p - '0');
    } else if (p == '.') {
        cnt++;
    } else {
      return -1;
    }
  }

  /* Handle short notation */
  if(cnt == 1){
    buf[3] = buf[1];
    buf[1] = 0;
    buf[2] = 0;
  }else if (cnt == 2){
    buf[3] = buf[2];
    buf[2] = 0;
  }else if(cnt != 3){
    /* String could not be parsed, return error */
    return -1;
  }

  ptr = m;
  for(i = 3; i >= 0; i--)
  {
    if(buf[i] > 99){
      *ptr++ = '0' + (buf[i] / 100);
      *ptr++ = '0' + ((buf[i] % 100) / 10);
      *ptr++ = '0' + ((buf[i] % 100) % 10);
    }else if(buf[i] > 9){
      *ptr++ = '0' + (buf[i] / 10);
      *ptr++ = '0' + (buf[i] % 10);
    }else{
      *ptr++ = '0' + buf[i];
    }
    if(i > 0)
      *ptr++ = '.';
  }

  return 0;
}

static struct pico_dns_key *pico_dns_client_idcheck(uint16_t id)
{
  struct pico_dns_key test;

  test.id = id;
  return RB_FIND(pico_dns_list, &DNSTable, &test);
}

static void pico_dns_client_callback(uint16_t ev, struct pico_socket *s);

static int pico_dns_client_send(struct pico_dns_key *key)
{
  struct pico_socket *s;
  struct pico_ip4 nameserver = {0};
  int w = 0;

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dns_client_callback);
  if (!s)
    return -1; 
  pico_string_to_ipv4(PICO_DNS_NS_GOOGLE, &nameserver.addr);
  if (pico_socket_connect(s, &nameserver, short_be(PICO_DNS_NS_PORT)) != 0)
    return -1;
  w = pico_socket_send(s, key->q_hdr, key->len);
  if (w <= 0)
    return -1;

  return 0;
}

static void pico_dns_client_retransmission(unsigned long now, void *arg)
{
  struct pico_dns_key *key = (struct pico_dns_key *)arg;

  if (key->retrans && key->retrans <= PICO_DNS_CLIENT_MAX_RETRANS) {
    dns_dbg("DNS: retransmission! (%u)\n", key->retrans);
    key->retrans++;
    pico_dns_client_send(key);
    pico_timer_add(PICO_DNS_CLIENT_RETRANS, pico_dns_client_retransmission, key);
  } else {
    dns_dbg("DNS: no retransmission! (%u)\n", key->retrans);
    pico_free(key->q_hdr);
    RB_REMOVE(pico_dns_list, &DNSTable, key);
  }
}

static void pico_dns_client_callback(uint16_t ev, struct pico_socket *s)
{
  void *q_qname, *q_suf, *a_hdr, *a_qname, *a_suf, *a_rdata;
  struct dns_message_hdr *hdr;
  struct dns_query_suffix query_suf;
  struct dns_answer_suffix answer_suf;
  struct pico_dns_key test, *key;
  char *answer;
  char dns_answer[PICO_DNS_MAX_RESPONSE_LEN] = {0};
  uint16_t compression = 0;
  int r = 0;

  if (ev & PICO_SOCK_EV_RD) {
    r = pico_socket_read(s, dns_answer, PICO_DNS_MAX_RESPONSE_LEN);
    pico_socket_close(s);
    if (r == PICO_DNS_MAX_RESPONSE_LEN || r < (int)sizeof(struct dns_message_hdr)) {
      dns_dbg("DNS ERROR: received incorrect number(%d) of bytes\n", r);
      return;
    }

    /* Check header validity */
    a_hdr = dns_answer;
    hdr = (struct dns_message_hdr *) a_hdr;
    pico_dns_client_hdr_ntoh(hdr);
    if (GET_FLAG_QR(hdr) != PICO_DNS_QR_RESPONSE || GET_FLAG_OPCODE(hdr) != PICO_DNS_OPCODE_QUERY 
        || GET_FLAG_TC(hdr) == PICO_DNS_TC_IS_TRUNCATED || GET_FLAG_RCODE(hdr) != PICO_DNS_RCODE_NO_ERROR) {
      dns_dbg("DNS ERROR: OPCODE %d | TC %d | RCODE %d\n", GET_FLAG_OPCODE(hdr), GET_FLAG_TC(hdr), GET_FLAG_RCODE(hdr));
      return;
    }

    if (hdr->ancount < 1 || r < (int)(sizeof(struct dns_message_hdr) + hdr->qdcount * sizeof(struct dns_query_suffix)
            + hdr->ancount * sizeof(struct dns_answer_suffix))) {
      dns_dbg("DNS ERROR: ancount < 1 OR received number(%d) of bytes too low\n", r);
      return;
    }

    /* Find DNS key */
    test.id = hdr->id;
    key = RB_FIND(pico_dns_list, &DNSTable, &test);
    if (!key) {
      dns_dbg("DNS WARNING: key with id %u not found\n", hdr->id);
      return;
    }
    key->retrans = 0;

    /* Check query suffix validity */
    q_qname = a_hdr + sizeof(struct dns_message_hdr);
    q_suf = pico_dns_client_seek(q_qname);
    query_suf = *(struct dns_query_suffix *) q_suf;
    if (short_be(query_suf.qtype) != key->qtype || short_be(query_suf.qclass) != key->qclass) {
      dns_dbg("DNS ERROR: received qtype (%u) or qclass (%u) incorrect\n", short_be(query_suf.qtype), short_be(query_suf.qclass));
      return;
    }

    /* Seek answer suffix */
    a_qname = q_suf + sizeof(struct dns_query_suffix);
    a_suf = a_qname;
    compression = short_be(*(uint16_t *)a_suf);
    switch (compression >> 14) 
    {
      case PICO_DNS_POINTER:
        while (compression >> 14 == PICO_DNS_POINTER) {
          dns_dbg("DNS: pointer\n");
          a_suf += sizeof(uint16_t);
          compression = short_be(*(uint16_t *)a_suf);
        }
        break;

      case PICO_DNS_LABEL:
        dns_dbg("DNS: label\n");
        a_suf = pico_dns_client_seek(a_qname);
        break;

      default:
        dns_dbg("DNS ERROR: incorrect compression (%u) value\n", compression);
        return;
    }

    /* Check answer suffix validity */
    answer_suf = *(struct dns_answer_suffix *)a_suf;
    if (short_be(answer_suf.qtype) != key->qtype || short_be(answer_suf.qclass) != key->qclass) {
      dns_dbg("DNS ERROR: received qtype (%u) or qclass (%u) incorrect\n", short_be(answer_suf.qtype), short_be(answer_suf.qclass));
      return;
    }

    if (short_be(answer_suf.ttl) > PICO_DNS_MAX_TTL) {
      dns_dbg("DNS ERROR: received TTL (%u) > MAX (%u)\n", short_be(answer_suf.ttl), PICO_DNS_MAX_TTL);
      return;
    }

    a_rdata = a_suf + sizeof(struct dns_answer_suffix);
    if (key->qtype == PICO_DNS_TYPE_A) {
      dns_dbg("DNS: length %u | ip %08X\n", short_be(answer_suf.rdlength), long_be(*(uint32_t *)a_rdata));
      answer = pico_zalloc(16);
      pico_ipv4_to_string(answer, *(uint32_t *)a_rdata);
      key->callback(answer);
    } else if (key->qtype == PICO_DNS_TYPE_PTR) {
      pico_dns_client_reverse_label((char *) a_rdata);
      dns_dbg("DNS: length %u | name %s\n", short_be(answer_suf.rdlength), (char *)a_rdata + 1);
      answer = pico_zalloc(answer_suf.rdlength - 1);
      memcpy(answer, (char *)a_rdata + 1, short_be(answer_suf.rdlength) - 1);
      key->callback(answer);
    } else {
      dns_dbg("DNS ERROR: incorrect qtype (%u)\n", key->qtype);
      return;
    }
  }

  if (ev == PICO_SOCK_EV_ERR) {
    dns_dbg("DNS: socket error received\n");
  }
}

int pico_dns_client_getaddr(const char *url, void (*callback)(char *))
{
  void *q_hdr, *q_qname, *q_suf;
  struct dns_message_hdr *hdr;
  struct dns_query_suffix query_suf;
  struct pico_dns_key *key;
  uint16_t url_len = 0;
  uint16_t id = 0;

  url_len = pico_dns_client_strlen(url);
  /* 2 extra bytes for url_len to account for 2 extra label length octets */
  q_hdr = pico_zalloc(sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix));
  q_qname = q_hdr + sizeof(struct dns_message_hdr);
  q_suf = q_qname + (1 + url_len + 1);

  /* Construct query header */
  hdr = (struct dns_message_hdr *) q_hdr;
  do {
    id = (uint16_t) (pico_rand() & 0xFFFFU);
    dns_dbg("DNS: generated id %u\n", id);
  } while (pico_dns_client_idcheck(id));
  pico_dns_client_construct_hdr(hdr, id);
  /* Add and manipulate domain name */
  memcpy(q_qname + 1, url, url_len + 1);
  pico_dns_client_label((char *)q_qname);
  /* Add type and class of query */
  query_suf.qtype = short_be(PICO_DNS_TYPE_A);
  query_suf.qclass = short_be(PICO_DNS_CLASS_IN);
  memcpy(q_suf, &query_suf, sizeof(struct dns_query_suffix));
  /* Create RB entry */
  key = pico_zalloc(sizeof(struct pico_dns_key));
  if (!key) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  key->q_hdr = q_hdr;
  key->len = sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix);
  key->id = id;
  key->qtype = PICO_DNS_TYPE_A;
  key->qclass = PICO_DNS_CLASS_IN;
  key->retrans = 1;
  key->callback = callback;
  /* Send query */
  pico_dns_client_send(key);
  /* Insert RB entry */
  if (RB_INSERT(pico_dns_list, &DNSTable, key))
    return -1; /* Element key already exists */

  pico_timer_add(PICO_DNS_CLIENT_RETRANS, pico_dns_client_retransmission, key);
  return 0;
}

int pico_dns_client_getname(const char *ip, void (*callback)(char *))
{
  void *q_hdr, *q_qname, *q_suf;
  struct dns_message_hdr *hdr;
  struct dns_query_suffix query_suf;
  struct pico_dns_key *key;
  uint16_t ip_len = 0;
  uint16_t arpa_len = 0;
  uint16_t id = 0;

  ip_len = pico_dns_client_strlen(ip);
  arpa_len = pico_dns_client_strlen(".in-addr.arpa");
  /* 2 extra bytes for ip_len and arpa_len to account for 2 extra length octets */
  q_hdr = pico_zalloc(sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix));
  q_qname = q_hdr + sizeof(struct dns_message_hdr);
  q_suf = q_qname + (1 + ip_len + arpa_len + 1);

  /* Construct query header */
  hdr = (struct dns_message_hdr *)q_hdr;
  do {
    id = (uint16_t) (pico_rand() & 0xFFFFU);
    dns_dbg("DNS: generated id %u\n", id);
  } while (pico_dns_client_idcheck(id));
  pico_dns_client_construct_hdr(hdr, id);
  /* Add and manipulate domain name */
  memcpy(q_qname + 1, ip, ip_len + 1);
  pico_dns_client_mirror((char *)(q_qname + 1));
  memcpy(q_qname + 1 + ip_len, ".in-addr.arpa", arpa_len);
  pico_dns_client_label((char *)q_qname);
  /* Add type and class of query */
  query_suf.qtype = short_be(PICO_DNS_TYPE_PTR);
  query_suf.qclass = short_be(PICO_DNS_CLASS_IN);
  memcpy(q_suf, &query_suf, sizeof(struct dns_query_suffix));
  /* Create RB entry */
  key = pico_zalloc(sizeof(struct pico_dns_key));
  if (!key) {
    pico_err = PICO_ERR_ENOMEM;
    return -1;
  }
  key->q_hdr = q_hdr;
  key->len = sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix);
  key->id = id;
  key->qtype = PICO_DNS_TYPE_PTR;
  key->qclass = PICO_DNS_CLASS_IN;
  key->retrans = 1;
  key->callback = callback;
  /* Send query */
  pico_dns_client_send(key);
  /* Insert RB entry */
  if (RB_INSERT(pico_dns_list, &DNSTable, key))
    return -1; /* Element key already exists */

  pico_timer_add(PICO_DNS_CLIENT_RETRANS, pico_dns_client_retransmission, key);
  return 0;
}

#ifdef PICO_DNS_CLIENT_MAIN
int main(int argc, char *argv[])
{
  dns_dbg(">>>>> DNS GET ADDR\n");
  pico_dns_client_getaddr("www.google.be");
  dns_dbg(">>>>> DNS GET NAME\n");
  pico_dns_client_getname("173.194.67.94");

  return 0;
}
#endif /* PICO_DNS_CLIENT_MAIN */
#endif /* PICO_SUPPORT_DNS_CLIENT */
