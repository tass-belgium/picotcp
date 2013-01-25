/*********************************************************************
PicoTCP. Copyright (c) 2012 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.
  
Authors: Kristof Roelants
*********************************************************************/
//#define PICO_SUPPORT_DNS_CLIENT
//#define PICO_DNS_CLIENT_MAIN

#ifdef PICO_DNS_CLIENT_MAIN
  #include "stdio.h"
  #include "stdlib.h"
  #include "string.h"
  #include "stdint.h"
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include "pico_constants.h"
  #define pico_zalloc malloc
  #define pico_free free
#else
  #include "pico_config.h"
  #include "pico_addressing.h"
  #include "pico_socket.h"
  #include "pico_ipv4.h"
#endif

#ifdef PICO_SUPPORT_DNS_CLIENT

//#define dns_dbg(...) do{}while(0)
#define dns_dbg dbg

/* Nameservers */
#define PICO_DNS_NS_GOOGLE "8.8.8.8"

/* Nameserver port */
#define PICO_DNS_NS_PORT 53

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

static void hexDump(char *desc, void *addr, int len);
 
static int pico_dns_client_strlen(const char *url)
{
  uint16_t len = 0;
  int p;

  while((p = *url++) != 0) {
    len++;
  }
  return len;
}

static int pico_dns_client_label(char *ptr)
{
  char *l;
  uint16_t lbl_len = 0;
  int p;

  if(!ptr)
    return -1;

  l = ptr;
  ptr++;
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

static void *pico_dns_client_seek(char *ptr)
{
  int p;

  while ((p = *ptr++) != 0);

  return ptr++;
}

static inline void pico_dns_client_construct_hdr(struct dns_message_hdr *hdr, uint16_t id)
{
  hdr->id = short_be(id);
  FLAG_QR(hdr, 0); 
  FLAG_OPCODE(hdr, 0); 
  FLAG_AA(hdr, 0); 
  FLAG_TC(hdr, 0); 
  FLAG_RD(hdr, 1); 
  FLAG_RA(hdr, 0); 
  FLAG_Z(hdr, 0); 
  FLAG_RCODE(hdr, 0); 
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

static void pico_dns_client_callback(uint16_t ev, struct pico_socket *s)
{
  void *q_qname, *q_suf, *a_hdr, *a_qname, *a_suf, *a_rdata;
  struct dns_message_hdr *hdr;
  struct dns_query_suffix query_suf;
  struct dns_answer_suffix answer_suf;
  char dns_answer[256] = {0};
  uint16_t compression = 0;
  int r = 0;

  if (ev & PICO_SOCK_EV_RD) {
    r = pico_socket_read(s, dns_answer, 256);
    pico_socket_close(s);

    hexDump("DNS answer", dns_answer, r); 

    if (r < (int)sizeof(struct dns_message_hdr))
      return;

    /* Check header validity */
    a_hdr = dns_answer;
    hdr = (struct dns_message_hdr *) a_hdr;
    pico_dns_client_hdr_ntoh(hdr);
    dns_dbg("QR %d | OPCODE %d | TC %d | RCODE %d\n", GET_FLAG_QR(hdr), GET_FLAG_OPCODE(hdr), GET_FLAG_TC(hdr), GET_FLAG_RCODE(hdr));
    if (GET_FLAG_QR(hdr) != 1 || GET_FLAG_OPCODE(hdr) != 0 || GET_FLAG_TC(hdr) == 1 || GET_FLAG_RCODE(hdr) != 0)
      return;

    if (r < (int)(sizeof(struct dns_message_hdr) + hdr->qdcount * sizeof(struct dns_query_suffix)
            + hdr->ancount * sizeof(struct dns_answer_suffix)))
      return;
 
    /* Check query suffix validity */
    q_qname = a_hdr + sizeof(struct dns_message_hdr);
    q_suf = pico_dns_client_seek(q_qname);
    query_suf = *(struct dns_query_suffix *) q_suf;
    if (hdr->id == 1) {
      if (short_be(query_suf.qtype) != PICO_DNS_TYPE_A || short_be(query_suf.qclass) != PICO_DNS_CLASS_IN)
        return;
    }
    else if (hdr->id == 2) {
      if (short_be(query_suf.qtype) != PICO_DNS_TYPE_PTR || short_be(query_suf.qclass) != PICO_DNS_CLASS_IN)
        return;
    }
    else {
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
        return;
    }

    /* Check answer suffix validity */
    answer_suf = *(struct dns_answer_suffix *) a_suf;
    if (hdr->id == 1) {
      if (short_be(answer_suf.qtype) != PICO_DNS_TYPE_A || short_be(answer_suf.qclass) != PICO_DNS_CLASS_IN)
        return;
    }
    else if (hdr->id == 2) {
      if (short_be(answer_suf.qtype) != PICO_DNS_TYPE_PTR || short_be(answer_suf.qclass) != PICO_DNS_CLASS_IN)
        return;
    }
    if (short_be(answer_suf.ttl) > PICO_DNS_MAX_TTL)
      return;

    a_rdata = a_suf + sizeof(struct dns_answer_suffix);
    if (hdr->id == 1) {
      dns_dbg("DNS: has ip %08X\n", long_be(*(uint32_t *)a_rdata));
    } else if (hdr->id == 2) {
      pico_dns_client_reverse_label((char *) a_rdata);
      dns_dbg("DNS: name %s\n", (char *)a_rdata + 1);
    } else {
      return;
    }
  }

  if (ev == PICO_SOCK_EV_ERR) {
    dns_dbg("DNS: socket error received\n");
  }
}

int pico_dns_client_getaddr(const char *url)
{
  void *q_hdr, *q_qname, *q_suf;
  struct dns_message_hdr *hdr;
  struct dns_query_suffix query_suf;
  uint16_t url_len = 0;

  url_len = pico_dns_client_strlen(url);
  /* 2 extra bytes for url_len to account for 2 extra label length octets */
  q_hdr = pico_zalloc(sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix));
  q_qname = q_hdr + sizeof(struct dns_message_hdr);
  q_suf = q_qname + (1 + url_len + 1);

  /* Construct query header */
  hdr = (struct dns_message_hdr *) q_hdr;
  pico_dns_client_construct_hdr(hdr, 1);
  /* Add and manipulate domain name */
  memcpy(q_qname + 1, url, url_len + 1);
  pico_dns_client_label((char *) q_qname);
  /* Add type and class of query */
  query_suf.qtype = short_be(PICO_DNS_TYPE_A);
  query_suf.qclass = short_be(PICO_DNS_CLASS_IN);
  memcpy(q_suf, &query_suf, sizeof(struct dns_query_suffix));

#ifndef PICO_DNS_CLIENT_MAIN
  hexDump("DNS getaddr query", q_hdr, sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix)); 
  int w = 0;
  struct pico_socket *s;
  struct pico_ip4 nameserver = {0};

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dns_client_callback);
  if (!s)
    return -1; 
  pico_string_to_ipv4(PICO_DNS_NS_GOOGLE, &nameserver.addr);
  if (pico_socket_connect(s, &nameserver, short_be(PICO_DNS_NS_PORT)) != 0)
    return -1;
  w = pico_socket_send(s, q_hdr, sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix));
  if (w <= 0)
    return -1;
#else
  hexDump("DNS getaddr query", q_hdr, sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix)); 
  struct addrinfo hints, *res;
  int s, r;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  getaddrinfo("8.8.8.8", "53", &hints, &res);
  s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  connect(s, res->ai_addr, res->ai_addrlen);
  send(s, q_hdr, sizeof(struct dns_message_hdr) + (1 + url_len + 1) + sizeof(struct dns_query_suffix), 0);
  r = recv(s, dns_answer, 256, 0);
  close(s);
  hexDump("DNS answer", dns_answer, r); 
#endif

  pico_free(q_hdr);
  return 0;
}

int pico_dns_client_getname(const char *ip)
{
  void *q_hdr, *q_qname, *q_suf;
  struct dns_message_hdr *hdr;
  struct dns_query_suffix query_suf;
  uint16_t ip_len = 0;
  uint16_t arpa_len = 0;

  ip_len = pico_dns_client_strlen(ip);
  arpa_len = pico_dns_client_strlen(".in-addr.arpa");
  /* 2 extra bytes for ip_len and suffix_len to account for 2 extra length octets */
  q_hdr = pico_zalloc(sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix));
  q_qname = q_hdr + sizeof(struct dns_message_hdr);
  q_suf = q_qname + (1 + ip_len + arpa_len + 1);

  /* Construct query header */
  hdr = (struct dns_message_hdr *) q_hdr;
  pico_dns_client_construct_hdr(hdr, 2);
  /* Add and manipulate domain name */
  memcpy(q_qname + 1, ip, ip_len + 1);
  pico_dns_client_mirror((char *) (q_qname + 1));
  memcpy(q_qname + 1 + ip_len, ".in-addr.arpa", arpa_len);
  pico_dns_client_label((char *) q_qname);
  /* Add type and class of query */
  query_suf.qtype = short_be(PICO_DNS_TYPE_PTR);
  query_suf.qclass = short_be(PICO_DNS_CLASS_IN);
  memcpy(q_suf, &query_suf, sizeof(struct dns_query_suffix));

#ifndef PICO_DNS_CLIENT_MAIN
  hexDump("DNS getname query", q_hdr, sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix)); 
  int w = 0;
  struct pico_socket *s;
  struct pico_ip4 nameserver = {0};

  s = pico_socket_open(PICO_PROTO_IPV4, PICO_PROTO_UDP, &pico_dns_client_callback);
  if (!s)
    return -1; 
  pico_string_to_ipv4(PICO_DNS_NS_GOOGLE, &nameserver.addr);
  if (pico_socket_connect(s, &nameserver, short_be(PICO_DNS_NS_PORT)) != 0)
    return -1;
  w = pico_socket_send(s, q_hdr, sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix));
  if (w <= 0)
    return -1;
#else
  hexDump("DNS getname query", q_hdr, sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix)); 
  struct addrinfo hints, *res;
  int s, r;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  getaddrinfo("8.8.8.8", "53", &hints, &res);
  s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  connect(s, res->ai_addr, res->ai_addrlen);
  send(s, q_hdr, sizeof(struct dns_message_hdr) + (1 + ip_len + arpa_len + 1) + sizeof(struct dns_query_suffix), 0);
  r = recv(s, dns_answer, 256, 0);
  close(s);
  hexDump("DNS answer", dns_answer, r); 
#endif

  pico_free(q_hdr);
  return 0;
}

static void hexDump (char *desc, void *addr, int len)
{
  int i;
  unsigned char buff[17];
  unsigned char *pc = addr;

  if (desc != NULL)
    dns_dbg("%s:\n", desc);

  for (i = 0; i < len; i++) {
    if ((i % 16) == 0) {
      if (i != 0)
        dns_dbg("  %s\n", buff);
        dns_dbg("  %04x ", i);
      }
      dns_dbg(" %02x", pc[i]);
      if ((pc[i] < 0x20) || (pc[i] > 0x7e))
        buff[i % 16] = '.';
      else
        buff[i % 16] = pc[i];
      buff[(i % 16) + 1] = '\0';
  }

  while ((i % 16) != 0) {
    dns_dbg("   ");
    i++;
  }
  dns_dbg("  %s\n", buff);
}

#ifdef PICO_DNS_CLIENT_MAIN
int main(int argc, char *argv[])
{
  dns_dbg(">>>>> DNS GET ADDR\n");
  pico_dns_client_getaddr("www.google.be");
  dns_dbg(">>>>> DNS GET NAME\n");
  pico_dns_client_getname("64.46.38.137");

  return 0;
}
#endif /* PICO_DNS_CLIENT_MAIN */
#endif /* PICO_SUPPORT_DNS_CLIENT */
