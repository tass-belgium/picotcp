#include "pico_setup.h"
#include "pico_common.h"

RB_GENERATE(pico_device_tree, pico_device, node, pico_dev_cmp);

static struct pico_device_tree mtree;

int pico_dev_insert(struct pico_device *dev)
{
  if ((RB_INSERT(pico_device_tree, &mtree, dev)) != NULL)
    return 0;
  else return -1;
}

int pico_dev_cmp(struct pico_device *m0, struct pico_device *m1)
{
  if (m0->hash < m1->hash)
    return -1;

  if (m1->hash < m0->hash)
    return 1;

  return 0;
}

uint32_t pico_dev_hash(char *name)
{
  unsigned long hash = 5381;
  int c;
  while ((c = *name++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

struct pico_device *pico_dev_get(char *name)
{
  struct pico_device p;
  p.hash = pico_dev_hash(name);
  return RB_FIND(pico_device_tree, &mtree, &p);
}


void pico_dev_delete(char *name)
{
  struct pico_device *p = pico_dev_get(name);
  if (p) {
    (void) RB_REMOVE(pico_device_tree, &mtree, p);
  }
}


RB_GENERATE(pico_device_tree, pico_device, node, pico_dev_cmp);
static struct pico_device_tree dtree;

/* device interface */
int pico_dev_cmp(struct pico_device *d0, struct pico_device *d1)
{
  if (d0->hash < d1->hash)
    return -1;
  if (d1->hash < d0->hash)
    return 1;
  return 0;
}

int pico_dev_insert(struct pico_device *dev)
{
  if ((RB_INSERT(pico_device_tree, &dtree, dev)) != NULL)
    return 0;
  else return -1;
}


#ifdef UNIT_DEVTABLE_MAIN

#include "stdio.h"
int main(void)
{
  struct pico_device a,b,c,d, *p;
  b.hash = pico_dev_hash("arp");
  b.hash = pico_dev_hash("ipv6");
  c.hash = pico_dev_hash("trans:6:7744");
  d.hash = pico_dev_hash("trans:6:7474");

  printf("hashes: %08x %08x %08x %08x\n", a.hash,  b.hash,  c.hash,  d.hash );
  pico_dev_insert(&a);
  pico_dev_insert(&b);
  pico_dev_insert(&c);
  pico_dev_insert(&d);
  pico_init_device(p, ipv4, NULL);


  RB_FOREACH(p, pico_device_tree, &mtree) {
    printf("(foreach) hash: %08x\n", p->hash);
  }

  p = pico_dev_get("ipv4");
  printf("(get) hash: %08x, name: %s\n", p->hash, p->name);
  p = pico_dev_get("foobar");
  if(p)
    printf("(get) hash: %08x\n", p->hash);
  return 0;
}


#endif
