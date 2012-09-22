#include "pico_setup.h"
#include "pico_common.h"

RB_GENERATE(pico_module_tree, pico_module, node, pico_mod_cmp);

static struct pico_module_tree mtree;

int pico_mod_insert(struct pico_module *mod)
{
  if ((RB_INSERT(pico_module_tree, &mtree, mod)) != NULL)
    return 0;
  else return -1;
}

int pico_mod_cmp(struct pico_module *m0, struct pico_module *m1)
{
  if (m0->hash < m1->hash)
    return -1;

  if (m1->hash < m0->hash)
    return 1;

  return 0;
}

uint32_t pico_mod_hash(char *name)
{
  unsigned long hash = 5381;
  int c;
  while ((c = *name++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  return hash;
}

struct pico_module *pico_mod_get(char *name)
{
  struct pico_module p;
  p.hash = pico_mod_hash(name);
  return RB_FIND(pico_module_tree, &mtree, &p);
}


void pico_mod_delete(char *name)
{
  struct pico_module *p = pico_mod_get(name);
  if (p) {
    (void) RB_REMOVE(pico_module_tree, &mtree, p);
  }
}


#ifdef MODULE_DYNAMIC

# error "MODULE_DYNAMIC NOT IMPLEMENTED"
  /* XXX: Use dlopen() */
#else

#define pico_init_module(p, itsname, arg) {\
  p = &pico_module_##itsname; \
  if (!pico_mod_get(p->name))  { \
    p->init(arg); \
    p->hash = pico_mod_hash(p->name); \
    pico_mod_insert(p); \
  } \
}


#endif


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

/** XXX finish dev tree interface ***/

#ifdef UNIT_TABLE_MAIN

#include "stdio.h"
int main(void)
{
  struct pico_module a,b,c,d, *p;
  b.hash = pico_mod_hash("arp");
  b.hash = pico_mod_hash("ipv6");
  c.hash = pico_mod_hash("trans:6:7744");
  d.hash = pico_mod_hash("trans:6:7474");

  printf("hashes: %08x %08x %08x %08x\n", a.hash,  b.hash,  c.hash,  d.hash );
  pico_mod_insert(&a);
  pico_mod_insert(&b);
  pico_mod_insert(&c);
  pico_mod_insert(&d);
  pico_init_module(p, ipv4, NULL);


  RB_FOREACH(p, pico_module_tree, &mtree) {
    printf("(foreach) hash: %08x\n", p->hash);
  }

  p = pico_mod_get("ipv4");
  printf("(get) hash: %08x, name: %s\n", p->hash, p->name);
  p = pico_mod_get("foobar");
  if(p)
    printf("(get) hash: %08x\n", p->hash);
  return 0;
}


#endif
