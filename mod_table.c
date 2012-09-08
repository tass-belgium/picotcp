#include "pico_setup.h"
#include "pico_common.h"

RB_GENERATE(pico_module_tree, pico_module, link, pico_mod_cmp);

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
  while (c = *name++)
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

#ifdef UNIT_MAIN

#include "stdio.h"
int main(void)
{
  struct pico_module a,b,c,d, *p;
  a.hash = pico_mod_hash("ipv4");
  b.hash = pico_mod_hash("ipv6");
  c.hash = pico_mod_hash("trans:6:7744");
  d.hash = pico_mod_hash("trans:6:7474");

  printf("hashes: %08x %08x %08x %08x\n", a.hash,  b.hash,  c.hash,  d.hash );
  pico_mod_insert(&a);
  pico_mod_insert(&b);
  pico_mod_insert(&c);
  pico_mod_insert(&d);

  RB_FOREACH(p, pico_module_tree, &mtree) {
    printf("(foreach) hash: %08x\n", p->hash);
  }

  p = pico_mod_get("ipv4");
  printf("(get) hash: %08x\n", p->hash);
  p = pico_mod_get("foobar");
  if(p)
    printf("(get) hash: %08x\n", p->hash);
}


#endif
