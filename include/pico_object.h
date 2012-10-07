#ifndef __PICO_OBJ
#define __PICO_OBJ

/* For now, the object container is a list. */
struct pico_object {
  struct pico_object *next;
};

void pico_list_insert(void *_obj, struct pico_object **list);
void pico_list_delete(void *_obj, struct pico_object **list);

#define pico_memalloc(x) malloc(x)
#define pico_memfree(x)  free(x)

#endif
