/* Pico object */

/* In this first version, this has only list powers.
 * In the future, the pico_object will have a compare() method, and
 * a more efficient structure could be used.
 */

void pico_list_insert(void *_obj, struct pico_object **list)
{
  struct pico_object *o = (struct pico_object *)_obj;
  o->next = *list;
  list = &o;
}

void pico_list_delete(void *_obj, struct pico_object **list)
{
  struct pico_object *o = (struct pico_object *)_obj;
  struct pico_object *cur = *list, *prev = NULL;
  while(cur) {
    if (cur == o) {
      if (prev == NULL)
        list = &cur->next;
      else
        list = &prev;
      memfree(cur);
      break;
    }
    prev = cur;
    cur = cur->next;
  }
}
