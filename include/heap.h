/*********************************************************************
   PicoTCP. Copyright (c) 2012-2015 Altran Intelligent Systems. Some rights reserved.
   See LICENSE and COPYING for usage.

 *********************************************************************/

#define DECLARE_HEAP(type, orderby) \
    struct heap_ ## type {   \
        uint32_t size;    \
        uint32_t n;       \
        type *top;        \
    }; \
    typedef struct heap_ ## type heap_ ## type; \
    static inline int heap_insert(struct heap_ ## type *heap, type * el) \
    { \
        uint32_t i; \
        type *newTop; \
        if (++heap->n >= heap->size) {                                                \
            newTop = PICO_ZALLOC((heap->n + 1) * sizeof(type)); \
            if(!newTop) { \
                heap->n--; \
                return -1; \
            } \
            if (heap->top)  { \
                memcpy(newTop, heap->top, heap->n * sizeof(type)); \
                PICO_FREE(heap->top); \
            } \
            heap->top = newTop;             \
            heap->size++;                                                               \
        }                                                                             \
        if (heap->n == 1) {                                                       \
            memcpy(&heap->top[1], el, sizeof(type));                                    \
            return 0;                                                                   \
        }                                                                             \
        for (i = heap->n; ((i > 1) && (heap->top[i / 2].orderby > el->orderby)); i /= 2) {        \
            memcpy(&heap->top[i], &heap->top[i / 2], sizeof(type));                     \
        }             \
        memcpy(&heap->top[i], el, sizeof(type));                                      \
        return 0;                                                                     \
    } \
    static inline int heap_peek(struct heap_ ## type *heap, type * first) \
    { \
        type *last;           \
        uint32_t i, child;        \
        if(heap->n == 0) {    \
            return -1;          \
        }                     \
        memcpy(first, &heap->top[1], sizeof(type));   \
        last = &heap->top[heap->n--];                 \
        for(i = 1; (i * 2u) <= heap->n; i = child) {   \
            child = 2u * i;                              \
            if ((child != heap->n) &&                   \
                (heap->top[child + 1]).orderby          \
                < (heap->top[child]).orderby)           \
                child++;                                \
            if (last->orderby >                         \
                heap->top[child].orderby)               \
                memcpy(&heap->top[i], &heap->top[child], \
                       sizeof(type));                  \
            else                                        \
                break;                                  \
        }                                             \
        memcpy(&heap->top[i], last, sizeof(type));    \
        return 0;                                     \
    } \
    static inline type *heap_first(heap_ ## type * heap)  \
    { \
        if (heap->n == 0)     \
            return NULL;        \
        return &heap->top[1];  \
    } \
    static inline heap_ ## type *heap_init(void) \
    { \
        heap_ ## type * p = (heap_ ## type *)PICO_ZALLOC(sizeof(heap_ ## type));  \
        return p;     \
    } \
    /*static inline void heap_destroy(heap_ ## type * h) \
       { \
        PICO_FREE(h->top); \
        PICO_FREE(h); \
       } \*/


