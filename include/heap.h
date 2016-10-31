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
    static inline type* getElement(struct heap_ ## type *heap, uint32_t idx) \
    { \
        return &heap->top[idx];\
    } \
    static inline int8_t increase_size(struct heap_ ## type *heap) \
    {\
        type *newTop; \
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
        return 0;                                                               \
    }\
    static inline int heap_insert(struct heap_ ## type *heap, type * el) \
    { \
        type* half;                                                                 \
        uint32_t i; \
        if (++heap->n >= heap->size) {                                                \
            if (increase_size(heap))                                                    \
                return -1;                                                           \
        }                                                                             \
        if (heap->n == 1) {                                                       \
            memcpy(getElement(heap, 1), el, sizeof(type));                                    \
            return 0;                                                                   \
        }                                                                             \
        i = heap->n;                                                                    \
        half = getElement(heap, i/2);                                                   \
        while ( (i > 1) && (half->orderby > el->orderby) ) {        \
            memcpy(getElement(heap, i), getElement(heap, i / 2), sizeof(type));                     \
            i /= 2;                                                                     \
            half = getElement(heap, i/2);                                                   \
        }             \
        memcpy(getElement(heap, i), el, sizeof(type));                                      \
        return 0;                                                                     \
    } \
    static inline int heap_peek(struct heap_ ## type *heap, type * first) \
    { \
        type *last;           \
        type *left_child;           \
        type *right_child;           \
        uint32_t i, child;        \
        if(heap->n == 0) {    \
            return -1;          \
        }                     \
        memcpy(first, getElement(heap, 1), sizeof(type));   \
        last = getElement(heap, heap->n--);                 \
        for(i = 1; (i * 2u) <= heap->n; i = child) {   \
            child = 2u * i;                              \
            right_child = getElement(heap, child+1);     \
            left_child = getElement(heap, child);      \
            if ((child != heap->n) &&                   \
                (right_child->orderby          \
                < left_child->orderby))           \
                child++;                                \
            left_child = getElement(heap, child);      \
            if (last->orderby >                         \
                left_child->orderby)               \
                memcpy(getElement(heap,i), getElement(heap,child), \
                       sizeof(type));                  \
            else                                        \
                break;                                  \
        }                                             \
        memcpy(getElement(heap, i), last, sizeof(type));    \
        return 0;                                     \
    } \
    static inline type *heap_first(heap_ ## type * heap)  \
    { \
        if (heap->n == 0)     \
            return NULL;        \
        return getElement(heap, 1);  \
    } \
    static inline heap_ ## type *heap_init(void) \
    { \
        heap_ ## type * p = (heap_ ## type *)PICO_ZALLOC(sizeof(heap_ ## type));  \
        return p;     \
    } \

