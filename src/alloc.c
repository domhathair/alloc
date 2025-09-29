#include "alloc.h"
#include <stdlib.h>

size_t __memory = 0;

static struct fat_pointer *__get_ptr(void *ptr) {
    if (!ptr || (size_t)ptr < offsetof(struct fat_pointer, ptr))
        return NULL;

    struct fat_pointer *__fat = (struct fat_pointer *)((size_t)ptr - offsetof(struct fat_pointer, ptr));
    if (!__fat)
        return NULL;

    return __fat;
}

static size_t *__len_ptr(void *ptr) {
    struct fat_pointer *__fat = __get_ptr(ptr);
    if (!__fat)
        return NULL;

    return &__fat->len;
}

extern size_t __len(void *ptr) {
    size_t *len = __len_ptr(ptr);
    if (!len)
        return 0;

    return *len;
}

extern void *__malloc(size_t len) {
    if (len == 0)
        return NULL;
    else if (__memory + len > MAX_HEAP)
        return NULL;

    struct fat_pointer *__fat = (struct fat_pointer *)malloc(offsetof(struct fat_pointer, ptr) + len);
    if (!__fat)
        return NULL;

    __memory += __fat->len = len;
    for (size_t i = 0; i < __fat->len; i++)
        __fat->ptr[i] = 0;

    return __fat->ptr;
}

extern void *__realloc(void *ptr, size_t len) {
    if (len == 0) {
        __free(ptr);
        return NULL;
    }

    if (!ptr)
        return __malloc(len);

    size_t *len_ptr = __len_ptr(ptr);
    if (!len_ptr)
        return NULL; /* Invalid fat pointer */
    if (len <= *len_ptr) {
        *len_ptr = len;
        return ptr;
    }

    void *ptr_new = __malloc(len);
    if (!ptr_new)
        return NULL;

    for (size_t i = 0; i < *len_ptr; i++)
        ((unsigned char *)ptr_new)[i] = ((unsigned char *)ptr)[i];
    __free(ptr);

    return ptr_new;
}

extern void __free(void *ptr) {
    struct fat_pointer *__fat = __get_ptr(ptr);
    if (!__fat)
        return;

    __memory -= __fat->len;
    for (size_t i = 0; i < __fat->len; i++) /*  */
        __fat->ptr[i] = 0;

    free(__fat);

    return;
}

#if __STDC_VERSION__ >= 202000L
#include <stdarg.h>

extern void *__new(size_t len, ctor_t *__ctor, ...) {
    void *__ptr = __malloc(len);
    if (!__ptr)
        return NULL;

    if (!__ctor)
        return __ptr;

    va_list args;
    va_start(args);
    int rv = __ctor(__ptr, args);
    va_end(args);

    if (rv != 0)
        __free(__ptr), __ptr = NULL;

    return __ptr;
}

extern void __delete(void *__ptr, dtor_t *__dtor) {
    void **ptr = __ptr;

    if (!ptr || !*ptr)
        return;

    if (__dtor)
        __dtor(*ptr);

    __free(*ptr);

    *ptr = NULL;

    return;
}
#endif /* __STDC_VERSION__ */

#ifdef EXAMPLE
#include <stdio.h>
#include <string.h>

struct cell {
    unsigned short address;
    char *mode;
    size_t len;
    void *ptr;
};

static int cell_ctor(void *ptr, va_list args) {
    struct cell *self = (struct cell *)ptr;
    unsigned short address = va_arg(args, int);
    const char *mode = va_arg(args, const char *);
    size_t len = va_arg(args, size_t);

    if (!self || __len(self) != sizeof(struct cell) || !mode)
        return -1;

    self->mode = (char *)__malloc(strlen(mode) + 1);
    if (!self->mode)
        return -1;

    for (size_t i = 0; i < strlen(mode); i++)
        self->mode[i] = mode[i];
    self->mode[strlen(mode)] = '\0';

    self->address = address;
    self->len = len;

    self->ptr = __malloc(self->len);
    if (!self->ptr)
        return -1;

    return 0;
}

static void cell_dtor(void *ptr) {
    struct cell *self = (struct cell *)ptr;

    if (!self)
        return;

    if (self->mode)
        __free(self->mode);

    if (self->ptr)
        __free(self->ptr);

    return;
}

extern int main(int, char *[]) {
    unsigned short address = 0x80;
    const char *mode = "rw";
    size_t len = 80;

    printf("Heap before __new: %zu\n", __memory);

    struct cell *cell = (struct cell *)__new(sizeof(struct cell), cell_ctor, address, mode, len);
    if (!cell)
        return -1;

    printf("Cell: %p, address: %hu, mode: %s, len: %zu, heap: %zu\n",
           cell,
           cell->address,
           cell->mode,
           cell->len,
           __memory);

    __delete(&cell, cell_dtor);

    printf("Heap after __delete: %zu\n", __memory);

    return 0;
}
#endif /* EXAMPLE */
