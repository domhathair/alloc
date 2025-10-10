/**
 * @file alloc.c
 * @brief Implementation of a simple "fat" allocator
 *
 * IMPORTANT NOTES:
 * - The pointer returned by fat_malloc/fat_realloc points to the payload (ptr),
 *   not to the start of the header. Use fat_free to free such pointers
 * - The implementation is NOT thread-safe. External synchronization is required
 *   if used concurrently
 * - The functions make minimal checks for pointer validity. Passing arbitrary
 *   pointers to internal helpers yields undefined behavior
 */

#include "alloc.h"
#include <stdint.h>
#include <stdlib.h>

/**
 * @brief Global counter of total allocated bytes (sum of all live allocations)
 *
 * @see fat_malloc, fat_free
 */
size_t _Allocated_memory = 0;

static struct fat_pointer *__get_ptr(void *ptr) {
    if (!ptr)
        return NULL;

    return (struct fat_pointer *)((uintptr_t)ptr - offsetof(struct fat_pointer, ptr));
}

static size_t *__len_ptr(void *ptr) {
    struct fat_pointer *_Fat = __get_ptr(ptr);
    if (!_Fat)
        return NULL;

    return &_Fat->len;
}

/**
 * @brief Return the length (in bytes) of the allocation associated with ptr
 *
 * @param ptr Pointer to payload (may be NULL)
 * @return Size in bytes of the allocation. Returns 0 if ptr is NULL or invalid
 */
extern size_t fat_len(void *ptr) {
    size_t *len = __len_ptr(ptr);
    if (!len)
        return 0;

    return *len;
}

/**
 * @brief Allocate a block of memory of requested payload size and return payload pointer
 *
 * @param len Requested payload size in bytes
 * @return Pointer to payload on success; NULL on failure
 *
 * @post On success, _Allocated_memory is increased by len and the returned payload is zeroed
 * @warning The pointer returned must be freed with fat_free, not free()
 * @see fat_free, fat_realloc, fat_len
 */
extern void *fat_malloc(size_t len) {
    if (len == 0 || len > MAX_HEAP || _Allocated_memory > MAX_HEAP - len)
        return NULL;

    size_t header = offsetof(struct fat_pointer, ptr);
    if (len > SIZE_MAX - header)
        return NULL;

    struct fat_pointer *_Fat = (struct fat_pointer *)calloc(header + len, sizeof(unsigned char));
    if (!_Fat)
        return NULL;

    _Allocated_memory += _Fat->len = len;

    return _Fat->ptr;
}

/**
 * @brief Reallocate a payload to a new size (similar to realloc semantics inside this API)
 *
 * @param ptr Pointer to payload previously returned by fat_malloc/fat_realloc (or NULL)
 * @param len New requested payload size
 * @return Pointer to payload (possibly moved) on success; NULL on failure or when len == 0
 *
 * @note Copy is performed byte-wise via unsigned char semantics
 * @warning Not thread-safe. If ptr is not a valid fat pointer, behavior is undefined
 * @see fat_malloc, fat_free
 */
extern void *fat_realloc(void *ptr, size_t len) {
    if (len == 0) {
        fat_free(ptr);
        return NULL;
    }

    if (!ptr)
        return fat_malloc(len);

    struct fat_pointer *_Fat = __get_ptr(ptr);
    if (!_Fat)
        return NULL; /* Invalid fat pointer */

    if (len == _Fat->len)
        return ptr;
    else if (len < _Fat->len) {
        for (size_t i = len; i < _Fat->len; i++)
            _Fat->ptr[i] = 0;

        size_t diff = _Fat->len - len;
        if (_Allocated_memory <= diff)
            /* Something is wrong with _Fat->len */
            return NULL;
        _Allocated_memory -= diff;
        _Fat->len = len;

        return ptr;
    }

    void *ptr_new = fat_malloc(len);
    if (!ptr_new)
        return NULL;

    for (size_t i = 0; i < _Fat->len; i++)
        ((unsigned char *)ptr_new)[i] = ((unsigned char *)ptr)[i];
    fat_free(ptr);

    return ptr_new;
}

/**
 * @brief Free a payload previously returned by fat_malloc/fat_realloc
 *
 * @param ptr Pointer to payload to free. If ptr is NULL, function does nothing
 * @return void
 *
 * @post _Allocated_memory is decreased by the allocation's stored length
 * @warning If ptr is not a valid fat allocation pointer, behavior is undefined; the function
 *          attempts minimal protection by returning on NULL input
 * @see fat_malloc, fat_realloc
 */
extern void fat_free(void *ptr) {
    struct fat_pointer *_Fat = __get_ptr(ptr);
    if (!_Fat)
        return;

    _Allocated_memory = (_Allocated_memory >= _Fat->len) ? _Allocated_memory - _Fat->len : 0;
    for (size_t i = 0; i < _Fat->len; i++) /*  */
        _Fat->ptr[i] = 0;

    free(_Fat);

    return;
}

#if __STDC_VERSION__ >= 202000L
#include <stdarg.h>

/**
 * @brief Allocate raw storage for an object and run a constructor (variadic)
 *
 * @param len Payload size in bytes to allocate.
 * @param __ctor Constructor function or NULL. If NULL, the allocated block is returned
 *               without calling any constructor
 * @param ... Arguments forwarded to the constructor via va_list
 * @return Pointer to allocated payload on success, or NULL on failure or if ctor returns non-zero
 *
 * @note Only available when __STDC_VERSION__ >= 202000L (C2x or newer).
 * @see _Delete
 */
extern void *_New(size_t len, ctor_t *__ctor,
#ifdef _WIN32
                  size_t n_memb,
#endif
                  ...) {
    void *__ptr = fat_malloc(len);
    if (!__ptr)
        return NULL;

    if (!__ctor)
        return __ptr;

    va_list args;
#ifdef _WIN32
    va_start(args, n_memb);
#else
    va_start(args);
#endif
    int rv = __ctor(__ptr, args);
    va_end(args);

    if (rv != 0)
        fat_free(__ptr), __ptr = NULL;

    return __ptr;
}

/**
 * @brief Call destructor and free an object. The caller must pass the address of the pointer
 *
 * @param __ptr Address of the payload pointer (i.e. pointer-to-pointer, void **).
 *              After return, *(__ptr) is set to NULL
 * @param __dtor Destructor function to call on the payload prior to freeing. May be NULL
 * @return void
 *
 * @warning The function expects an address-of-pointer. Passing a raw payload pointer instead
 *          (not its address) leads to undefined behavior
 * @see _New
 */
extern void _Delete(void **__ptr, dtor_t *__dtor) {
    if (!__ptr || !*__ptr)
        return;

    if (__dtor)
        __dtor(*__ptr);

    fat_free(*__ptr);

    *__ptr = NULL;

    return;
}
#endif /* __STDC_VERSION__ */
