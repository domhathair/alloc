/*
 * alloc.h - A simple memory allocator with "fat" pointers
 *
 * Copyright (c) 2025, Alexander Chepkov
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS 'AS IS' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef ALLOC_H
#define ALLOC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fat_pointer {
    size_t len;
    unsigned char ptr[];
};

#ifndef MAX_HEAP
/* 1 GiB by default */
#define MAX_HEAP 1073741824
#endif /* MAX_HEAP */

extern size_t __memory;

extern size_t __len(void *);
extern void *__malloc(size_t);
extern void *__realloc(void *, size_t);
extern void __free(void *);

#ifdef __cplusplus
}
#endif

#if __STDC_VERSION__ >= 202000L
#include <stdarg.h>

typedef int ctor_t(void *, va_list);
typedef void dtor_t(void *);

extern void *__new(size_t, ctor_t *, ...);
extern void __delete(void *, dtor_t *);
#endif /* __STDC_VERSION__ */

#endif /* ALLOC_H */
