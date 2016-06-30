#ifndef _LINAU_IMPL_H_
#define _LINAU_IMPL_H_

#include <sys/types.h>

#include <stdbool.h>

bool find_position(size_t * const posp, const char * const buf,
    const size_t buflen, const size_t start, const char chr);

#endif
