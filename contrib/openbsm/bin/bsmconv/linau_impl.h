#ifndef _LINAU_IMPL_H_
#define _LINAU_IMPL_H_

#include <sys/types.h>

#include <stdbool.h>
#include <nv.h>

nvlist_t *linau_proto_create(void);

bool find_position(size_t * posp, const char *buf, size_t buflen, size_t start,
    char chr);

#endif
