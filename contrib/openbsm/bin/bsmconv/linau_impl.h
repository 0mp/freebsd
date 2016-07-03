#ifndef _LINAU_IMPL_H_
#define _LINAU_IMPL_H_

#include <sys/types.h>

#include <stdbool.h>
#include <nv.h>

nvlist_t *linau_proto_create(void);
void linau_proto_destroy(nvlist_t *nvl);

uintmax_t linau_proto_get_number(const nvlist_t *nvl, const char *nvname);
void linau_proto_set_number(nvlist_t *nvl, const char *nvname, uintmax_t num);
void linau_proto_set_string(nvlist_t *nvl, const char *nvname, const char *str);
int linau_proto_compare_origin(uint32_t id1, uint64_t timestamp1, uint32_t id2,
    uint64_t timestamp2);

bool find_position(size_t *posp, const char *buf, size_t start, char chr);
char * extract_substring(const char *buf, size_t start, size_t len);

#endif
