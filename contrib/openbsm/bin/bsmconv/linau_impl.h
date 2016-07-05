#ifndef _LINAU_IMPL_H_
#define _LINAU_IMPL_H_

#include <sys/types.h>

#include <stdbool.h>

#include <sys/nv.h>

nvlist_t *linau_proto_create(void);
void linau_proto_destroy(nvlist_t *nvl);

uintmax_t linau_proto_get_number(const nvlist_t *nvl, const char *nvname);
const char *linau_proto_get_string(const nvlist_t *nvl, const char *nvname);

void linau_proto_set_number(nvlist_t *nvl, const char *nvname, uintmax_t num);
void linau_proto_set_string(nvlist_t *nvl, const char *nvname, const char *str);
int linau_proto_compare_origin(uint32_t id1, uint64_t time1, uint32_t id2,
   uint64_t time2);

bool find_position(size_t *posp, const char *buf, size_t start, char chr);
void locate_msg(const char *buf, size_t *msgstartp, size_t *secsposp,
    size_t *nsecsposp, size_t *idposp, size_t *msgendp);
char * extract_substring(const char *buf, size_t start, size_t len);

uint32_t extract_uint32(const char *buf, size_t start, size_t end);
uint32_t string_to_uint32(const char *str);
size_t find_string_value_end(const char *buf, size_t start, char stringtype);

#endif
