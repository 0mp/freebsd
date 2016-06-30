#ifndef _LINAU_RECORD_H_
#define _LINAU_RECORD_H_

#include <nv.h>
#include <stdint.h>
#include <stdio.h>

/* The sizes of the fileds are based on what I've found in
 * audit-userspace/auparse/auparse.h. */
/* struct linau_record { */
/*         char		*lr_type; */
/*         uint32_t	lr_typelen; */
/*         uint32_t	lr_id; */
/*         uint64_t	lr_nsecs; */
/*         uint32_t	lr_size; */
/*         nvlist_t	*lr_fields; */
/* }; */

typedef linau_record nvlist;

linau_record *linau_record_create(void);

void linau_record_set_id(linau_record *record, uint32_t id);
void linau_record_set_timestamp(linau_record *record, uint64_t timestamp);
void linau_record_set_type(linau_record *record, const char *type);

linau_record *linau_record_parse(const char * buf);
uint64_t linau_record_parse_timestamp(const char *buf);
char *linau_record_parse_type(const char *buf);

linau_record *linau_record_fetch(FILE * fp);

/* char *linau_record_generate_key(const struct linau_record *record); */
/* uint32_t linau_record_get_id(const struct linau_record *record); */
/* uint64_t linau_record_get_timestamp(const struct linau_record *record); */

/* linau_record *linau_record_parse(const char * const buf, size_t buflen); */
/* void linau_record_parse_type(char **typep, size_t *typelenp, const char *buf, */
/*     size_t buflen); */
/* void linau_record_parse_timestamp(uint64_t * const timestamp, const char *buf, */
/*     size_t buflen); */

/* void linau_record_set_id(struct linau_record *record, uint32_t id); */
/* void linau_record_set_timestamp(struct linau_record * record, */
/*     uint64_t timestamp); */
/* void linau_record_set_type(struct linau_record *record, const char *type, */
/*     size_t typelen); */

#endif
