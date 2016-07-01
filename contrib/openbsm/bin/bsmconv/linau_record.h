#ifndef _LINAU_RECORD_H_
#define _LINAU_RECORD_H_

#include <nv.h>
#include <stdint.h>
#include <stdio.h>

typedef nvlist_t linau_record;

linau_record *linau_record_create(void);

void linau_record_set_id(linau_record *record, uint32_t id);
void linau_record_set_timestamp(linau_record *record, uint64_t timestamp);
void linau_record_set_type(linau_record *record, const char *type);

linau_record *linau_record_parse(const char * buf);
uint64_t linau_record_parse_timestamp(const char *buf);
char *linau_record_parse_type(const char *buf);

linau_record *linau_record_fetch(FILE * fp);

#endif
