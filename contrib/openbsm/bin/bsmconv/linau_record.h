#ifndef _LINAU_RECORD_H_
#define _LINAU_RECORD_H_

#include <nv.h>
#include <stdint.h>
#include <stdio.h>

typedef nvlist_t linau_record;

linau_record *linau_record_create(void);
void linau_record_destroy(linau_record *record);

uint32_t linau_record_get_id(const linau_record *record);
uint64_t linau_record_get_timestamp(const linau_record *record);
const char *linau_record_get_type(const linau_record *record);

void linau_record_set_fields(linau_record *record, nvlist_t *fields);
void linau_record_set_id(linau_record *record, uint32_t id);
void linau_record_set_timestamp(linau_record *record, uint64_t timestamp);
void linau_record_set_type(linau_record *record, const char *type);

linau_record *linau_record_parse(const char * buf);
nvlist_t *linau_record_parse_fields(const char *buf);
uint32_t linau_record_parse_id(const char *buf);
uint64_t linau_record_parse_timestamp(const char *buf);
char *linau_record_parse_type(const char *buf);

char * linau_record_generate_key(const linau_record *record);

linau_record *linau_record_fetch(FILE * fp);

#endif
