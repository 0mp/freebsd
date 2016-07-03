#ifndef _LINAU_RECORD_H_
#define _LINAU_RECORD_H_

#include <nv.h>
#include <stdint.h>
#include <stdio.h>

/* For the sake of linau_event_print. */
#define	BSMCONV_LINAU_RECORD_FIELDS_NVNAME	"_fields"
#define	BSMCONV_LINAU_RECORD_ID_NVNAME		"_id"
#define	BSMCONV_LINAU_RECORD_TIMESTAMP_NVNAME	"_timestamp"
#define	BSMCONV_LINAU_RECORD_TYPE_NVNAME	"_type"

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

linau_record *linau_record_fetch(FILE * fp);

int linau_record_comapre_origin(const linau_record *reca,
    const linau_record *recb);

#endif
