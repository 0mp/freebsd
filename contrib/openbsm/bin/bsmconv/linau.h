#ifndef _LINAU_H_
#define _LINAU_H_

#include <stdint.h>
#include <stdio.h>

#include <nv.h>

/*
 * linau_event interface.
 */

typedef nvlist_t linau_event;

linau_event *linau_event_create(void);
void linau_event_destroy(linau_event *event);

void linau_event_add_record(linau_event *event, const linau_record *record,
    size_t recordnum);
bool linau_event_empty(const linau_event *event);

uint32_t linau_event_get_id(const linau_event *event);
uint32_t linau_event_get_size(const linau_event *event);
uint64_t linau_event_get_timestamp(const linau_event *event);

void linau_event_set_id(linau_event *event, uint32_t id);
void linau_event_set_timestamp(linau_event *event, uint64_t timestamp);

void linau_event_print(const linau_event *event);

int linau_event_compare_origin(const linau_event *event,
    const linau_record *record);


/*
 * linau_record interface.
 */

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

/*
 * linau_field interface.
 */

#define BSMCONV_LINAU_FIELD_NAME	"name"
#define BSMCONV_LINAU_FIELD_VALUE	"value"
#define BSMCONV_LINAU_FIELD_TYPE	"__bsmconvlinaufieldtype__"
#define BSMCONV_LINAU_FIELD_TYPE_STRING	"string"
/* For the sake of linau_event_print(). */
#define	BSMCONV_LINAU_FIELD_NAME_NVNAME		"name"
#define	BSMCONV_LINAU_FIELD_VALUE_NVNAME	"value"

typedef nvlist_t linau_field;

linau_field *linau_field_create(void);
void linau_field_destroy(linau_field *field);

void linau_field_set_name(linau_field *field, const char * name);
void linau_field_set_value(linau_field *field, const char * value);

linau_field *linau_field_parse(const char *buf, size_t *lastposp);
char *linau_field_parse_name(const char *buf, size_t start, size_t end);
char *linau_field_parse_value(const char *buf, size_t start);


#endif
