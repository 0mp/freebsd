#ifndef _LINAU_H_
#define _LINAU_H_

#include <sys/queue.h>

#include <stdint.h>
#include <stdio.h>

#include <nv.h>

/*
 * linau_event interface.
 */

struct linau_event {
	TAILQ_HEAD(, linau_record) 	le_records;
};

struct linau_event *linau_event_create(void);
void linau_event_destroy(struct linau_event *event);

void linau_event_add_record(linau_event *event, const linau_record *record,
    size_t recordnum);
bool linau_event_empty(const linau_event *event);

uint32_t linau_event_get_id(const linau_event *event);
uint32_t linau_event_get_size(const linau_event *event);
uint64_t linau_event_get_timestamp(const linau_event *event);

void linau_event_print(const linau_event *event);

int linau_event_compare_origin(const linau_event *event,
    const linau_record *record);


/*
 * linau_record interface.
 */

struct linau_record {
	char				*lr_type;
	uint32_t			lr_id;
	uint64_t			lr_time;
	TAILQ_ENTRY(linau_record)	lr_next;
	nvlist_t			*lr_fields;
};

struct linau_record *linau_record_create(void);
void linau_record_destroy(struct linau_record *record);

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

struct linau_record *linau_record_fetch(FILE * fp);

int linau_record_comapre_origin(const linau_record *reca,
    const linau_record *recb);

/*
 * linau_field interface.
 */

struct linau_field {
	char	*lf_name;
	char	*lf_value;
}

linau_field *linau_field_create(void);
void linau_field_destroy(linau_field *field);
void linau_field_shallow_destroy(linau_field *field);

void linau_field_set_name(linau_field *field, const char * name);
void linau_field_set_value(linau_field *field, const char * value);

linau_field *linau_field_parse(const char *buf, size_t *lastposp);
char *linau_field_parse_name(const char *buf, size_t start, size_t end);
char *linau_field_parse_value(const char *buf, size_t start);

#endif
