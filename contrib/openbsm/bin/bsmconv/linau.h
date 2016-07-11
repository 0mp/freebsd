#ifndef _LINAU_H_
#define _LINAU_H_

#include <sys/nv.h>
#include <sys/types.h>

#include <stdint.h>
#include <stdio.h>

struct linau_event;
struct linau_record;
struct linau_field;

/* linau_event. */
struct linau_event	*linau_event_create(void);
void			 linau_event_destroy(struct linau_event *event);
void			 linau_event_clear(struct linau_event *event);

void	 		 linau_event_add_record(struct linau_event *event,
			    struct linau_record *record);
bool			 linau_event_empty(const struct linau_event *event);

uint32_t		 linau_event_get_id(const struct linau_event *event);
uint64_t		 linau_event_get_time(const struct linau_event *event);

struct timeval		*linau_event_get_timeval(
			    const struct linau_event *event);

void			 linau_event_dump(const struct linau_event *event);

int			 linau_event_compare_origin(
			    const struct linau_event *event,
			    const struct linau_record *record);

int			 linau_event_to_au(const struct linau_event *event,
			    unsigned short *aueventidp);

u_char			*linau_event_process(const struct linau_event *event,
			    size_t *buflenp);

/* linau_record. */
struct			 linau_record *linau_record_create(void);
void			 linau_record_destroy(struct linau_record *record);
nvlist_t		*linau_record_clone_fields(
			    const struct linau_record *record);

bool			 linau_record_exists_field(
			    const struct linau_record *record,
			    const char *name);

const char		*linau_record_get_field(
			    const struct linau_record *record,
			    const char *name);
nvlist_t		*linau_record_get_fields(
			    const struct linau_record *record);
size_t			 linau_record_get_fields_count(
			    const struct linau_record *record);
uint32_t		 linau_record_get_id(const struct linau_record *record);
const char		*linau_record_get_text(
			    const struct linau_record *record);
uint64_t		 linau_record_get_time(
			    const struct linau_record *record);
const char		*linau_record_get_type(
			    const struct linau_record *record);

bool			 linau_record_try_get_uint32_field(
			    const struct linau_record *record,
			    const char *fieldname, uint32_t *fieldvalp);

void			 linau_record_move_fields(struct linau_record *record,
			    nvlist_t *fields);
void			 linau_record_move_type(struct linau_record *record,
			    char *type);

void			 linau_record_set_fields_count(
			    struct linau_record *record, size_t fields_count);
void			 linau_record_set_id(struct linau_record *record,
			    uint32_t id);
void			 linau_record_set_text(struct linau_record *record,
			    const char *text);
void			 linau_record_set_time(struct linau_record *record,
			    uint64_t time);

struct linau_record	*linau_record_parse(const char * buf);
nvlist_t		*linau_record_parse_fields(const char *buf,
			    size_t *fields_countp);
uint32_t		 linau_record_parse_id(const char *buf);
uint64_t		 linau_record_parse_time(const char *buf);
char			*linau_record_parse_type(const char *buf);

struct linau_record	*linau_record_fetch(FILE * fp);

int			 linau_record_comapre_origin(
			    const struct linau_record *reca,
			    const struct linau_record *recb);

void			 linau_record_to_au(const struct linau_record *record,
			    int aurecordd);

/* linau_field. */
struct linau_field	*linau_field_create(void);
void			 linau_field_destroy(struct linau_field *field);
void			 linau_field_shallow_destroy(struct linau_field *field);

void			 linau_field_move_name(struct linau_field *field,
			    char *name);
void			 linau_field_move_value(struct linau_field *field,
			    char *value);

struct linau_field	*linau_field_parse(const char *buf, size_t *lastposp);
char			*linau_field_parse_name(const char *buf, size_t start,
			    size_t end);
char			*linau_field_parse_value(const char *buf,
			    size_t start);

#endif
