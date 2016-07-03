#ifndef _LINAU_FIELD_H_
#define _LINAU_FIELD_H_

#include <nv.h>

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
