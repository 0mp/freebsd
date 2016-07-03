#include <ctype.h>
#include <nv.h>
#include <string.h>
#include <stdlib.h>

#include "linau_field.h"
#include "linau_impl.h"
#include "pjdlog.h"

static size_t find_string_value_end(const char *buf, size_t start,
    char stringtype);


static size_t
find_string_value_end(const char *buf, size_t start, char stringtype)
{
	size_t end;
	size_t prevend;
	size_t buflen;

	PJDLOG_ASSERT(buf != NULL);

	buflen = strlen(buf);
	end = start + 1;
	PJDLOG_ASSERT(end < buflen);

	do {
		prevend = end;
		PJDLOG_VERIFY(find_position(&end, buf, prevend, stringtype));
	} while (buf[end - 1] == '\\');

	return (end);
}


linau_field *
linau_field_create(void)
{

	return (linau_proto_create());
}

void
linau_field_destroy(linau_field *field)
{

	linau_proto_destroy(field);
}

void
linau_field_set_name(linau_field *field, const char * name)
{

	linau_proto_set_string(field, BSMCONV_LINAU_FIELD_NAME_NVNAME, name);
}

/* TODO The value is always a string at the moment. */
void
linau_field_set_value(linau_field *field, const char * value)
{

	linau_proto_set_string(field, BSMCONV_LINAU_FIELD_VALUE_NVNAME, value);
	linau_proto_set_string(field, BSMCONV_LINAU_FIELD_TYPE,
	    BSMCONV_LINAU_FIELD_TYPE_STRING);
}

linau_field *
linau_field_parse(const char *buf, size_t *lastposp)
{
	size_t namestart;
	size_t equalpos;
	size_t nameend;
	size_t valstart;
	char *name;
	char *value;
	linau_field * field;
	size_t buflen;

	pjdlog_debug(6, " . . > linau_record_parse_field");

	PJDLOG_ASSERT(buf != NULL);
	buflen = strlen(buf);

	field = linau_field_create();
	PJDLOG_VERIFY(field != NULL);

	namestart = *lastposp;
	pjdlog_debug(6, " . . > namestart (%zu) points to (%c)", namestart,
	    buf[namestart]);

	/* Skip a comma and spaces. */
	if (namestart + 1 < buflen && isspace(buf[namestart]))
		namestart++;
	else if (namestart + 1 < buflen && buf[namestart] == ',')
		namestart++;
	else
		PJDLOG_ABORT("The record fields should be separated by either "
		    "a comma or a whitespace");
	while (namestart + 1 < buflen && isspace(buf[namestart]))
		namestart++;

	PJDLOG_ASSERT(!isspace(buf[namestart]));
	PJDLOG_ASSERT(buf[namestart] != ',');

	pjdlog_debug(6, " . . > Nonspace namestart (%zu) points to (%c)",
	    namestart, buf[namestart]);

	/* Trailing whitespace is invalid. */
	PJDLOG_ASSERT(namestart != buflen);

	/* Reach the next field. Assume there are no '=' in the name. */
	PJDLOG_VERIFY(find_position(&equalpos, buf, namestart + 1, '='));
	nameend = equalpos - 1;
	PJDLOG_ASSERT(buf[nameend] != '=');

	name = linau_field_parse_name(buf, namestart, nameend);
	linau_field_set_name(field, name);
	free(name);

	valstart = equalpos + 1;
	PJDLOG_ASSERT(valstart < buflen);

	value = linau_field_parse_value(buf, valstart);
	linau_field_set_value(field, value);
	free(value);

	pjdlog_debug(6, " . . > Field: name: (%s|%zu), value: (%s|%zu)",
	    nvlist_get_string(field, BSMCONV_LINAU_FIELD_NAME),
	    strlen(nvlist_get_string(field, BSMCONV_LINAU_FIELD_NAME)),
	    nvlist_get_string(field, BSMCONV_LINAU_FIELD_VALUE),
	    strlen(nvlist_get_string(field, BSMCONV_LINAU_FIELD_VALUE)));

	*lastposp = valstart + strlen(value);

	return (field);
}

char *
linau_field_parse_name(const char *buf, size_t start, size_t end)
{
	size_t len;
	char *name;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(start <= end);

	len = end - start + 1;
	name = extract_substring(buf, start, len);

	return (name);
}

char *
linau_field_parse_value(const char *buf, size_t start)
{
	size_t len;
	size_t end;
	size_t spacepos;
	char *value;
	size_t buflen = strlen(buf);

	PJDLOG_ASSERT(start < buflen);

	switch (buf[start]) {
	case '"':
		end = find_string_value_end(buf, start, '"');
		break;
	case '\'':
		/*
		 * You cannot have a value like '''.
		 * You can have a value like '\''.
		 */
		end = find_string_value_end(buf, start, '\'');
		break;
	default:
		/* XXX Ugly. */
		if (!find_position(&spacepos, buf, start, ' ')) {
			PJDLOG_ASSERT(spacepos == buflen);
			spacepos--; // Newline.
			PJDLOG_ASSERT(buf[spacepos] == '\n');
		}
		end = spacepos - 1;

		if (buf[end] == ',')
			end--;

		break;
	}

	len = end - start + 1;

	value = extract_substring(buf, start, len);

	return (value);

}
