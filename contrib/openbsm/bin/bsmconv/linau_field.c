#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "linau.h"
#include "linau_common.h"
#include "linau_impl.h"
#include "pjdlog.h"

static size_t find_string_value_end(const char *buf, size_t start,
    char stringtype);

static size_t
find_string_value_end(const char *buf, size_t start, char stringtype)
{
	size_t buflen;
	size_t end;
	/* XXX How to call such variables like endchrp? */
	char *endchrp;

	PJDLOG_ASSERT(buf != NULL);

	buflen = strlen(buf);
	end = start + 1;
	PJDLOG_ASSERT(end < buflen);

	do {
		endchrp = strchr(buf + end, stringtype);
		PJDLOG_VERIFY(endchrp != NULL);
		end = endchrp - buf;
	} while (buf[end - 1] == '\\');

	return (end);
}

struct linau_field *
linau_field_create(void)
{
	struct linau_field *field;

	field = calloc(1, sizeof(*field));
	PJDLOG_VERIFY(field != NULL);

	return (field);
}

void
linau_field_destroy(struct linau_field *field)
{

	free(field->lf_name);
	free(field->lf_value);
	free(field);
	/* XXX Should I change field to NULL now? */
}

void
linau_field_shallow_destroy(struct linau_field *field)
{

	free(field);
}

void
linau_field_move_name(struct linau_field *field, char *name)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(name != NULL);

	field->lf_name = name;
}

void
linau_field_move_value(struct linau_field *field, char *value)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(value != NULL);

	field->lf_value = value;
}

struct linau_field *
linau_field_parse(const char *buf, size_t *lastposp)
{
	struct linau_field *field;
	char *name;
	char *value;
	size_t buflen;
	size_t equalpos;
	size_t nameend;
	size_t namestart;
	size_t valstart;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(lastposp != NULL);

	pjdlog_debug(6, " . . . . . + linau_record_parse_field");

	buflen = strlen(buf);

	field = linau_field_create();
	/* XXX Do we need this? */
	PJDLOG_VERIFY(field != NULL);

	namestart = *lastposp;
	pjdlog_debug(6, " . . . . . . namestart (%zu) points to (%c)",
	    namestart, buf[namestart]);

	/* Skip a comma or a whitespace. */
	if (namestart + 1 < buflen && isspace(buf[namestart]))
		namestart++;
	else if (namestart + 1 < buflen && buf[namestart] == ',')
		namestart++;
	else
		PJDLOG_ABORT("The record fields should be separated by either "
		    "a comma or a whitespace");

	/* Skip any number of whitespaces. */
	while (namestart + 1 < buflen && isspace(buf[namestart]))
		namestart++;

	PJDLOG_ASSERT(!isspace(buf[namestart]));
	PJDLOG_ASSERT(buf[namestart] != ',');

	pjdlog_debug(6, " . . . . . . Nonspace namestart (%zu) points to (%c)",
	    namestart, buf[namestart]);

	/* Trailing whitespace is invalid. */
	PJDLOG_ASSERT(namestart != buflen);

	/* Reach the next field. Assume there are no '=' in the name. */
	PJDLOG_VERIFY(find_position(&equalpos, buf, namestart + 1, '='));
	nameend = equalpos - 1;
	PJDLOG_ASSERT(buf[nameend] != '=');

	name = linau_field_parse_name(buf, namestart, nameend);
	linau_field_move_name(field, name);

	valstart = equalpos + 1;
	PJDLOG_ASSERT(valstart < buflen);

	value = linau_field_parse_value(buf, valstart);
	linau_field_move_value(field, value);

	*lastposp = valstart + strlen(value);

	pjdlog_debug(6, " . . . . . -");

	return (field);
}

char *
linau_field_parse_name(const char *buf, size_t start, size_t end)
{

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(start <= end);

	return (extract_substring(buf, start, end - start + 1));
}

char *
linau_field_parse_value(const char *buf, size_t start)
{
	char *value;
	size_t end;
	size_t spacepos;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(start < strlen(buf));

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
			PJDLOG_ASSERT(spacepos == strlen(buf));
			PJDLOG_ASSERT(buf[spacepos] == '\0');
		}
		end = spacepos - 1;

		if (buf[end] == ',')
			end--;

		break;
	}

	value = extract_substring(buf, start, end - start + 1);

	return (value);
}
