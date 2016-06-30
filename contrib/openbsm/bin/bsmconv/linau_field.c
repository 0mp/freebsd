#include <nv.h>
#include <string.h>
#include <stdlib.h>

#include "linau_field.h"
#include "linau_impl.h"
#include "pjdlog.h"

#define	BSMCONV_LINAU_FIELD_NAME_NVNAME		"name"
#define	BSMCONV_LINAU_FIELD_VALUE_NVNAME	"value"

linau_field *
linau_field_create(void)
{
	return (linau_proto_create());
}

void
linau_field_set_name(linau_field *field, const char * name)
{

	linau_proto_set_string(field, BSMCONV_LINAU_FIELD_NAME_NVNAME, name);
}

void
linau_field_set_value(linau_field *field, const char * value)
{

	linau_proto_set_string(field, BSMCONV_LINAU_FIELD_VALUE_NVNAME, value);
}

/* TODO Commas are invalid for the time being. */
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

	/* Skip spaces. */
	/* XXX Commas are invalid for the time being. */
	while (namestart < buflen && buf[namestart] == ' ')
		namestart++;

	pjdlog_debug(6, " . . > Nonspace namestart (%zu) points to (%c)",
	    namestart, buf[namestart]);

	/* TODO Check if we reach the end of line. Return if so. */
	if (namestart == buflen) {
		nvlist_destroy(field);
		*lastposp = namestart;
		PJDLOG_ABORT("parse_field() reach the end of line contating "
		    "trailing spaces. It hasn't been implemented yet");
	}

	/*
	 * Reach the next field. Assume there are no '=' in the name.
	 */
	PJDLOG_VERIFY(find_position(&equalpos, buf, namestart + 1, '='));
	nameend = equalpos - 1;
	PJDLOG_ASSERT(buf[nameend] != '=');

	/* 0mphere5 */
	name = linau_field_parse_name(buf, namestart, nameend);
	linau_field_set_name(field, name);

	valstart = equalpos + 1;
	PJDLOG_ASSERT(valstart < buflen);
	value = linau_field_parse_value(buf, buflen, valstart);
	/* XXX The value is always a string at the moment. */
	nvlist_move_string(field, BSMCONV_LINAU_FIELD_VALUE, value);
	nvlist_add_string(field, BSMCONV_LINAU_FIELD_TYPE,
	    BSMCONV_LINAU_FIELD_TYPE_STRING);

	pjdlog_debug(6, " . . > Field: name: (%s|%zu), value: (%s|%zu)",
	    nvlist_get_string(field, BSMCONV_LINAU_FIELD_NAME),
	    strlen(nvlist_get_string(field, BSMCONV_LINAU_FIELD_NAME)),
	    nvlist_get_string(field, BSMCONV_LINAU_FIELD_VALUE),
	    strlen(nvlist_get_string(field, BSMCONV_LINAU_FIELD_VALUE)));

	*lastposp = valstart + strlen(value);
	*fieldp = field;
}


char *
linau_field_parse_name(const char *buf, size_t start, size_t end)
{
	size_t len;
	char *name;

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(start <= end);

	len = end - start + 1;
	name = calloc(len + 1, sizeof(*name));
	PJDLOG_VERIFY(name != NULL);
	name = strncpy(name, buf + start, len);
	name[len] = '\0';
	PJDLOG_VERIFY(strncmp(name, buf + start, len) == 0);

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
	/* 0mphere100 */

	PJDLOG_ASSERT(start < buflen);

	switch (buf[start]) {
	case '"':
		linau_field_parse_string_value(&end, start, buf,
		    buflen, '"');
		break;
	case '\'':
		/*
		 * XXX You cannot have a value like '''.
		 * It's assumed that there are no apostophes between two main
		 * apostrophes.  Actually, it is OK as long as there is a \
		 * before the '.
		 * TODO Add a test.
		 */
		linau_field_parse_string_value(&end, start, buf,
		    buflen, '\'');
		break;
	default:
		/* XXX Ugly. */
		if (!find_position(&spacepos, buf, start, ' ')) {
			PJDLOG_ASSERT(spacepos == buflen);
			spacepos--; // Newline.
			PJDLOG_ASSERT(buf[spacepos] == '\n');
		}
		end = spacepos - 1;
		break;
	}

	len = end - start + 1;

	value = calloc(len, sizeof(*value));
	PJDLOG_VERIFY(value != NULL);
	PJDLOG_VERIFY(strncpy(value, buf + start, len) != NULL);
	value[len] = '\0';
	PJDLOG_VERIFY(strncmp(value, buf + start, len) == 0);

	return (value);

}

/*******************************************************************************
 * End.
 */

static void
linau_field_parse_string_value(size_t * const endp, const size_t start,
    const char * const recordstr, const size_t recordstrlen,
    const char stringtype)
{
	size_t end;
	size_t prevend;

	PJDLOG_ASSERT(recordstr != NULL);
	PJDLOG_ASSERT(recordstrlen > 0);

	end = start + 1;
	PJDLOG_ASSERT(end < recordstrlen);

	do {
		prevend = end;
		PJDLOG_VERIFY(find_position(&end, recordstr, prevend, stringtype));
	} while (recordstr[end - 1] == '\\');

	*endp = end;
}


