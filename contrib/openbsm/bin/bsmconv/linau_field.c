#include <nv.h>
#include <string.h>
#include <stdlib.h>

#include "linau_field.h"
#include "linau_impl.h"
#include "pjdlog.h"

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
		PJDLOG_VERIFY(find_position(&end, recordstr, recordstrlen,
		    prevend, stringtype));
	} while (recordstr[end - 1] == '\\');

	*endp = end;
}

static char *
linau_field_parse_name(const char * const recordstr, const size_t start,
    const size_t end)
{
	size_t len;
	char *name;

	PJDLOG_ASSERT(recordstr != NULL);
	PJDLOG_ASSERT(start <= end);

	len = end - start + 1;
	name = calloc(len + 1, sizeof(*name));
	PJDLOG_VERIFY(name != NULL);
	name = strncpy(name, recordstr + start, len);
	name[len] = '\0';
	PJDLOG_VERIFY(strncmp(name, recordstr + start, len) == 0);

	return (name);
}

static char *
linau_field_parse_value(const char * const recordstr, const size_t recordstrlen,
    const size_t start)
{
	size_t len;
	size_t end;
	size_t spacepos;
	char *value;

	PJDLOG_ASSERT(start < recordstrlen);

	switch (recordstr[start]) {
	case '"':
		linau_field_parse_string_value(&end, start, recordstr,
		    recordstrlen, '"');
		break;
	case '\'':
		/*
		 * XXX You cannot have a value like '''.
		 * It's assumed that there are no apostophes between two main
		 * apostrophes.  Actually, it is OK as long as there is a \
		 * before the '.
		 * TODO Add a test.
		 */
		linau_field_parse_string_value(&end, start, recordstr,
		    recordstrlen, '\'');
		break;
	default:
		/* XXX Ugly. */
		if (!find_position(&spacepos, recordstr, recordstrlen, start,
		    ' ')) {
			PJDLOG_ASSERT(spacepos == recordstrlen);
			spacepos--; // Newline.
			PJDLOG_ASSERT(recordstr[spacepos] == '\n');
		}
		end = spacepos - 1;
		break;
	}

	len = end - start + 1;

	value = calloc(len, sizeof(*value));
	PJDLOG_VERIFY(value != NULL);
	PJDLOG_VERIFY(strncpy(value, recordstr + start, len) != NULL);
	value[len] = '\0';
	PJDLOG_VERIFY(strncmp(value, recordstr + start, len) == 0);

	return (value);

}


void
linau_field_parse(nvlist_t ** const fieldp, const char * const recordstr,
    const size_t recordstrlen, size_t * const lastposp)
{
	pjdlog_debug(6, " . . > linau_record_parse_field");
	size_t namestart;
	size_t equalpos;
	size_t nameend;
	size_t valstart;
	char *name;
	char *value;
	nvlist_t * field;

	PJDLOG_ASSERT(recordstr != NULL);
	PJDLOG_ASSERT(recordstrlen > 0);
	PJDLOG_ASSERT(*fieldp == NULL);

	field = nvlist_create(0);
	/* XXX Missing PJDLOG_VERIFY ? */

	namestart = *lastposp;
	pjdlog_debug(6, " . . > namestart (%zu) points to (%c)", namestart,
	    recordstr[namestart]);

	/* Skip spaces. */
	/* XXX Commas are invalid for the time being. */
	while (namestart < recordstrlen && recordstr[namestart] == ' ')
		namestart++;

	pjdlog_debug(6, " . . > Nonspace namestart (%zu) points to (%c)",
	    namestart, recordstr[namestart]);

	/* TODO Check if we reach the end of line. Return if so. */
	if (namestart == recordstrlen) {
		nvlist_destroy(field);
		*lastposp = namestart;
		PJDLOG_ABORT("parse_field() reach the end of line contating "
		    "trailing spaces. It hasn't been implemented yet");
	}

	/*
	 * Reach the next field. Assue there are no '=' in the name.
	 */
	PJDLOG_VERIFY(find_position(&equalpos, recordstr, recordstrlen,
	    namestart + 1, '='));
	nameend = equalpos - 1;
	PJDLOG_ASSERT(recordstr[nameend] != '=');

	name = linau_field_parse_name(recordstr, namestart, nameend);
	nvlist_move_string(field, BSMCONV_LINAU_FIELD_NAME, name);

	valstart = equalpos + 1;
	PJDLOG_ASSERT(valstart < recordstrlen);
	value = linau_field_parse_value(recordstr, recordstrlen, valstart);
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
