/*-
 * Copyright (c) 2016 Mateusz Piotrowski <0mp@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed by Mateusz Piotrowski during
 * the Google Summer of Code 2016 under the mentorship of Konrad Witaszczyk.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "linau.h"
#include "linau_common.h"
#include "linau_impl.h"
#include "pjdlog.h"

static size_t find_string_value_end(const char *buf, size_t start,
    char stringtype);

struct linau_field {
	char	*lf_name;
	char	*lf_value;
};

static size_t
find_string_value_end(const char *buf, size_t start, char stringtype)
{
	size_t buflen;
	size_t end;
	/* STYLE: How to call such variables like endchrp? */
	char *endchrp;

	PJDLOG_ASSERT(buf != NULL);

	buflen = strlen(buf);
	end = start + 1;
	PJDLOG_ASSERT(end < buflen);

	do {
		endchrp = strchr(buf + end, stringtype);
		/* STYLE: PJDLOG_ASSERT or PJDLOG_VERIFY? */
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
	PJDLOG_ASSERT(field != NULL);

	return (field);
}

void
linau_field_destroy(struct linau_field *field)
{

	free(field->lf_name);
	free(field->lf_value);
	linau_field_shallow_destroy(field);
}

void
linau_field_shallow_destroy(struct linau_field *field)
{

	free(field);
}

const char *
linau_field_get_name(const struct linau_field *field)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(field->lf_name != NULL);

	return (field->lf_name);
}

const char *
linau_field_get_value(const struct linau_field *field)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(field->lf_value != NULL);

	return (field->lf_value);
}

void
linau_field_set_name(struct linau_field *field, const char *name)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(name != NULL);
	PJDLOG_ASSERT(strchr(name, '\0') != NULL);

	field->lf_name = strdup(name);
	PJDLOG_ASSERT(field->lf_name != NULL);
}

void
linau_field_set_value(struct linau_field *field, const char *value)
{

	PJDLOG_ASSERT(field != NULL);
	PJDLOG_ASSERT(value != NULL);
	PJDLOG_ASSERT(strchr(value, '\0') != NULL);

	field->lf_value = strdup(value);
	PJDLOG_ASSERT(field->lf_value != NULL);
}

/*
 * XXX: This function allows the fileds to be separated by ",[ ]*" or "[ ]+".
 * In the future, when the Linux Audit becomes more standardized, this function
 * should allow "," and " " separators only.
 */
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

	namestart = *lastposp;
	pjdlog_debug(6, " . . . . . . namestart (%zu) points to (%c)",
	    namestart, buf[namestart]);

	/* Skip a comma or a space. */
	if (namestart + 1 < buflen && buf[namestart] == ' ')
		namestart++;
	else if (namestart + 1 < buflen && buf[namestart] == ',')
		namestart++;
	else
		PJDLOG_ABORT("The record fields should be separated by either "
		    "a comma or a space");

	/*
	 * Skip any number of spaces.
	 *
	 * XXX: It is not within the Linux Audit 'standard' but it is quite
	 * often to see a comma and a space afterwards.
	 */
	while (namestart + 1 < buflen && buf[namestart] == ' ')
		namestart++;

	PJDLOG_ASSERT(! buf[namestart] != ' ' && buf[namestart] != ',');

	pjdlog_debug(6, " . . . . . . Nonspace namestart (%zu) points to (%c)",
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

	*lastposp = valstart + strlen(value);

	pjdlog_debug(6, " . . . . . -");

	return (field);
}

char *
linau_field_parse_name(const char *buf, size_t start, size_t end)
{

	return (extract_substring(buf, start, end - start + 1));
}

char *
linau_field_parse_value(const char *buf, size_t start)
{
	char *value;
	size_t end;
	size_t spacepos;

	PJDLOG_ASSERT(buf != NULL);

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
		/* STYLE: Ugly. */
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
