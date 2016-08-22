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
struct linau_record	*linau_record_create(void);
struct linau_record	*linau_record_construct(const char *type, uint32_t id,
			    uint64_t time, const nvlist_t *fields,
			    size_t fields_count, const char *buf);
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

void			 linau_record_set_fields(struct linau_record *record,
			    const nvlist_t *fields, size_t fields_count);
void			 linau_record_set_id(struct linau_record *record,
			    uint32_t id);
void			 linau_record_set_text(struct linau_record *record,
			    const char *text);
void			 linau_record_set_time(struct linau_record *record,
			    uint64_t time);
void			 linau_record_set_type(struct linau_record *record,
			    const char *type);

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
			    int aurd);

/* linau_field. */
struct linau_field	*linau_field_create(void);
void			 linau_field_destroy(struct linau_field *field);
void			 linau_field_shallow_destroy(struct linau_field *field);

const char		*linau_field_get_name(const struct linau_field *field);
const char		*linau_field_get_value(const struct linau_field *field);

void			 linau_field_set_name(struct linau_field *field,
			    const char *name);
void			 linau_field_set_value(struct linau_field *field,
			    const char *value);

struct linau_field	*linau_field_parse(const char *buf, size_t *lastposp);
char			*linau_field_parse_name(const char *buf, size_t start,
			    size_t end);
char			*linau_field_parse_value(const char *buf,
			    size_t start);

#endif
