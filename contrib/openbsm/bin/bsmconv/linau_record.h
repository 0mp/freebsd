#ifndef _LINAU_RECORD_H_
#define _LINAU_RECORD_H_

#include <sys/queue.h>

#include <stdint.h>
#include <stdio.h>


#define BSMCONV_LINAU_RECORD_INPUT_BUFFER_SIZE 16

/* The sizes of the fileds are based on what I've found in
 * audit-userspace/auparse/auparse.h. */
struct linau_record {
	char				*lr_type;
	uint32_t			lr_typelen;
	uint32_t			lr_id;
	uint64_t			lr_nsecs;
	uint32_t			lr_size;
	TAILQ_HEAD(, linau_field)	lr_fields;
	TAILQ_ENTRY(linau_record) 	next;
};

struct linau_record * linau_record_fetch(FILE * fp);

struct linau_record * linau_record_parse(const char * const recordstr,
    const size_t recordstrlen);

void linau_record_parse_type(char ** const typep, size_t * const typelenp,
    const char * const recordstr, const size_t recordstrlen);
void linau_record_set_id(struct linau_record * const record, const uint32_t id);
void linau_record_set_nsecs(struct linau_record * const record,
    const uint64_t nsecs);
void linau_record_set_type(struct linau_record * const record,
    const char * const type, const size_t typelen);
void linau_record_parse_nsecs(uint64_t * const nsecsp,
    const char * const recordstr, const size_t recordstrlen);

#endif
