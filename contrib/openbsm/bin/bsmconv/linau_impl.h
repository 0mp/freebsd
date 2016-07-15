#ifndef _LINAU_IMPL_H_
#define _LINAU_IMPL_H_

#include <sys/nv.h>
#include <sys/queue.h>

struct linau_event {
	TAILQ_HEAD(, linau_record) 	le_records;
};

struct linau_record {
	uint32_t			 lr_id;
	char				*lr_type;
	uint64_t			 lr_time;
	nvlist_t			*lr_fields;
	size_t				 lr_fields_count;
	char				*lr_text;
	TAILQ_ENTRY(linau_record)	 lr_next;
};

#endif
