#ifndef _LINAU_EVENT_H_
#define _LINAU_EVENT_H_

#include <sys/queue.h>
#include <stdint.h>

struct linau_event {
	uint32_t			le_size;
	TAILQ_HEAD(, linau_record)	le_records;
};

#endif
