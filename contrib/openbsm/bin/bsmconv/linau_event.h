#ifndef _LINAU_EVENT_H_
#define _LINAU_EVENT_H_

#include <sys/queue.h>

#include <nv.h>
#include <stdint.h>

struct linau_event {
	uint32_t	le_size;
	nvlist_t	*le_records;
};

#endif
