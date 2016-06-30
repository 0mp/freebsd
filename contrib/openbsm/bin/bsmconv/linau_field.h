#ifndef _LINAU_FIELD_H_
#define _LINAU_FIELD_H_

#include <sys/queue.h>
#include <stdint.h>

struct linau_field {
	char				*lf_name;
	uint32_t			lf_namelen;
	char				*lf_val;
	uint32_t			lf_vallen;
	uint32_t			lf_size;
};

#endif
