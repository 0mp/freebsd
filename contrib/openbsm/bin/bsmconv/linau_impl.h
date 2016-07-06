#ifndef _LINAU_IMPL_H_
#define _LINAU_IMPL_H_

#include <sys/nv.h>
#include <sys/types.h>

#include <stdbool.h>


int		 linau_proto_compare_origin(uint32_t id1, uint64_t time1,
		    uint32_t id2, uint64_t time2);

bool		 find_position(size_t *posp, const char *buf, size_t start,
		    char chr);
void		 locate_msg(const char *buf, size_t *msgstartp,
		    size_t *secsposp, size_t *nsecsposp, size_t *idposp,
		    size_t *msgendp);
char		*extract_substring(const char *buf, size_t start, size_t len);


#endif
