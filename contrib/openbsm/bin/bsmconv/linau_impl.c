#include <stdlib.h> /* NULL */

#include "linau_impl.h"
#include "pjdlog.h"

bool
find_position(size_t * const posp, const char * const buf, const size_t buflen,
    const size_t start, const char chr)
{

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(posp != NULL);

	for (*posp = start; *posp < buflen; (*posp)++)
		if (buf[*posp] == chr)
			break;

	return (*posp < buflen);
}

