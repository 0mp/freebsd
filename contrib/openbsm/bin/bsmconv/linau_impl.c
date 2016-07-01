#include <stdlib.h>
#include <string.h>

#include "linau_impl.h"
#include "pjdlog.h"

nvlist_t *
linau_proto_create(void)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);

	/* XXX PJDLOG_VERIFY or if? */
	if (nvlist_error(nvl) == 0)
		return (nvl);
	else
		return (NULL);
}

void
linau_proto_destroy(nvlist_t *nvl)
{

	nvlist_destroy(nvl);
}

void
linau_proto_set_string(nvlist_t *nvl, const char *nvname, const char *str)
{

	PJDLOG_ASSERT(nvl != NULL);
	PJDLOG_ASSERT(str != NULL);

	nvlist_add_string(nvl, nvname, str);
	PJDLOG_VERIFY(nvlist_error(nvl) == 0);
	PJDLOG_ASSERT(nvlist_exists_string(nvl, nvname));
}

bool
find_position(size_t *posp, const char *buf, size_t start, char chr)
{
	size_t buflen;

	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(posp != NULL);

	buflen = strlen(buf);

	for (*posp = start; *posp < buflen; (*posp)++)
		if (buf[*posp] == chr)
			break;

	return (*posp < buflen);
}

char *
extract_substring(const char *buf, size_t start, size_t len)
{
	char *substr;

	pjdlog_debug(5, " . > extract_substring");
	pjdlog_debug(5, " . > start (%zu), len (%zu), buflen (%zu)", start, len,
	    strlen(buf));
	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(start + len <= strlen(buf));

	substr = calloc(len + 1, sizeof(*substr));
	PJDLOG_VERIFY(substr != NULL);
	PJDLOG_VERIFY(strncpy(substr, buf + start, len) != NULL);
	substr[len] = '\0';
	PJDLOG_VERIFY(strncmp(substr, buf + start, len) == 0);

	pjdlog_debug(5, " . > End of extract_substring");
	return (substr);
}
