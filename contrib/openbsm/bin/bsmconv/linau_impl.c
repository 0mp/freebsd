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

uintmax_t
linau_proto_get_number(const nvlist_t *nvl, const char *nvname)
{
	uintmax_t num;

	PJDLOG_ASSERT(nvl != NULL);
	PJDLOG_ASSERT(!nvlist_empty(nvl));
	PJDLOG_ASSERT(nvlist_error(nvl) == 0);

	PJDLOG_ASSERT(nvlist_exists_number(nvl, nvname));

	num = nvlist_get_number(nvl, nvname);

	PJDLOG_VERIFY(nvlist_error(nvl) == 0);

	return (num);
}

const char *
linau_proto_get_string(const nvlist_t *nvl, const char *nvname)
{
	const char *str;

	str = nvlist_get_string(nvl, nvname);

	PJDLOG_VERIFY(nvlist_error(nvl) == 0);

	return (str);
}

void
linau_proto_set_number(nvlist_t *nvl, const char *nvname, uintmax_t num)
{

	PJDLOG_ASSERT(nvl != NULL);
	PJDLOG_ASSERT(nvname != NULL);

	nvlist_add_number(nvl, nvname, num);

	PJDLOG_VERIFY(nvlist_error(nvl) == 0);
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

int
linau_proto_compare_origin(uint32_t id1, uint64_t timestamp1, uint32_t id2,
    uint64_t timestamp2)
{

	if (timestamp1 < timestamp2)
		return -1;
	else if (timestamp1 > timestamp2)
		return 1;
	else if (id1 < id2)
		return -1;
	else if (id1 > id2)
		return 1;
	else
		return 0;
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

	PJDLOG_ASSERT(buf != NULL);
	PJDLOG_ASSERT(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(start + len <= strlen(buf));

	substr = malloc((len + 1) * sizeof(*substr));
	PJDLOG_VERIFY(substr != NULL);
	PJDLOG_VERIFY(strncpy(substr, buf + start, len) != NULL);
	substr[len] = '\0';
	PJDLOG_VERIFY(strncmp(substr, buf + start, len) == 0);

	return (substr);
}
