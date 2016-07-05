#include <ctype.h>
#include <errno.h>
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
linau_proto_compare_origin(uint32_t id1, uint64_t time1, uint32_t id2,
    uint64_t time2)
{

	if (time1 < time2)
		return -1;
	else if (time1 > time2)
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

/* XXX Ugly. */
void
locate_msg(const char *buf, size_t *msgstartp, size_t *secsposp,
    size_t *nsecsposp, size_t *idposp, size_t *msgendp)
{
	pjdlog_debug(6, " . . > linau_record_locate_msg");
	const char * msgprefix;
	size_t msgii, strii;
	size_t dotpos;
	size_t msgstart;
	size_t msgend;
	size_t nsecsstart;
	size_t secsstart;
	size_t separatorpos;
	size_t idstart;
	size_t msgprefixlen;
	size_t buflen;

	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);
	buflen = strlen(buf);

	msgprefix = "msg=audit(";
	msgprefixlen = strlen(msgprefix);
	PJDLOG_ASSERT(msgprefixlen == 10);

	/* Find msg field start. */
	for (strii = 0; strii < buflen; strii++) {
		for (msgii = 0; msgii < msgprefixlen; msgii++)
			if (buf[strii + msgii] != msgprefix[msgii])
				break;

		if (msgii == msgprefixlen)
			break;
	}

	PJDLOG_VERIFY(msgii == msgprefixlen);
	msgstart = strii;
	pjdlog_debug(6, " . . > msgstart: (%zu)", msgstart);
	secsstart = msgstart + msgprefixlen;
	PJDLOG_ASSERT(buf[secsstart] != '(');

	/* Find msg field msgend. */
	PJDLOG_VERIFY(find_position(&msgend, buf, msgstart, ')'));

	/* Find a dotpos inside the msg field. */
	PJDLOG_VERIFY(find_position(&dotpos, buf, msgstart, '.'));

	/* Find the timestamp:id separator. */
	PJDLOG_VERIFY(find_position(&separatorpos, buf, dotpos, ':'));

	nsecsstart = dotpos + 1;
	idstart = separatorpos + 1;

	PJDLOG_ASSERT(msgstart < secsstart &&
	    secsstart < nsecsstart &&
	    nsecsstart < idstart &&
	    idstart < msgend);

	*msgstartp = msgstart;
	*secsposp = secsstart;
	*nsecsposp = nsecsstart;
	*idposp = idstart;
	*msgendp = msgend;

	pjdlog_debug(6, " . . > secspos (%zu), nsecspos (%zu), idpos (%zu), "
	    "msgstart (%zu), msgend (%zu)", secsstart, nsecsstart, idstart,
	    msgstart, *msgendp);
}

uint32_t
extract_uint32(const char *buf, size_t start, size_t end)
{
	size_t len;
	uint32_t num;
	char *numstr;

	PJDLOG_ASSERT(isdigit(buf[start]) != 0);
	PJDLOG_ASSERT(isdigit(buf[end]) != 0);

	len = end - start + 1;
	numstr = extract_substring(buf, start, len);
	num = string_to_uint32(numstr);

	return (num);
}

uint32_t
string_to_uint32(const char *str)
{
	char *endp;
	uint32_t num;

	pjdlog_debug(6, " . . >> string_to_uint32");

	errno = 0;
	num = (uint32_t)strtoul(str, &endp, 10);

	PJDLOG_VERIFY(str != endp);
	PJDLOG_VERIFY(*endp == '\0');
	PJDLOG_VERIFY(num != 0 || errno == 0);

	return (num);
}



size_t
find_string_value_end(const char *buf, size_t start, char stringtype)
{
	size_t end;
	size_t prevend;
	size_t buflen;

	PJDLOG_ASSERT(buf != NULL);

	buflen = strlen(buf);
	end = start + 1;
	PJDLOG_ASSERT(end < buflen);

	do {
		prevend = end;
		PJDLOG_VERIFY(find_position(&end, buf, prevend, stringtype));
	} while (buf[end - 1] == '\\');

	return (end);
}
