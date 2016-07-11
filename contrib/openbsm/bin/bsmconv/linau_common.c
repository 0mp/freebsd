#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "linau_common.h"
#include "pjdlog.h"

int
linau_proto_compare_origin(uint32_t id1, uint64_t time1, uint32_t id2,
    uint64_t time2)
{

	if (time1 < time2)
		return -1;
	if (time1 > time2)
		return 1;
	if (id1 < id2)
		return -1;
	if (id1 > id2)
		return 1;

	return 0;
}

uint64_t
combine_secs_with_nsecs(uint32_t secs, uint32_t nsecs)
{

	return ((uint64_t)(secs) * (1000 * 1000 * 1000) + (uint64_t)nsecs);
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
	const char * msgprefix;
	size_t buflen;
	size_t dotpos;
	size_t idstart;
	size_t msgend;
	size_t msgii;
	size_t msgprefixlen;
	size_t msgstart;
	size_t nsecsstart;
	size_t secsstart;
	size_t separatorpos;
	size_t strii;

	PJDLOG_VERIFY(strchr(buf, '\0') != NULL);
	PJDLOG_ASSERT(buf != NULL);

	buflen = strlen(buf);

	pjdlog_debug(6, " . . > linau_record_locate_msg");

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
string_to_uint32(const char *str)
{
	char *endp;
	uint32_t num;

	PJDLOG_ASSERT(str != NULL);

	errno = 0;
	num = (uint32_t)strtoul(str, &endp, 10);

	PJDLOG_VERIFY(str != endp);
	PJDLOG_VERIFY(*endp == '\0');
	PJDLOG_VERIFY(num != 0 || errno == 0);

	return (num);
}
