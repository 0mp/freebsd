#include <sys/types.h>
#include <sys/sbuf.h>

#include <stdlib.h> /* NULL */

#include "mpjdlog.h"
#include "pjdlog.h"

static int mpjdlog_loglevel;

void
mpjdlog_proto_log(int loglevel, const char *fmt, va_list ap)
{
	struct sbuf *buf;
	int ii;

	buf = sbuf_new_auto();
	PJDLOG_VERIFY(buf != NULL);
	for (ii = 2; ii <= loglevel; ii++)
		sbuf_printf(buf, ". ");
	sbuf_printf(buf, "%s", fmt);
	PJDLOG_VERIFY(sbuf_finish(buf) == 0);

	pjdlogv_debug(mpjdlog_get_level(), sbuf_data(buf), ap);

	sbuf_delete(buf);
}

int
mpjdlog_get_level(void)
{

	return (mpjdlog_loglevel);
}

void
mpjdlog_set_level(int loglevel)
{

	mpjdlog_loglevel = loglevel;
}

void
mpjdlog_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	mpjdlog_proto_log(mpjdlog_get_level(), fmt, ap);
	va_end(ap);
}

void
mpjdlog_log_trailer(void)
{

	mpjdlog_log("");
}
