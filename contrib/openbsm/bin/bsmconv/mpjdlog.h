#ifndef	_MPJDLOG_H_
#define	_MPJDLOG_H_

#include <stdarg.h>

#include "pjdlog.h"

#define mpjdlog_log_header(...) mpjdlog_proto_log(mpjdlog_get_level() - 1, \
    __func__, 0)

int	mpjdlog_get_level(void);
void	mpjdlog_set_level(int loglevel);
void	mpjdlog_log(const char *fmt, ...);
void	mpjdlog_log_trailer(void);

void	mpjdlog_proto_log(int loglevel, const char *fmt, va_list va);

#endif
