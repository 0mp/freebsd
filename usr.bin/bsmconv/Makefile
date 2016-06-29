#
# $FreeBSD$
#

OPENBSMDIR=${.CURDIR}/../../contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/bsmconv
CFLAGS+=-I${OPENBSMDIR} -I${OPENBSMDIR}/bin/auditdistd

NO_WFORMAT=
NO_WMISSING_VARIABLE_DECLARATIONS=

PROG=	bsmconv
SRCS=	bsmconv.c
SRCS+=	pjdlog.c
SRCS+=	linau_event.c
SRCS+=	linau_record.c

LIBADD+=sbuf util
MAN=

# auditdistd cannot use FreeBSD specific lock annotation macros. Disable
# thread safety analysis completely.
# NO_WTHREAD_SAFETY=

.include <bsd.prog.mk>
