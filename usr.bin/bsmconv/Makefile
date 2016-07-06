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
SRCS+=	linau_event.c
SRCS+=	linau_field.c
SRCS+=	linau_impl.c
SRCS+=	linau_record.c
SRCS+=	pjdlog.c

LIBADD+=sbuf util nv bsm
MAN=

.include <bsd.prog.mk>
