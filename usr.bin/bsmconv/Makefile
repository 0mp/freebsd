#
# $FreeBSD$
#

OPENBSMDIR=${.CURDIR}/../../contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/bsmconv
CFLAGS+=-I${OPENBSMDIR} -I${OPENBSMDIR}/sys

NO_WFORMAT=
NO_WMISSING_VARIABLE_DECLARATIONS=

PROG=	bsmconv
SRCS=	bsmconv.c
SRCS+=	linau_common.c
SRCS+=	linau_conv.c
SRCS+=	linau_event.c
SRCS+=	linau_field.c
SRCS+=	linau_record.c
SRCS+=	pjdlog.c
SRCS+=	mpjdlog.c

LIBADD+=sbuf util nv bsm
MAN=

.include <bsd.prog.mk>
