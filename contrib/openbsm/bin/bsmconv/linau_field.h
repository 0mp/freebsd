#ifndef _LINAU_FIELD_H_
#define _LINAU_FIELD_H_

#define BSMCONV_LINAU_FIELD_NAME	"name"
#define BSMCONV_LINAU_FIELD_VALUE	"value"
#define BSMCONV_LINAU_FIELD_TYPE	"__bsmconvlinaufieldtype__"
#define BSMCONV_LINAU_FIELD_TYPE_STRING	"string"

void linau_field_parse(nvlist_t ** const fieldp,
    const char * const recordstr, const size_t recordstrlen,
    size_t * const lastposp);

#endif
