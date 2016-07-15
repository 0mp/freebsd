#ifndef _LINAU_CONV_H_
#define _LINAU_CONV_H_

#include "linau.h"

void	linau_conv_to_au(int aurecordd, const struct linau_record *record,
	    int typenum);
int	linau_conv_get_type_number(const char *type);

#endif
