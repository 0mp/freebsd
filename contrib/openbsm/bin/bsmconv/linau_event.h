#ifndef _LINAU_EVENT_H_
#define _LINAU_EVENT_H_

#include <nv.h>

#include "linau_record.h"

typedef nvlist_t linau_event;

linau_event *linau_event_create(void);
void linau_event_destroy(linau_event *event);

void linau_event_add_record(linau_event *event, const linau_record *record);

uint32_t linau_event_get_size(const linau_event *event);

void linau_event_print(const linau_event *event);

#endif
