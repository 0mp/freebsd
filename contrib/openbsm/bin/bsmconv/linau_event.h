#ifndef _LINAU_EVENT_H_
#define _LINAU_EVENT_H_

#include <nv.h>

#include "linau_record.h"

typedef nvlist_t linau_event;

linau_event *linau_event_create(void);
void linau_event_destroy(linau_event *event);

void linau_event_add_record(linau_event *event, const linau_record *record,
    size_t recordnum);
bool linau_event_empty(const linau_event *event);

uint32_t linau_event_get_id(const linau_event *event);
uint32_t linau_event_get_size(const linau_event *event);
uint64_t linau_event_get_timestamp(const linau_event *event);

void linau_event_set_id(linau_event *event, uint32_t id);
void linau_event_set_timestamp(linau_event *event, uint64_t timestamp);

void linau_event_print(const linau_event *event);

int linau_event_compare_origin(const linau_event *event,
    const linau_record *record);

#endif
