#include "linau_event.h"
#include "linau_record.h"
#include "pjdlog.h"

static void
linau_event_add_record(struct linau_event * const event,
   struct linau_record * const record)
{
	pjdlog_debug(4, "linau_event_add_record");

	PJDLOG_ASSERT(event != NULL);
	/* TODO Why does this assert is illegal? */
	/* PJDLOG_ASSERT(event->records != NULL); */
	PJDLOG_ASSERT(record != NULL);

	/* Update the size. */
	event->size += record->size;

	/* Append the field to the record. */
	/* XXX Issue #23. */
	TAILQ_INSERT_TAIL(&event->records, record, next);
}

static void
linau_event_print(const struct linau_event * event)
{
	struct linau_record *rp;
	struct linau_record *rptemp;
	struct linau_field *fp;
	struct linau_field *fptemp;

	pjdlog_debug(1, "========================");
	pjdlog_debug(1, "event:");
	pjdlog_debug(1, " > size\t(%zu)", event->size);
	pjdlog_debug(1, " > records");

	TAILQ_FOREACH_SAFE(rp, &event->records, next, rptemp) {
		pjdlog_debug(1, " . > id\t(%lu)", rp->id);
		pjdlog_debug(1, " . > nsecs\t(%llu)", rp->nsecs);
		pjdlog_debug(1, " . > type\t(%.*s)", (int)rp->typelen, rp->type);
		pjdlog_debug(1, " . > typelen\t(%zu)", rp->typelen);
		pjdlog_debug(1, " . > size\t(%zu)", rp->size);
		/* TAILQ_REMOVE(&event->records, rp, next); */
		/* free(rp->type); */
		/* free(rp); */
		TAILQ_FOREACH_SAFE(fp, &rp->fields, next, fptemp) {
			pjdlog_debug(1, " . . > name\t(%.*s)", (int)fp->namelen,
			    fp->name);
			pjdlog_debug(1, " . . > namelen\t(%zu)", fp->namelen);
			pjdlog_debug(1, " . . > val\t(%.*s)", (int)fp->vallen,
			    fp->val);
			pjdlog_debug(1, " . . > vallen\t(%zu)", fp->vallen);
			pjdlog_debug(1, " . . > size\t(%zu)", fp->size);
			/* TAILQ_REMOVE(&rp->fields, fp, next); */
			/* free(fp->name); */
			/* free(fp->val); */
			/* free(fp); */
		}
	}
}
