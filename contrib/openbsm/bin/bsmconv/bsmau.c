#include "bsmau.h"

#include <sys/queue.h>

#include <stdlib.h>

#include "pjdlog.h"


struct bsmau_tokenlist *
bsmau_tokenlist_create(void)
{
	struct bsmau_tokenlist *tokenlist;

	tokenlist = calloc(1, sizeof(*tokenlist));
	PJDLOG_VERIFY(tokenlist != NULL);

	TAILQ_INIT(&tokenlist->btl_tokens);

	return (tokenlist);
}
