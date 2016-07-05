#ifndef _BSMAU_H_
#define _BSMAU_H_

#include <sys/queue.h>

#include <bsm/libbsm.h>

struct bsmau_tokenlist {
	TAILQ_HEAD(, bsmau_token)	btl_tokens;
};

struct bsmau_token {
	u_char				bt_buf;
	size_t				bt_len;
	TAILQ_ENTRY(bsmau_token)	bt_next;
};

struct bsmau_tokenlist		*bsmau_tokenlist_create(void);

#endif
