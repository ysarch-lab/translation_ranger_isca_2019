/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/pagechain.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagechain is a multipage container which is used for that.
 */

#ifndef _LINUX_PAGECHAIN_H
#define _LINUX_PAGECHAIN_H

#include <linux/slab.h>

/* 14 pointers + two long's align the pagechain structure to a power of two */
#define PAGECHAIN_SIZE	13

struct page;

struct pagechain {
	struct list_head list;
	unsigned long nr;
	struct page *pages[PAGECHAIN_SIZE];
};

static inline void pagechain_init(struct pagechain *pchain)
{
	pchain->nr = 0;
	INIT_LIST_HEAD(&pchain->list);
}

static inline void pagechain_reinit(struct pagechain *pchain)
{
	pchain->nr = 0;
}

static inline unsigned pagechain_count(struct pagechain *pchain)
{
	return pchain->nr;
}

static inline unsigned pagechain_space(struct pagechain *pchain)
{
	return PAGECHAIN_SIZE - pchain->nr;
}

static inline bool pagechain_empty(struct pagechain *pchain)
{
	return pchain->nr == 0;
}

/*
 * Add a page to a pagechain.  Returns the number of slots still available.
 */
static inline unsigned pagechain_deposit(struct pagechain *pchain, struct page *page)
{
	VM_BUG_ON(!pagechain_space(pchain));
	pchain->pages[pchain->nr++] = page;
	return pagechain_space(pchain);
}

static inline struct page *pagechain_withdraw(struct pagechain *pchain)
{
	if (!pagechain_count(pchain))
		return NULL;
	return pchain->pages[--pchain->nr];
}

void __init pagechain_cache_init(void);
struct pagechain *pagechain_alloc(void);
void pagechain_free(struct pagechain *pchain);

#endif /* _LINUX_PAGECHAIN_H */

