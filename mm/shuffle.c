// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2018 Intel Corporation. All rights reserved.

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/mmzone.h>
#include <linux/random.h>
#include "internal.h"

/*
 * For two pages to be swapped in the shuffle, they must be free (on a
 * 'free_area' lru), have the same order, and have the same migratetype.
 */
static struct page * __meminit shuffle_valid_page(unsigned long pfn, int order)
{
	struct page *page;

	/*
	 * Given we're dealing with randomly selected pfns in a zone we
	 * need to ask questions like...
	 */

	/* ...is the pfn even in the memmap? */
	if (!pfn_valid_within(pfn))
		return NULL;

	/* ...is the pfn in a present section or a hole? */
	if (!pfn_present(pfn))
		return NULL;

	/* ...is the page free and currently on a free_area list? */
	page = pfn_to_page(pfn);
	if (!PageBuddy(page))
		return NULL;

	/*
	 * ...is the page on the same list as the page we will
	 * shuffle it with?
	 */
	if (page_order(page) != order)
		return NULL;

	return page;
}

/*
 * Fisher-Yates shuffle the freelist which prescribes iterating through
 * an array, pfns in this case, and randomly swapping each entry with
 * another in the span, end_pfn - start_pfn.
 *
 * To keep the implementation simple it does not attempt to correct for
 * sources of bias in the distribution, like modulo bias or
 * pseudo-random number generator bias. I.e. the expectation is that
 * this shuffling raises the bar for attacks that exploit the
 * predictability of page allocations, but need not be a perfect
 * shuffle.
 *
 * Note that we don't use @z->zone_start_pfn and zone_end_pfn(@z)
 * directly since the caller may be aware of holes in the zone and can
 * improve the accuracy of the random pfn selection.
 */
#define SHUFFLE_RETRY 10
static void __meminit shuffle_zone_order(struct zone *z, unsigned long start_pfn,
		unsigned long end_pfn, const int order)
{
	unsigned long i, flags;
	const int order_pages = 1 << order;

	if (start_pfn < z->zone_start_pfn)
		start_pfn = z->zone_start_pfn;
	if (end_pfn > zone_end_pfn(z))
		end_pfn = zone_end_pfn(z);

	/* probably means that start/end were outside the zone */
	if (end_pfn <= start_pfn)
		return;
	spin_lock_irqsave(&z->lock, flags);
	start_pfn = ALIGN(start_pfn, order_pages);
	for (i = start_pfn; i < end_pfn; i += order_pages) {
		unsigned long j;
		int migratetype, retry;
		struct page *page_i, *page_j;

		/*
		 * We expect page_i, in the sub-range of a zone being
		 * added (@start_pfn to @end_pfn), to more likely be
		 * valid compared to page_j randomly selected in the
		 * span @zone_start_pfn to @spanned_pages.
		 */
		page_i = shuffle_valid_page(i, order);
		if (!page_i)
			continue;

		for (retry = 0; retry < SHUFFLE_RETRY; retry++) {
			/*
			 * Pick a random order aligned page from the
			 * start of the zone. Use the *whole* zone here
			 * so that if it is freed in tiny pieces that we
			 * randomize in the whole zone, not just within
			 * those fragments.
			 *
			 * Since page_j comes from a potentially sparse
			 * address range we want to try a bit harder to
			 * find a shuffle point for page_i.
			 */
			j = z->zone_start_pfn +
				ALIGN_DOWN(get_random_long() % z->spanned_pages,
						order_pages);
			page_j = shuffle_valid_page(j, order);
			if (page_j && page_j != page_i)
				break;
		}
		if (retry >= SHUFFLE_RETRY) {
			pr_debug("%s: failed to swap %#lx\n", __func__, i);
			continue;
		}

		/*
		 * Each migratetype corresponds to its own list, make
		 * sure the types match otherwise we're moving pages to
		 * lists where they do not belong.
		 */
		migratetype = get_pageblock_migratetype(page_i);
		if (get_pageblock_migratetype(page_j) != migratetype) {
			pr_debug("%s: migratetype mismatch %#lx\n", __func__, i);
			continue;
		}

		list_swap(&page_i->lru, &page_j->lru);

		pr_debug("%s: swap: %#lx -> %#lx\n", __func__, i, j);

		/* take it easy on the zone lock */
		if ((i % (100 * order_pages)) == 0) {
			spin_unlock_irqrestore(&z->lock, flags);
			cond_resched();
			spin_lock_irqsave(&z->lock, flags);
		}
	}
	spin_unlock_irqrestore(&z->lock, flags);
}

void __meminit shuffle_zone(struct zone *z, unsigned long start_pfn,
               unsigned long end_pfn)
{
       int i;

       /* shuffle all the orders at the specified order and higher */
       for (i = CONFIG_SHUFFLE_PAGE_ORDER; i < MAX_ORDER; i++)
               shuffle_zone_order(z, start_pfn, end_pfn, i);
}

/**
 * shuffle_free_memory - reduce the predictability of the page allocator
 * @pgdat: node page data
 * @start_pfn: Limit the shuffle to the greater of this value or zone start
 * @end_pfn: Limit the shuffle to the less of this value or zone end
 *
 * While shuffle_zone() attempts to avoid holes with pfn_valid() and
 * pfn_present() they can not report sub-section sized holes. @start_pfn
 * and @end_pfn limit the shuffle to the exact memory pages being freed.
 */
void __meminit shuffle_free_memory(pg_data_t *pgdat, unsigned long start_pfn,
		unsigned long end_pfn)
{
	struct zone *z;

	for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
		shuffle_zone(z, start_pfn, end_pfn);
}

void add_to_free_area_random(struct page *page, struct free_area *area,
		int migratetype)
{
	if (area->rand_bits == 0) {
		area->rand_bits = 64;
		area->rand = get_random_u64();
	}

	if (area->rand & 1)
		add_to_free_area(page, area, migratetype);
	else
		add_to_free_area_tail(page, area, migratetype);
	area->rand_bits--;
	area->rand >>= 1;
}
