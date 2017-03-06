/*
 * Exchange two in-use pages. Page flags and page->mapping are exchanged
 * as well. Only anonymous pages are supported.
 *
 * Copyright (C) 2016 NVIDIA, Zi Yan <ziy@nvidia.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#include <linux/syscalls.h>
#include <linux/migrate.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/mm_inline.h>
#include <linux/page_idle.h>
#include <linux/page-flags.h>
#include <linux/ksm.h>
#include <linux/memcontrol.h>
#include <linux/balloon_compaction.h>
#include <linux/buffer_head.h>
#include <linux/fs.h> /* buffer_migrate_page  */
#include <linux/backing-dev.h>


#include "internal.h"

struct exchange_page_info {
	struct page *from_page;
	struct page *to_page;

	struct anon_vma *from_anon_vma;
	struct anon_vma *to_anon_vma;

	struct list_head list;
};

struct page_flags {
	unsigned int page_error :1;
	unsigned int page_referenced:1;
	unsigned int page_uptodate:1;
	unsigned int page_active:1;
	unsigned int page_unevictable:1;
	unsigned int page_checked:1;
	unsigned int page_mappedtodisk:1;
	unsigned int page_dirty:1;
	unsigned int page_is_young:1;
	unsigned int page_is_idle:1;
	unsigned int page_swapcache:1;
	unsigned int page_writeback:1;
	unsigned int page_private:1;
	unsigned int page_doublemap:1;
	unsigned int __pad:2;
};


static void exchange_page(char *to, char *from)
{
	u64 tmp;
	int i;

	for (i = 0; i < PAGE_SIZE; i += sizeof(tmp)) {
		tmp = *((u64*)(from + i));
		*((u64*)(from + i)) = *((u64*)(to + i));
		*((u64*)(to + i)) = tmp;
	}
}

static inline void exchange_highpage(struct page *to, struct page *from)
{
	char *vfrom, *vto;

	vfrom = kmap_atomic(from);
	vto = kmap_atomic(to);
	exchange_page(vto, vfrom);
	kunmap_atomic(vto);
	kunmap_atomic(vfrom);
}

static void __exchange_gigantic_page(struct page *dst, struct page *src,
				int nr_pages)
{
	int i;
	struct page *dst_base = dst;
	struct page *src_base = src;

	for (i = 0; i < nr_pages; ) {
		cond_resched();
		exchange_highpage(dst, src);

		i++;
		dst = mem_map_next(dst, dst_base, i);
		src = mem_map_next(src, src_base, i);
	}
}

static void exchange_huge_page(struct page *dst, struct page *src)
{
	int i;
	int nr_pages;

	if (PageHuge(src)) {
		/* hugetlbfs page */
		struct hstate *h = page_hstate(src);
		nr_pages = pages_per_huge_page(h);

		if (unlikely(nr_pages > MAX_ORDER_NR_PAGES)) {
			__exchange_gigantic_page(dst, src, nr_pages);
			return;
		}
	} else {
		/* thp page */
		BUG_ON(!PageTransHuge(src));
		nr_pages = hpage_nr_pages(src);
	}

	for (i = 0; i < nr_pages; i++) {
		cond_resched();
		exchange_highpage(dst + i, src + i);
	}
}

/*
 * Copy the page to its new location without polluting cache
 */
static void exchange_page_flags(struct page *to_page, struct page *from_page)
{
	int from_cpupid, to_cpupid;
	struct page_flags from_page_flags = {0}, to_page_flags = {0};
	struct mem_cgroup *to_memcg = page_memcg(to_page),
					  *from_memcg = page_memcg(from_page);

	from_cpupid = page_cpupid_xchg_last(from_page, -1);

	from_page_flags.page_error = PageError(from_page);
	if (from_page_flags.page_error)
		ClearPageError(from_page);
	from_page_flags.page_referenced = TestClearPageReferenced(from_page);
	from_page_flags.page_uptodate = PageUptodate(from_page);
	ClearPageUptodate(from_page);
	from_page_flags.page_active = TestClearPageActive(from_page);
	from_page_flags.page_unevictable = TestClearPageUnevictable(from_page);
	from_page_flags.page_checked = PageChecked(from_page);
	if (from_page_flags.page_checked)
		ClearPageChecked(from_page);
	from_page_flags.page_mappedtodisk = PageMappedToDisk(from_page);
	ClearPageMappedToDisk(from_page);
	from_page_flags.page_dirty = PageDirty(from_page);
	ClearPageDirty(from_page);
	from_page_flags.page_is_young = test_and_clear_page_young(from_page);
	from_page_flags.page_is_idle = page_is_idle(from_page);
	clear_page_idle(from_page);
	from_page_flags.page_swapcache = PageSwapCache(from_page);
	/*from_page_flags.page_private = PagePrivate(from_page);*/
	/*ClearPagePrivate(from_page);*/
	from_page_flags.page_writeback = test_clear_page_writeback(from_page);
	from_page_flags.page_doublemap = PageDoubleMap(from_page);


	to_cpupid = page_cpupid_xchg_last(to_page, -1);

	to_page_flags.page_error = PageError(to_page);
	if (to_page_flags.page_error)
		ClearPageError(to_page);
	to_page_flags.page_referenced = TestClearPageReferenced(to_page);
	to_page_flags.page_uptodate = PageUptodate(to_page);
	ClearPageUptodate(to_page);
	to_page_flags.page_active = TestClearPageActive(to_page);
	to_page_flags.page_unevictable = TestClearPageUnevictable(to_page);
	to_page_flags.page_checked = PageChecked(to_page);
	if (to_page_flags.page_checked)
		ClearPageChecked(to_page);
	to_page_flags.page_mappedtodisk = PageMappedToDisk(to_page);
	ClearPageMappedToDisk(to_page);
	to_page_flags.page_dirty = PageDirty(to_page);
	ClearPageDirty(to_page);
	to_page_flags.page_is_young = test_and_clear_page_young(to_page);
	to_page_flags.page_is_idle = page_is_idle(to_page);
	clear_page_idle(to_page);
	to_page_flags.page_swapcache = PageSwapCache(to_page);
	/*to_page_flags.page_private = PagePrivate(to_page);*/
	/*ClearPagePrivate(to_page);*/
	to_page_flags.page_writeback = test_clear_page_writeback(to_page);
	to_page_flags.page_doublemap = PageDoubleMap(to_page);

	/* set to_page */
	if (from_page_flags.page_error)
		SetPageError(to_page);
	if (from_page_flags.page_referenced)
		SetPageReferenced(to_page);
	if (from_page_flags.page_uptodate)
		SetPageUptodate(to_page);
	if (from_page_flags.page_active) {
		VM_BUG_ON_PAGE(from_page_flags.page_unevictable, from_page);
		SetPageActive(to_page);
	} else if (from_page_flags.page_unevictable)
		SetPageUnevictable(to_page);
	if (from_page_flags.page_checked)
		SetPageChecked(to_page);
	if (from_page_flags.page_mappedtodisk)
		SetPageMappedToDisk(to_page);

	/* Move dirty on pages not done by migrate_page_move_mapping() */
	if (from_page_flags.page_dirty)
		SetPageDirty(to_page);

	if (from_page_flags.page_is_young)
		set_page_young(to_page);
	if (from_page_flags.page_is_idle)
		set_page_idle(to_page);
	if (from_page_flags.page_doublemap)
		SetPageDoubleMap(to_page);

	/* set from_page */
	if (to_page_flags.page_error)
		SetPageError(from_page);
	if (to_page_flags.page_referenced)
		SetPageReferenced(from_page);
	if (to_page_flags.page_uptodate)
		SetPageUptodate(from_page);
	if (to_page_flags.page_active) {
		VM_BUG_ON_PAGE(to_page_flags.page_unevictable, from_page);
		SetPageActive(from_page);
	} else if (to_page_flags.page_unevictable)
		SetPageUnevictable(from_page);
	if (to_page_flags.page_checked)
		SetPageChecked(from_page);
	if (to_page_flags.page_mappedtodisk)
		SetPageMappedToDisk(from_page);

	/* Move dirty on pages not done by migrate_page_move_mapping() */
	if (to_page_flags.page_dirty)
		SetPageDirty(from_page);

	if (to_page_flags.page_is_young)
		set_page_young(from_page);
	if (to_page_flags.page_is_idle)
		set_page_idle(from_page);
	if (to_page_flags.page_doublemap)
		SetPageDoubleMap(from_page);

	/*
	 * Copy NUMA information to the new page, to prevent over-eager
	 * future migrations of this same page.
	 */
	page_cpupid_xchg_last(to_page, from_cpupid);
	page_cpupid_xchg_last(from_page, to_cpupid);

	ksm_exchange_page(to_page, from_page);
	/*
	 * Please do not reorder this without considering how mm/ksm.c's
	 * get_ksm_page() depends upon ksm_migrate_page() and PageSwapCache().
	 */
	ClearPageSwapCache(to_page);
	ClearPageSwapCache(from_page);
	if (from_page_flags.page_swapcache)
		SetPageSwapCache(to_page);
	if (to_page_flags.page_swapcache)
		SetPageSwapCache(from_page);


#ifdef CONFIG_PAGE_OWNER
	/* exchange page owner  */
	BUG();
#endif
	/* exchange mem cgroup  */
	to_page->mem_cgroup = from_memcg;
	from_page->mem_cgroup = to_memcg;

}

/*
 * Replace the page in the mapping.
 *
 * The number of remaining references must be:
 * 1 for anonymous pages without a mapping
 * 2 for pages with a mapping
 * 3 for pages with a mapping and PagePrivate/PagePrivate2 set.
 */

static int exchange_page_move_mapping(struct address_space *to_mapping,
			struct address_space *from_mapping,
			struct page *to_page, struct page *from_page,
			struct buffer_head *to_head, struct buffer_head *from_head,
			enum migrate_mode mode,
			int to_extra_count, int from_extra_count)
{
	int to_expected_count = 1 + to_extra_count,
		from_expected_count = 1 + from_extra_count;
	unsigned long from_page_index = from_page->index;
	unsigned long to_page_index = to_page->index;
	int to_swapbacked = PageSwapBacked(to_page),
		from_swapbacked = PageSwapBacked(from_page);
	struct address_space *to_mapping_value = to_page->mapping,
						 *from_mapping_value = from_page->mapping;

	VM_BUG_ON_PAGE(to_mapping != page_mapping(to_page), to_page);
	VM_BUG_ON_PAGE(from_mapping != page_mapping(from_page), from_page);
	VM_BUG_ON(PageCompound(from_page) != PageCompound(to_page));

	if (!to_mapping) {
		/* Anonymous page without mapping */
		if (page_count(to_page) != to_expected_count)
			return -EAGAIN;
	}

	if (!from_mapping) {
		/* Anonymous page without mapping */
		if (page_count(from_page) != from_expected_count)
			return -EAGAIN;
	}

	/* both are anonymous pages  */
	if (!from_mapping && !to_mapping) {
		/* from_page  */
		from_page->index = to_page_index;
		from_page->mapping = to_mapping_value;

		ClearPageSwapBacked(from_page);
		if (to_swapbacked)
			SetPageSwapBacked(from_page);


		/* to_page  */
		to_page->index = from_page_index;
		to_page->mapping = from_mapping_value;

		ClearPageSwapBacked(to_page);
		if (from_swapbacked)
			SetPageSwapBacked(to_page);
	} else if (!from_mapping && to_mapping) { /* from is anonymous, to is file-backed  */
		struct zone *from_zone, *to_zone;
		void **to_pslot;
		int dirty;

		from_zone = page_zone(from_page);
		to_zone = page_zone(to_page);

		spin_lock_irq(&to_mapping->tree_lock);

		to_pslot = radix_tree_lookup_slot(&to_mapping->page_tree, page_index(to_page));

		to_expected_count += 1 + page_has_private(to_page);
		if (page_count(to_page) != to_expected_count ||
			radix_tree_deref_slot_protected(to_pslot, &to_mapping->tree_lock)
			!= to_page) {
			spin_unlock_irq(&to_mapping->tree_lock);
			return -EAGAIN;
		}

		if (!page_ref_freeze(to_page, to_expected_count)) {
			spin_unlock_irq(&to_mapping->tree_lock);
			pr_debug("cannot freeze page count\n");
			return -EAGAIN;
		}

		if (mode == MIGRATE_ASYNC && to_head &&
				!buffer_migrate_lock_buffers(to_head, mode)) {
			page_ref_unfreeze(to_page, to_expected_count);
			spin_unlock_irq(&to_mapping->tree_lock);

			pr_debug("cannot lock buffer head\n");
			return -EAGAIN;
		}

		if (!page_ref_freeze(from_page, from_expected_count)) {
			page_ref_unfreeze(to_page, to_expected_count);
			spin_unlock_irq(&to_mapping->tree_lock);

			return -EAGAIN;
		}
		/*
		 * Now we know that no one else is looking at the page:
		 * no turning back from here.
		 */
		ClearPageSwapBacked(from_page);
		ClearPageSwapBacked(to_page);

		/* from_page  */
		from_page->index = to_page_index;
		from_page->mapping = to_mapping_value;
		/* to_page  */
		to_page->index = from_page_index;
		to_page->mapping = from_mapping_value;

		if (to_swapbacked)
			__SetPageSwapBacked(from_page);
		else
			VM_BUG_ON_PAGE(PageSwapCache(to_page), to_page);

		if (from_swapbacked)
			__SetPageSwapBacked(to_page);
		else
			VM_BUG_ON_PAGE(PageSwapCache(from_page), from_page);

		dirty = PageDirty(to_page);

		radix_tree_replace_slot(&to_mapping->page_tree, to_pslot, from_page);

		/* move cache reference */
		page_ref_unfreeze(to_page, to_expected_count - 1);
		page_ref_unfreeze(from_page, from_expected_count + 1);

		spin_unlock(&to_mapping->tree_lock);

		/*
		 * If moved to a different zone then also account
		 * the page for that zone. Other VM counters will be
		 * taken care of when we establish references to the
		 * new page and drop references to the old page.
		 *
		 * Note that anonymous pages are accounted for
		 * via NR_FILE_PAGES and NR_ANON_MAPPED if they
		 * are mapped to swap space.
		 */
		if (to_zone != from_zone) {
			__dec_node_state(to_zone->zone_pgdat, NR_FILE_PAGES);
			__inc_node_state(from_zone->zone_pgdat, NR_FILE_PAGES);
			if (PageSwapBacked(to_page) && !PageSwapCache(to_page)) {
				__dec_node_state(to_zone->zone_pgdat, NR_SHMEM);
				__inc_node_state(from_zone->zone_pgdat, NR_SHMEM);
			}
			if (dirty && mapping_cap_account_dirty(to_mapping)) {
				__dec_node_state(to_zone->zone_pgdat, NR_FILE_DIRTY);
				__dec_zone_state(to_zone, NR_ZONE_WRITE_PENDING);
				__inc_node_state(from_zone->zone_pgdat, NR_FILE_DIRTY);
				__inc_zone_state(from_zone, NR_ZONE_WRITE_PENDING);
			}
		}
		local_irq_enable();

	} else {
		/* from is file-backed to is anonymous: fold this to the case above */
		/* both are file-backed  */
		BUG();
	}

	return MIGRATEPAGE_SUCCESS;
}

static int exchange_from_to_pages(struct page *to_page, struct page *from_page,
				enum migrate_mode mode)
{
	int rc = -EBUSY;
	struct address_space *to_page_mapping, *from_page_mapping;
	struct buffer_head *to_head = NULL, *to_bh = NULL;

	VM_BUG_ON_PAGE(!PageLocked(from_page), from_page);
	VM_BUG_ON_PAGE(!PageLocked(to_page), to_page);

	/* copy page->mapping not use page_mapping()  */
	to_page_mapping = page_mapping(to_page);
	from_page_mapping = page_mapping(from_page);

	/* from_page has to be anonymous page  */
	BUG_ON(from_page_mapping);
	BUG_ON(PageWriteback(from_page));
	/* writeback has to finish */
	BUG_ON(PageWriteback(to_page));

	/* to_page is anonymous  */
	if (!to_page_mapping) {
exchange_mappings:
		/* actual page mapping exchange */
		rc = exchange_page_move_mapping(to_page_mapping, from_page_mapping,
							to_page, from_page, NULL, NULL, mode, 0, 0);
	} else {
		/* shmem */
		if (to_page_mapping->a_ops->migratepage == migrate_page)
			goto exchange_mappings;
		else if (to_page_mapping->a_ops->migratepage == buffer_migrate_page) {
			if (!page_has_buffers(to_page))
				goto exchange_mappings;

			to_head = page_buffers(to_page);

			rc = exchange_page_move_mapping(to_page_mapping,
					from_page_mapping, to_page, from_page,
					to_head, NULL, mode, 0, 0);

			if (rc != MIGRATEPAGE_SUCCESS)
				return rc;

			/*
			 * In the async case, migrate_page_move_mapping locked the buffers
			 * with an IRQ-safe spinlock held. In the sync case, the buffers
			 * need to be locked now
			 */
			if (mode != MIGRATE_ASYNC)
				BUG_ON(!buffer_migrate_lock_buffers(to_head, mode));

			ClearPagePrivate(to_page);
			set_page_private(from_page, page_private(to_page));
			set_page_private(to_page, 0);
			/* transfer private page count  */
			put_page(to_page);
			get_page(from_page);

			to_bh = to_head;
			do {
				set_bh_page(to_bh, from_page, bh_offset(to_bh));
				to_bh = to_bh->b_this_page;

			} while (to_bh != to_head);

			SetPagePrivate(from_page);

			to_bh = to_head;
		} else if (!to_page_mapping->a_ops->migratepage) {
			/* fallback_migrate_page  */
			if (PageDirty(to_page)) {
				if (mode != MIGRATE_SYNC)
					return -EBUSY;
				return writeout(to_page_mapping, to_page);
			}
			if (page_has_private(to_page) &&
				!try_to_release_page(to_page, GFP_KERNEL))
				return -EAGAIN;

			goto exchange_mappings;
		}
	}
	/* actual page data exchange  */
	if (rc != MIGRATEPAGE_SUCCESS)
		return rc;

	if (PageHuge(from_page) || PageTransHuge(from_page))
		exchange_huge_page(to_page, from_page);
	else
		exchange_highpage(to_page, from_page);

	/*
	 * 1. buffer_migrate_page:
	 *   private flag should be transferred from to_page to from_page
	 *
	 * 2. anon<->anon, fallback_migrate_page:
	 *   both have none private flags or to_page's is cleared.
	 * */
	VM_BUG_ON(!((page_has_private(from_page) && !page_has_private(to_page)) ||
				(!page_has_private(from_page) && !page_has_private(to_page))));

	exchange_page_flags(to_page, from_page);

	if (to_bh) {
		VM_BUG_ON(to_bh != to_head);
		do {
			unlock_buffer(to_bh);
			put_bh(to_bh);
			to_bh = to_bh->b_this_page;

		} while (to_bh != to_head);
	}

	return rc;
}

static int unmap_and_exchange(struct page *from_page,
		struct page *to_page, enum migrate_mode mode)
{
	int rc = -EAGAIN;
	struct anon_vma *from_anon_vma = NULL;
	struct anon_vma *to_anon_vma = NULL;
	/*bool is_from_lru = !__PageMovable(from_page);*/
	/*bool is_to_lru = !__PageMovable(to_page);*/
	int from_page_was_mapped = 0;
	int to_page_was_mapped = 0;
	int from_page_count = 0, to_page_count = 0;
	int from_map_count = 0, to_map_count = 0;
	unsigned long from_flags, to_flags;
	pgoff_t from_index, to_index;
	struct address_space *from_mapping, *to_mapping;

	if (!trylock_page(from_page)) {
		if (mode == MIGRATE_ASYNC)
			goto out;
		lock_page(from_page);
	}

	if (!trylock_page(to_page)) {
		if (mode == MIGRATE_ASYNC)
			goto out_unlock;
		lock_page(to_page);
	}

	/* from_page is supposed to be an anonymous page */
	VM_BUG_ON_PAGE(PageWriteback(from_page), from_page);

	if (PageWriteback(to_page)) {
		/*
		 * Only in the case of a full synchronous migration is it
		 * necessary to wait for PageWriteback. In the async case,
		 * the retry loop is too short and in the sync-light case,
		 * the overhead of stalling is too much
		 */
		if (mode != MIGRATE_SYNC) {
			rc = -EBUSY;
			goto out_unlock_both;
		}
		wait_on_page_writeback(to_page);
	}

	/*
	 * By try_to_unmap(), page->mapcount goes down to 0 here. In this case,
	 * we cannot notice that anon_vma is freed while we migrates a page.
	 * This get_anon_vma() delays freeing anon_vma pointer until the end
	 * of migration. File cache pages are no problem because of page_lock()
	 * File Caches may use write_page() or lock_page() in migration, then,
	 * just care Anon page here.
	 *
	 * Only page_get_anon_vma() understands the subtleties of
	 * getting a hold on an anon_vma from outside one of its mms.
	 * But if we cannot get anon_vma, then we won't need it anyway,
	 * because that implies that the anon page is no longer mapped
	 * (and cannot be remapped so long as we hold the page lock).
	 */
	if (PageAnon(from_page) && !PageKsm(from_page))
		from_anon_vma = page_get_anon_vma(from_page);

	if (PageAnon(to_page) && !PageKsm(to_page))
		to_anon_vma = page_get_anon_vma(to_page);

	/*if (unlikely(!is_from_lru)) {*/
		/*VM_BUG_ON_PAGE(1, from_page);*/
		/*goto out_unlock_both;*/
	/*}*/

	/*if (unlikely(!is_to_lru)) {*/
		/*pr_debug("exchange non-lru to_page\n");*/
		/*goto out_unlock_both;*/
	/*}*/

	from_page_count = page_count(from_page);
	from_map_count = page_mapcount(from_page);
	to_page_count = page_count(to_page);
	to_map_count = page_mapcount(to_page);
	from_flags = from_page->flags;
	to_flags = to_page->flags;
	from_mapping = from_page->mapping;
	to_mapping = to_page->mapping;
	from_index = from_page->index;
	to_index = to_page->index;
	/*
	 * Corner case handling:
	 * 1. When a new swap-cache page is read into, it is added to the LRU
	 * and treated as swapcache but it has no rmap yet.
	 * Calling try_to_unmap() against a page->mapping==NULL page will
	 * trigger a BUG.  So handle it here.
	 * 2. An orphaned page (see truncate_complete_page) might have
	 * fs-private metadata. The page can be picked up due to memory
	 * offlining.  Everywhere else except page reclaim, the page is
	 * invisible to the vm, so the page can not be migrated.  So try to
	 * free the metadata, so the page can be freed.
	 */
	if (!from_page->mapping) {
		VM_BUG_ON_PAGE(PageAnon(from_page), from_page);
		if (page_has_private(from_page)) {
			try_to_free_buffers(from_page);
			goto out_unlock_both;
		}
	} else if (page_mapped(from_page)) {
		/* Establish migration ptes */
		VM_BUG_ON_PAGE(PageAnon(from_page) && !PageKsm(from_page) &&
					   !from_anon_vma, from_page);
		try_to_unmap(from_page,
			TTU_MIGRATION|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
		from_page_was_mapped = 1;
	}

	if (!to_page->mapping) {
		VM_BUG_ON_PAGE(PageAnon(to_page), to_page);
		if (page_has_private(to_page)) {
			try_to_free_buffers(to_page);
			goto out_unlock_both_remove_from_migration_pte;
		}
	} else if (page_mapped(to_page)) {
		/* Establish migration ptes */
		VM_BUG_ON_PAGE(PageAnon(to_page) && !PageKsm(to_page) &&
						!to_anon_vma, to_page);
		try_to_unmap(to_page,
			TTU_MIGRATION|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
		to_page_was_mapped = 1;
	}

	if (!page_mapped(from_page) && !page_mapped(to_page)) {
		rc = exchange_from_to_pages(to_page, from_page, mode);
	}


	/* In remove_migration_ptes(), page_walk_vma() assumes
	 * from_page and to_page have the same index.
	 * Thus, we restore old_page->index here.
	 * Here to_page is the old_page.
	 */
	if (to_page_was_mapped) {
		if (rc == MIGRATEPAGE_SUCCESS)
			swap(to_page->index, to_index);

		remove_migration_ptes(to_page,
			rc == MIGRATEPAGE_SUCCESS ? from_page : to_page, false);

		if (rc == MIGRATEPAGE_SUCCESS)
			swap(to_page->index, to_index);
	}

out_unlock_both_remove_from_migration_pte:
	if (from_page_was_mapped) {
		if (rc == MIGRATEPAGE_SUCCESS)
			swap(from_page->index, from_index);

		remove_migration_ptes(from_page,
			rc == MIGRATEPAGE_SUCCESS ? to_page : from_page, false);

		if (rc == MIGRATEPAGE_SUCCESS)
			swap(from_page->index, from_index);
	}
out_unlock_both:
	if (to_anon_vma)
		put_anon_vma(to_anon_vma);
	unlock_page(to_page);
out_unlock:
	/* Drop an anon_vma reference if we took one */
	if (from_anon_vma)
		put_anon_vma(from_anon_vma);
	unlock_page(from_page);
out:
	return rc;
}

static bool can_be_exchanged(struct page *from, struct page *to)
{
	if (PageCompound(from) != PageCompound(to))
		return false;

	if (PageHuge(from) != PageHuge(to))
		return false;

	if (PageHuge(from) || PageHuge(to))
		return false;

	if (compound_order(from) != compound_order(to))
		return false;

	return true;
}

/*
 * Exchange pages in the exchange_list
 *
 * Caller should release the exchange_list resource.
 *
 * */
static int exchange_pages(struct list_head *exchange_list,
			enum migrate_mode mode,
			int reason)
{
	struct exchange_page_info *one_pair, *one_pair2;
	int failed = 0;

	list_for_each_entry_safe(one_pair, one_pair2, exchange_list, list) {
		struct page *from_page = one_pair->from_page;
		struct page *to_page = one_pair->to_page;
		int rc;
		int retry = 0;

again:
		if (page_count(from_page) == 1) {
			/* page was freed from under us. So we are done  */
			ClearPageActive(from_page);
			ClearPageUnevictable(from_page);

			mod_node_page_state(page_pgdat(from_page), NR_ISOLATED_ANON +
					page_is_file_cache(from_page),
					-hpage_nr_pages(from_page));
			put_page(from_page);

			if (page_count(to_page) == 1) {
				ClearPageActive(to_page);
				ClearPageUnevictable(to_page);
				put_page(to_page);
				mod_node_page_state(page_pgdat(to_page), NR_ISOLATED_ANON +
						page_is_file_cache(to_page),
						-hpage_nr_pages(to_page));
			} else
				goto putback_to_page;

			continue;
		}

		if (page_count(to_page) == 1) {
			/* page was freed from under us. So we are done  */
			ClearPageActive(to_page);
			ClearPageUnevictable(to_page);

			mod_node_page_state(page_pgdat(to_page), NR_ISOLATED_ANON +
					page_is_file_cache(to_page),
					-hpage_nr_pages(to_page));
			put_page(to_page);

			mod_node_page_state(page_pgdat(from_page), NR_ISOLATED_ANON +
					page_is_file_cache(from_page),
					-hpage_nr_pages(from_page));
			putback_lru_page(from_page);
			continue;
		}

		/* TODO: compound page not supported */
		if (!can_be_exchanged(from_page, to_page) ||
			page_mapping(from_page)
			/* allow to_page to be file-backed page  */
			/*|| page_mapping(to_page)*/
			) {
			++failed;
			goto putback;
		}

		rc = unmap_and_exchange(from_page, to_page, mode);

		if (rc == -EAGAIN && retry < 3) {
			++retry;
			goto again;
		}

		if (rc != MIGRATEPAGE_SUCCESS)
			++failed;

putback:
		mod_node_page_state(page_pgdat(from_page), NR_ISOLATED_ANON +
				page_is_file_cache(from_page),
				-hpage_nr_pages(from_page));

		putback_lru_page(from_page);
putback_to_page:
		/*if (!__PageMovable(to_page)) {*/
			mod_node_page_state(page_pgdat(to_page), NR_ISOLATED_ANON +
					page_is_file_cache(to_page),
					-hpage_nr_pages(to_page));

			putback_lru_page(to_page);
		/*} else {*/
			/*putback_movable_page(to_page);*/
		/*}*/

	}
	return failed;
}

int exchange_two_pages(struct page *page1, struct page *page2)
{
	struct exchange_page_info page_info;
	LIST_HEAD(exchange_list);
	int err = -EFAULT;
	int pagevec_flushed = 0;

	VM_BUG_ON_PAGE(PageTail(page1), page1);
	VM_BUG_ON_PAGE(PageTail(page2), page2);

	if (!(PageLRU(page1) && PageLRU(page2)))
		return -EBUSY;

retry_isolate1:
	if (!get_page_unless_zero(page1))
		return -EBUSY;
	err = isolate_lru_page(page1);
	put_page(page1);
	if (err) {
		if (!pagevec_flushed) {
			migrate_prep();
			pagevec_flushed = 1;
			goto retry_isolate1;
		}
		count_vm_event(MEM_DEFRAG_SRC_ANON_PAGES_FAILED);
		return err;
	}
	mod_node_page_state(page_pgdat(page1),
			NR_ISOLATED_ANON + page_is_file_cache(page1),
			hpage_nr_pages(page1));

retry_isolate2:
	if (!get_page_unless_zero(page2)) {
		putback_lru_page(page1);
		return -EBUSY;
	}
	err = isolate_lru_page(page2);
	put_page(page2);
	if (err) {
		if (!pagevec_flushed) {
			migrate_prep();
			pagevec_flushed = 1;
			goto retry_isolate2;
		}
		return err;
	}
	mod_node_page_state(page_pgdat(page2),
			NR_ISOLATED_ANON + page_is_file_cache(page2),
			hpage_nr_pages(page2));

	page_info.from_page = page1;
	page_info.to_page = page2;
	INIT_LIST_HEAD(&page_info.list);
	list_add(&page_info.list, &exchange_list);


	return exchange_pages(&exchange_list, MIGRATE_SYNC, 0);

}
