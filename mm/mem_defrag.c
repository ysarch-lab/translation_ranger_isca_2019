/*
 * Memory defragmentation.
 *
 * Two lists:
 *   1) a mm list, representing virtual address spaces
 *   2) a anon_vma list, representing the physical address space.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/mm_inline.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/hashtable.h>
#include <linux/mem_defrag.h>
#include <linux/shmem_fs.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/vmstat.h>
#include <linux/migrate.h>
#include <linux/page-isolation.h>
#include <linux/sort.h>

#include <asm/tlb.h>
#include <asm/pgalloc.h>
#include "internal.h"


struct contig_stats {
	int err;
	unsigned long contig_pages;
	unsigned long first_vaddr_in_chunk;
	unsigned long first_paddr_in_chunk;
};

struct defrag_result_stats {
	unsigned long aligned;
	unsigned long migrated;
	unsigned long src_compound_failed;
	unsigned long src_not_present;
	unsigned long dst_out_of_bound_failed;
	unsigned long dst_compound_failed;
	unsigned long dst_free_failed;
	unsigned long dst_anon_failed;
	unsigned long dst_file_failed;
	unsigned long dst_misc_failed;
	unsigned long not_defrag_vpn;
	unsigned int aligned_max_order;
};

enum {
	VMA_THRESHOLD_TYPE_TIME = 0,
	VMA_THRESHOLD_TYPE_SIZE,
};

int num_breakout_chunks = 0;
int vma_scan_percentile = 100;
int vma_scan_threshold_type = VMA_THRESHOLD_TYPE_TIME;
int vma_no_repeat_defrag = 0;
int kmem_defragd_always;
static DEFINE_SPINLOCK(kmem_defragd_mm_lock);

#define MM_SLOTS_HASH_BITS 10
static __read_mostly DEFINE_HASHTABLE(mm_slots_hash, MM_SLOTS_HASH_BITS);

static struct kmem_cache *mm_slot_cache __read_mostly;

struct defrag_scan_control {
	struct mm_struct *mm;
	unsigned long scan_address;
	char __user *out_buf;
	int buf_len;
	int used_len;
	enum mem_defrag_action action;
	bool scan_in_vma;
	unsigned long vma_scan_threshold;
};

/**
 * struct mm_slot - hash lookup from mm to mm_slot
 * @hash: hash collision list
 * @mm_node: kmem_defragd scan list headed in kmem_defragd_scan.mm_head
 * @mm: the mm that this information is valid for
 */
struct mm_slot {
	struct hlist_node hash;
	struct list_head mm_node;
	struct mm_struct *mm;
};

/**
 * struct kmem_defragd_scan - cursor for scanning
 * @mm_head: the head of the mm list to scan
 * @mm_slot: the current mm_slot we are scanning
 * @address: the next address inside that to be scanned
 *
 * There is only the one kmem_defragd_scan instance of this cursor structure.
 */
struct kmem_defragd_scan {
	struct list_head mm_head;
	struct mm_slot *mm_slot;
	unsigned long address;
};

static struct kmem_defragd_scan kmem_defragd_scan= {
	.mm_head = LIST_HEAD_INIT(kmem_defragd_scan.mm_head),
};


static inline struct mm_slot *alloc_mm_slot(void)
{
	if (!mm_slot_cache)	/* initialization failed */
		return NULL;
	return kmem_cache_zalloc(mm_slot_cache, GFP_KERNEL);
}

static inline void free_mm_slot(struct mm_slot *mm_slot)
{
	kmem_cache_free(mm_slot_cache, mm_slot);
}

static struct mm_slot *get_mm_slot(struct mm_struct *mm)
{
	struct mm_slot *mm_slot;

	hash_for_each_possible(mm_slots_hash, mm_slot, hash, (unsigned long)mm)
		if (mm == mm_slot->mm)
			return mm_slot;

	return NULL;
}

static void insert_to_mm_slots_hash(struct mm_struct *mm,
				    struct mm_slot *mm_slot)
{
	mm_slot->mm = mm;
	hash_add(mm_slots_hash, &mm_slot->hash, (long)mm);
}

static inline int kmem_defragd_test_exit(struct mm_struct *mm)
{
	return atomic_read(&mm->mm_users) == 0;
}

int __kmem_defragd_enter(struct mm_struct *mm)
{
	struct mm_slot *mm_slot;

	mm_slot = alloc_mm_slot();
	if (!mm_slot)
		return -ENOMEM;

	/* __kmem_defragd_exit() must not run from under us */
	VM_BUG_ON_MM(kmem_defragd_test_exit(mm), mm);
	if (unlikely(test_and_set_bit(MMF_VM_MEM_DEFRAG, &mm->flags))) {
		free_mm_slot(mm_slot);
		return 0;
	}

	spin_lock(&kmem_defragd_mm_lock);
	insert_to_mm_slots_hash(mm, mm_slot);
	/*
	 * Insert just behind the scanning cursor, to let the area settle
	 * down a little.
	 */
	list_add_tail(&mm_slot->mm_node, &kmem_defragd_scan.mm_head);
	spin_unlock(&kmem_defragd_mm_lock);

	atomic_inc(&mm->mm_count);

	return 0;
}

void __kmem_defragd_exit(struct mm_struct *mm)
{
	struct mm_slot *mm_slot;
	int free = 0;

	spin_lock(&kmem_defragd_mm_lock);
	mm_slot = get_mm_slot(mm);
	if (mm_slot && kmem_defragd_scan.mm_slot != mm_slot) {
		hash_del(&mm_slot->hash);
		list_del(&mm_slot->mm_node);
		free = 1;
	}
	spin_unlock(&kmem_defragd_mm_lock);

	if (free) {
		clear_bit(MMF_VM_MEM_DEFRAG, &mm->flags);
		free_mm_slot(mm_slot);
		mmdrop(mm);
	} else if (mm_slot) {
		/*
		 * This is required to serialize against
		 * kmem_defragd_test_exit() (which is guaranteed to run
		 * under mmap sem read mode). Stop here (after we
		 * return all pagetables will be destroyed) until
		 * kmem_defragd has finished working on the pagetables
		 * under the mmap_sem.
		 */
		down_write(&mm->mmap_sem);
		up_write(&mm->mmap_sem);
	}
}

static void collect_mm_slot(struct mm_slot *mm_slot)
{
	struct mm_struct *mm = mm_slot->mm;

	VM_BUG_ON(NR_CPUS != 1 && !spin_is_locked(&kmem_defragd_mm_lock));

	if (kmem_defragd_test_exit(mm)) {
		/* free mm_slot */
		hash_del(&mm_slot->hash);
		list_del(&mm_slot->mm_node);

		/*
		 * Not strictly needed because the mm exited already.
		 *
		 * clear_bit(MMF_VM_HUGEPAGE, &mm->flags);
		 */

		/* kmem_defragd_mm_lock actually not necessary for the below */
		free_mm_slot(mm_slot);
		mmdrop(mm);
	}
}

static bool mem_defrag_vma_check(struct vm_area_struct *vma)
{
	if ((!test_bit(MMF_VM_MEM_DEFRAG_ALL, &vma->vm_mm->flags) &&
		!(vma->vm_flags & VM_MEMDEFRAG) && !kmem_defragd_always) ||
		(vma->vm_flags & VM_NOMEMDEFRAG))
			return false;
	if (shmem_file(vma->vm_file)) {
		if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE))
			return false;
		return IS_ALIGNED((vma->vm_start >> PAGE_SHIFT) - vma->vm_pgoff,
				HPAGE_PMD_NR);
	}
	if (is_vm_hugetlb_page(vma))
		return true;
	if (!vma->anon_vma || vma->vm_ops)
		return false;
	if (is_vma_temporary_stack(vma))
		return false;
	return true;
}

static int do_vma_stat(struct mm_struct *mm, struct vm_area_struct *vma,
		char *kernel_buf, int pos, int* remain_buf_len)
{
	int used_len;
	int init_remain_len = *remain_buf_len;

	if (!*remain_buf_len || !kernel_buf)
		return -1;

	used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%p, 0x%lx, 0x%lx, "
						 "0x%lx, -1\n",
						 mm, (unsigned long)vma+vma->vma_create_jiffies, vma->vm_start, vma->vm_end);

	*remain_buf_len -= used_len;

	if (*remain_buf_len == 1) {
		*remain_buf_len = init_remain_len;
		kernel_buf[pos] = '\0';
		return -1;
	}

	return 0;
}

static inline int get_contig_page_size(struct page *page)
{
	int page_size = PAGE_SIZE;

	if (PageCompound(page)) {
		struct page *head_page = compound_head(page);
		int compound_size = PAGE_SIZE<<compound_order(head_page);

		if (head_page != page) {
			VM_BUG_ON_PAGE(!PageTail(page), page);
			page_size = compound_size - (page - head_page) * PAGE_SIZE;
		} else
			page_size = compound_size;
	}

	return page_size;
}

/*
 * write one page stats to kernel_buf.
 *
 * If kernel_buf is not big enough, the page information will not be recorded
 * at all.
 *
 *  */
static int do_page_stat(struct mm_struct *mm, struct vm_area_struct *vma,
		struct page *page, unsigned long vaddr,
		char *kernel_buf, int pos, int* remain_buf_len,
		enum mem_defrag_action action,
		struct contig_stats *contig_stats,
		bool scan_in_vma)
{
	int used_len;
	struct anon_vma *anon_vma;
	int init_remain_len = *remain_buf_len;
	int end_note = -1;
	unsigned long num_pages = page?(get_contig_page_size(page)/PAGE_SIZE):1;

	if (!*remain_buf_len || !kernel_buf)
		return -1;

	if (action == MEM_DEFRAG_CONTIG_STATS) {
		long long contig_pages;
		unsigned long paddr = page?PFN_PHYS(page_to_pfn(page)):0;
		bool last_entry = false;

		if (!contig_stats->first_vaddr_in_chunk) {
			contig_stats->first_vaddr_in_chunk = vaddr;
			contig_stats->first_paddr_in_chunk = paddr;
			contig_stats->contig_pages = 0;
		}

		/* scan_in_vma is set to true if buffer runs out while scanning a
		 * vma. A corner case happens, when buffer runs out, then vma changes,
		 * scan_address is reset to vm_start. Then, vma info is printed twice.
		 */
		if (vaddr == vma->vm_start && !scan_in_vma) {
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%p, 0x%lx, 0x%lx, "
								 "0x%lx, ",
								 mm, (unsigned long)vma+vma->vma_create_jiffies, vma->vm_start, vma->vm_end);

			*remain_buf_len -= used_len;

			if (*remain_buf_len == 1) {
				contig_stats->err = 1;
				goto out_of_buf;
			}
			pos += used_len;
		}

		if (page) {
			if (contig_stats->first_paddr_in_chunk) {
				if (((long long)vaddr - contig_stats->first_vaddr_in_chunk) ==
					((long long)paddr - contig_stats->first_paddr_in_chunk))
					contig_stats->contig_pages += num_pages;
				else {
					/* output present contig chunk */
					contig_pages = contig_stats->contig_pages;
					goto output_contig_info;
				}
			} else { /* the previous chunk is not present pages */
				/* output non-present contig chunk */
				contig_pages = -(long long)contig_stats->contig_pages;
				goto output_contig_info;
			}
		} else {
			/* the previous chunk is not present pages */
			if (!contig_stats->first_paddr_in_chunk) {
				VM_BUG_ON(contig_stats->first_vaddr_in_chunk +
						  contig_stats->contig_pages * PAGE_SIZE !=
						  vaddr);
				++contig_stats->contig_pages;
			} else {
				/* output present contig chunk */
				contig_pages = contig_stats->contig_pages;

				goto output_contig_info;
			}
		}

check_last_entry:
		/* if vaddr is the last page, we need to dump stats as well  */
		if ((vaddr + num_pages * PAGE_SIZE) < vma->vm_end)
			return 0;
		else {
			if (contig_stats->first_paddr_in_chunk)
				contig_pages = contig_stats->contig_pages;
			else
				contig_pages = -(long long)contig_stats->contig_pages;
			last_entry = true;
		}
output_contig_info:
		if (last_entry)
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%lld, -1\n",
								 contig_pages);
		else
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%lld, ",
								 contig_pages);

		*remain_buf_len -= used_len;
		if (*remain_buf_len == 1) {
			contig_stats->err = 1;
			goto out_of_buf;
		} else {
			pos += used_len;
			if (last_entry) {
				/* clear contig_stats  */
				contig_stats->first_vaddr_in_chunk = 0;
				contig_stats->first_paddr_in_chunk = 0;
				contig_stats->contig_pages = 0;
				return 0;
			} else {
				/* set new contig_stats  */
				contig_stats->first_vaddr_in_chunk = vaddr;
				contig_stats->first_paddr_in_chunk = paddr;
				contig_stats->contig_pages = num_pages;
				goto check_last_entry;
			}
		}
		return 0;
	}

	if (!list_empty(&vma->anchor_page_list)) {
		struct anchor_page_info *iter;

		list_for_each_entry(iter, &vma->anchor_page_list, list)
			if (vaddr >= iter->start && vaddr < iter->end &&
				page == iter->anchor_page) {
				end_note = -2;
				break;
			}
	}

	used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%p, %p, 0x%lx, 0x%lx, "
						 "0x%lx, 0x%llx",
						 mm, vma, vma->vm_start, vma->vm_end,
						 vaddr, page ? PFN_PHYS(page_to_pfn(page)) : 0);

	*remain_buf_len -= used_len;
	if (*remain_buf_len == 1)
		goto out_of_buf;
	pos += used_len;

	if (page && PageAnon(page)) {
		/* check page order  */
		used_len = scnprintf(kernel_buf + pos, *remain_buf_len, ", %d",
							 compound_order(page));
		*remain_buf_len -= used_len;
		if (*remain_buf_len == 1)
			goto out_of_buf;
		pos += used_len;

		anon_vma = page_anon_vma(page);
		if (!anon_vma)
			goto end_of_stat;
		anon_vma_lock_read(anon_vma);

		do {
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, ", %p",
								 anon_vma);
			*remain_buf_len -= used_len;
			if (*remain_buf_len == 1) {
				anon_vma_unlock_read(anon_vma);
				goto out_of_buf;
			}
			pos += used_len;

			anon_vma = anon_vma->parent;
		} while (anon_vma != anon_vma->parent);

		anon_vma_unlock_read(anon_vma);
	}
end_of_stat:
	/* end of one page stat  */
	used_len = scnprintf(kernel_buf + pos, *remain_buf_len, ", %d\n", end_note);
	*remain_buf_len -= used_len;
	if (*remain_buf_len == 1)
		goto out_of_buf;

	return 0;
out_of_buf: /* revert incomplete data  */
	*remain_buf_len = init_remain_len;
	kernel_buf[pos] = '\0';
	return -1;

}

static inline unsigned long get_page_offset(unsigned long addr1,
		unsigned long addr2, unsigned long alignment)
{
	unsigned long mask = alignment - 1;
	return (alignment + (addr1 & mask) - (addr2 & mask)) & mask;
}

static inline bool migrate_async_suitable(int migratetype)
{
	return is_migrate_cma(migratetype) || migratetype == MIGRATE_MOVABLE;
}

static int isolate_free_page_no_wmark(struct page *page, unsigned int order)
{
	struct zone *zone;
	int mt;

	BUG_ON(!PageBuddy(page));

	zone = page_zone(page);
	mt = get_pageblock_migratetype(page);


	/* Remove page from free list */
	list_del(&page->lru);
	zone->free_area[order].nr_free--;
	__ClearPageBuddy(page);
	set_page_private(page, 0);

	/*
	 * Set the pageblock if the isolated page is at least half of a
	 * pageblock
	 */
	if (order >= pageblock_order - 1) {
		struct page *endpage = page + (1 << order) - 1;
		for (; page < endpage; page += pageblock_nr_pages) {
			int mt = get_pageblock_migratetype(page);
			if (!is_migrate_isolate(mt) && !is_migrate_cma(mt)
				&& mt != MIGRATE_HIGHATOMIC)
				set_pageblock_migratetype(page,
							  MIGRATE_MOVABLE);
		}
	}

	return 1UL << order;
}

static void map_free_pages(struct list_head *list)
{
	unsigned int i, order, nr_pages;
	struct page *page, *next;
	LIST_HEAD(tmp_list);

	list_for_each_entry_safe(page, next, list, lru) {
		list_del(&page->lru);

		order = page_private(page);
		nr_pages = 1 << order;

		post_alloc_hook(page, order, __GFP_MOVABLE);
		if (order)
			split_page(page, order);

		for (i = 0; i < nr_pages; i++) {
			list_add_tail(&page->lru, &tmp_list);
			page++;
		}
	}

	list_splice(&tmp_list, list);
}

struct exchange_alloc_info {
	struct list_head list;
	struct page *src_page;
	struct page *dst_page;
};

struct exchange_alloc_head {
	struct list_head exchange_list;
	struct list_head freelist;
	struct list_head migratepage_list;
	unsigned long num_freepages;
};

static int create_exchange_alloc_info(struct vm_area_struct *vma,
		unsigned long scan_address, struct page *first_in_use_page,
		int total_free_pages,
		struct list_head *freelist,
		struct list_head *exchange_list,
		struct list_head *migratepage_list)
{
	struct page *in_use_page;
	struct page *freepage;
	struct exchange_alloc_info *one_pair;
	int err;
	int pagevec_flushed = 0;

	down_read(&vma->vm_mm->mmap_sem);
	in_use_page = follow_page(vma, scan_address,
							FOLL_GET|FOLL_MIGRATION | FOLL_REMOTE);
	up_read(&vma->vm_mm->mmap_sem);

	freepage = list_first_entry_or_null(freelist, struct page, lru);

	if (first_in_use_page != in_use_page ||
		!freepage ||
		PageCompound(in_use_page) != PageCompound(freepage) ||
		compound_order(in_use_page) != compound_order(freepage)) {
		if (in_use_page)
			put_page(in_use_page);
		return -EBUSY;
	}
	one_pair = kmalloc(sizeof(struct exchange_alloc_info),
		GFP_KERNEL | __GFP_ZERO);

	if (!one_pair) {
		put_page(in_use_page);
		return -ENOMEM;
	}

retry_isolate:
	/* isolate in_use_page */
	err = isolate_lru_page(in_use_page);
	if (err) {
		if (!pagevec_flushed) {
			migrate_prep();
			pagevec_flushed = 1;
			goto retry_isolate;
		}
		put_page(in_use_page);
		in_use_page = NULL;
	}

	if (in_use_page) {
		put_page(in_use_page);
		mod_node_page_state(page_pgdat(in_use_page),
				NR_ISOLATED_ANON + page_is_file_cache(in_use_page),
				hpage_nr_pages(in_use_page));
		list_add_tail(&in_use_page->lru, migratepage_list);
	}
	/* fill info  */
	one_pair->src_page = in_use_page;
	one_pair->dst_page = freepage;
	INIT_LIST_HEAD(&one_pair->list);

	list_add_tail(&one_pair->list, exchange_list);

	return 0;
}

static void free_alloc_info(struct list_head *alloc_info_list)
{
	struct exchange_alloc_info *item, *item2;

	list_for_each_entry_safe(item, item2, alloc_info_list, list) {
		list_del(&item->list);
		kfree(item);
	}
}

/*
 * migrate callback: give a specific free page when it is called to guarantee
 * contiguity after migration.
 */
static struct page *exchange_alloc(struct page *migratepage,
				unsigned long data,
				int **result)
{
	struct exchange_alloc_head *head = (struct exchange_alloc_head *)data;
	struct page *freepage = NULL;
	struct exchange_alloc_info *info;

	list_for_each_entry(info, &head->exchange_list, list) {
		if (migratepage == info->src_page) {
			freepage = info->dst_page;
			/* remove it from freelist */
			list_del(&freepage->lru);
			if (PageTransHuge(freepage))
				head->num_freepages -= HPAGE_PMD_NR;
			else
				head->num_freepages--;
			break;
		}
	}

	return freepage;
}

static void exchange_free(struct page *freepage, unsigned long data)
{
	struct exchange_alloc_head *head = (struct exchange_alloc_head *)data;

	list_add_tail(&freepage->lru, &head->freelist);
	if (PageTransHuge(freepage))
		head->num_freepages += HPAGE_PMD_NR;
	else
		head->num_freepages++;
}

int defrag_address_range(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long start_addr, unsigned long end_addr,
		struct page *anchor_page, unsigned long page_vaddr,
		struct defrag_result_stats *defrag_stats)
{
	/*unsigned long va_pa_page_offset = (unsigned long)-1;*/
	unsigned long scan_address;
	unsigned long page_size = PAGE_SIZE;
	int failed = 0;
	int not_present = 0;
	bool src_thp = false;

	for (scan_address = start_addr; scan_address < end_addr;
		 scan_address += page_size) {
		struct page *scan_page;
		unsigned long scan_phys_addr;
		long long page_dist;

		cond_resched();

		down_read(&vma->vm_mm->mmap_sem);
		scan_page = follow_page(vma, scan_address, FOLL_MIGRATION | FOLL_REMOTE);
		up_read(&vma->vm_mm->mmap_sem);
		scan_phys_addr = PFN_PHYS(scan_page ? page_to_pfn(scan_page) : 0);

		page_size = PAGE_SIZE;

		if (!scan_phys_addr) {
			not_present++;
			failed += 1;
			defrag_stats->src_not_present += 1;
			continue;
		}

		page_size = get_contig_page_size(scan_page);

		/* PTE-mapped THP not allowed  */
		if ((scan_page == compound_head(scan_page)) &&
			PageTransHuge(scan_page) && !PageHuge(scan_page))
			src_thp = true;

		/* Allow THPs  */
		if (PageCompound(scan_page) && !src_thp) {
			count_vm_events(MEM_DEFRAG_SRC_COMP_PAGES_FAILED, page_size/PAGE_SIZE);
			failed += (page_size/PAGE_SIZE);
			defrag_stats->src_compound_failed += (page_size/PAGE_SIZE);

			defrag_stats->not_defrag_vpn = scan_address + page_size;
			goto quit_defrag;
			continue;
		}

		VM_BUG_ON(!anchor_page);

		page_dist = (scan_address - page_vaddr) / PAGE_SIZE;

		/* already in the contiguous pos  */
		if (page_dist == (long long)(scan_page - anchor_page)) {
			defrag_stats->aligned += (page_size/PAGE_SIZE);
			defrag_stats->aligned_max_order = max(defrag_stats->aligned_max_order,
				compound_order(scan_page));
			continue;
		} else { /* migrate pages according to the anchor pages in the vma.  */
			struct page *dest_page = anchor_page + page_dist;
			int page_drained = 0;
			bool dst_thp = false;
			int scan_page_order = src_thp?compound_order(scan_page):0;

			if (zone_end_pfn(page_zone(anchor_page)) <= (page_to_pfn(anchor_page) + page_dist) ||
				page_zone(anchor_page)->zone_start_pfn > (page_to_pfn(anchor_page) + page_dist)) {
				failed += 1;
				defrag_stats->dst_out_of_bound_failed += 1;

				defrag_stats->not_defrag_vpn = scan_address + page_size;
				goto quit_defrag;
				continue;
			}

retry_defrag:
			/* migrate */
			if (PageBuddy(dest_page)) {
				struct zone *zone = page_zone(dest_page);
				spinlock_t *zone_lock = &zone->lock;
				unsigned long zone_lock_flags;
				unsigned long free_page_order = 0;
				int err = 0;
				struct exchange_alloc_head exchange_alloc_head = {0};
				int migratetype = get_pageblock_migratetype(dest_page);

				INIT_LIST_HEAD(&exchange_alloc_head.exchange_list);
				INIT_LIST_HEAD(&exchange_alloc_head.freelist);
				INIT_LIST_HEAD(&exchange_alloc_head.migratepage_list);

				count_vm_events(MEM_DEFRAG_DST_FREE_PAGES, 1<<scan_page_order);

				if (!migrate_async_suitable(migratetype)) {
					failed += 1;
					defrag_stats->dst_free_failed += 1;

					defrag_stats->not_defrag_vpn = scan_address + page_size;
					goto quit_defrag;
					continue;
				}

				/* lock page_zone(dest_page)->lock  */
				spin_lock_irqsave(zone_lock, zone_lock_flags);

				if (!PageBuddy(dest_page)) {
					err = -EINVAL;
					goto freepage_isolate_fail;
				}

				free_page_order = page_order(dest_page);

				/* fail early if not enough free pages */
				if (free_page_order < scan_page_order) {
					err = -ENOMEM;
					goto freepage_isolate_fail;
				}

				pr_debug("defrag: vma: %p, [0x%lx, 0x%lx): vaddr: 0x%lx to 0x%lx, origin page: 0x%lx, dest free page: 0x%lx, order: %lu\n",
					vma,
					start_addr,
					end_addr,
					scan_address,
					scan_address + page_size,
					page_to_pfn(scan_page),
					page_to_pfn(dest_page), free_page_order);

				/* __isolate_free_page()  */
				err = isolate_free_page_no_wmark(dest_page, free_page_order);
				if (!err)
					goto freepage_isolate_fail;

				expand(zone, dest_page, scan_page_order, free_page_order,
					&(zone->free_area[free_page_order]),
					migratetype);

				if (!is_migrate_isolate(migratetype))
					__mod_zone_freepage_state(zone, -(1UL << scan_page_order), migratetype);

				prep_new_page(dest_page, scan_page_order,
					__GFP_MOVABLE|(scan_page_order?__GFP_COMP:0), 0);

				if (scan_page_order) {
					VM_BUG_ON(!src_thp);
					VM_BUG_ON(scan_page_order != HPAGE_PMD_ORDER);
					prep_transhuge_page(dest_page);
				}

				list_add(&dest_page->lru, &exchange_alloc_head.freelist);

freepage_isolate_fail:
				spin_unlock_irqrestore(zone_lock, zone_lock_flags);

				if (err < 0) {
					failed += (page_size/PAGE_SIZE);
					defrag_stats->dst_free_failed += (page_size/PAGE_SIZE);

					defrag_stats->not_defrag_vpn = scan_address + page_size;
					goto quit_defrag;
					continue;
				}

				/* gather in-use pages
				 * create a exchange_alloc_info structure, a list of
				 * tuples, each like:
				 * (in_use_page, free_page)
				 *
				 * TODO: Maybe early fail if in_use_page cannot be migrated,
				 * like pinned.
				 *
				 * so in exchange_alloc, the code needs to traverse the list
				 * and find the tuple from in_use_page. Then return the
				 * corresponding free page.
				 *
				 * This can guarantee the contiguity after migration.
				 */

				err = create_exchange_alloc_info(vma, scan_address, scan_page,
							1<<free_page_order,
							&exchange_alloc_head.freelist,
							&exchange_alloc_head.exchange_list,
							&exchange_alloc_head.migratepage_list);

				if (err) {
					pr_debug("create_exchange_alloc_info error: %d\n", err);
				}
				exchange_alloc_head.num_freepages = 1<<scan_page_order;

				/* migrate pags  */
				err = migrate_pages(&exchange_alloc_head.migratepage_list,
					exchange_alloc, exchange_free,
					(unsigned long)&exchange_alloc_head,
					MIGRATE_SYNC, MR_COMPACTION);

				/* putback not migrated in_use_pagelist */
				putback_movable_pages(&exchange_alloc_head.migratepage_list);

				/* release free pages in freelist */
				release_freepages(&exchange_alloc_head.freelist);

				/* free allocated exchange info  */
				free_alloc_info(&exchange_alloc_head.exchange_list);

				count_vm_events(MEM_DEFRAG_DST_FREE_PAGES_FAILED,
						exchange_alloc_head.num_freepages);

				if (exchange_alloc_head.num_freepages) {
					pr_debug("exchange with free pages: total free pages: %lu, "
							 "remaining after exchange: %lu\n",
						1UL<<free_page_order, exchange_alloc_head.num_freepages);

					failed += exchange_alloc_head.num_freepages;
					defrag_stats->dst_free_failed += exchange_alloc_head.num_freepages;
				}
				defrag_stats->migrated += ((1UL<<scan_page_order) - exchange_alloc_head.num_freepages);

			} else { /* exchange  */
				int err = -EBUSY;

				/* PTE-mapped THP not allowed  */
				if ((dest_page == compound_head(dest_page)) &&
					PageTransHuge(dest_page) && !PageHuge(dest_page))
					dst_thp = true;

				if (PageCompound(dest_page) && !dst_thp) {
					failed += get_contig_page_size(dest_page);
					defrag_stats->dst_compound_failed += 1;

			defrag_stats->not_defrag_vpn = scan_address + page_size;
			goto quit_defrag;
					continue;
				}

				if (src_thp != dst_thp) {
					failed += get_contig_page_size(scan_page);
					defrag_stats->src_compound_failed += 1;

			defrag_stats->not_defrag_vpn = scan_address + page_size;
			goto quit_defrag;
					continue;
				}

				pr_debug("defrag: vma: %p, [0x%lx, 0x%lx]: vaddr: 0x%lx, origin page: 0x%lx, page in use: 0x%lx,"
					"count: %d, mapcount: %d, mapping: %p, index: %#lx, flags: %#lx(%pGp), %s, order: %d"
					"\n",
					vma,
					start_addr,
					end_addr,
					scan_address,
					page_to_pfn(scan_page),
					page_to_pfn(dest_page),
					page_ref_count(dest_page),
					PageSlab(dest_page)?0:page_mapcount(dest_page),
					dest_page->mapping, page_to_pgoff(dest_page),
					dest_page->flags, &dest_page->flags,
					PageCompound(dest_page)?"compound_page":"single_page",
					compound_order(dest_page)
					);

				/* free page on pcplist */
				if (page_count(dest_page) == 0){
					/* not managed pages  */
					if (!dest_page->flags) {
						failed += 1;
						defrag_stats->dst_misc_failed += 1;

			defrag_stats->not_defrag_vpn = scan_address + page_size;
			goto quit_defrag;
						continue;
					}
					/* spill order-0 pages to buddy allocator from pcplist */
					if (!page_drained) {
						drain_all_pages(NULL);
						page_drained = 1;
						goto retry_defrag;
					}
				}

				if (PageAnon(dest_page)) {
					count_vm_events(MEM_DEFRAG_DST_ANON_PAGES, 1<<scan_page_order);

					if (src_thp && dst_thp)
						pr_debug("anonymous THP page exchange\n");

					err = exchange_two_pages(scan_page, dest_page);
					pr_debug("anonymous page exchange\n");
					if (err) {
						count_vm_events(MEM_DEFRAG_DST_ANON_PAGES_FAILED, 1<<scan_page_order);
						failed += 1<<scan_page_order;
						defrag_stats->dst_anon_failed += 1<<scan_page_order;
					}
				} else if (page_mapping(dest_page)) {
					count_vm_events(MEM_DEFRAG_DST_FILE_PAGES, 1<<scan_page_order);

					err = exchange_two_pages(scan_page, dest_page);
					pr_debug("file-backed page exchange\n");
					if (err) {
						count_vm_events(MEM_DEFRAG_DST_FILE_PAGES_FAILED, 1<<scan_page_order);
						failed += 1<<scan_page_order;
						defrag_stats->dst_file_failed += 1<<scan_page_order;
					}
				} else if (!PageLRU(dest_page) && __PageMovable(dest_page)) {
					failed += 1<<scan_page_order;
					defrag_stats->dst_misc_failed += 1<<scan_page_order;
					pr_debug("non-lru movable page exchange\n");
				} else {
					failed += 1<<scan_page_order;
					/* unmovable pages  */
					defrag_stats->dst_misc_failed += 1<<scan_page_order;
					pr_debug("unmovable pages exchange\n");
				}
				pr_debug("exchange result: %d\n", err);

				if (err == -EAGAIN)
					goto retry_defrag;
				if (!err)
					defrag_stats->migrated += 1<<scan_page_order;
				else {

			defrag_stats->not_defrag_vpn = scan_address + page_size;
			goto quit_defrag;
				}

			}
		}

	}
quit_defrag:
	return failed;
}

void dump_anchor_info(struct vm_area_struct *vma, unsigned long scan_address)
{
	struct interval_tree_node *iter;

	pr_info("addr: %lx in vma [%lx, %lx)\n", scan_address, vma->vm_start, vma->vm_end);

	for (iter = interval_tree_iter_first(&vma->anchor_page_rb, vma->vm_start, vma->vm_end);
		 iter;
		 iter = interval_tree_iter_next(iter, vma->vm_start, vma->vm_end)) {

		struct anchor_page_node *info = container_of(iter, struct anchor_page_node, node);

		pr_info("anchor (vpn: %lx, pfn: %lx): range [%lx, %lx]\n",
				info->anchor_vpn, info->anchor_pfn,
				iter->start, iter->last);
	}
}

struct anchor_page_node *get_anchor_page_node_from_vma(struct vm_area_struct *vma,
	unsigned long address)
{
	struct interval_tree_node *prev_vma_node;

	prev_vma_node = interval_tree_iter_first(&vma->anchor_page_rb,
		address, address);

	if (!prev_vma_node)
		return NULL;

	return container_of(prev_vma_node, struct anchor_page_node, node);
}

unsigned long get_aligned_pfn(unsigned long vpn, unsigned long lower_pfn,
		unsigned long offset_mask)
{
	unsigned long aligned_mask = ~offset_mask;
	unsigned long vpn_offset = vpn & offset_mask;
	unsigned long pfn_offset = lower_pfn & offset_mask;

	if (vpn_offset >= pfn_offset)
		return (lower_pfn & aligned_mask) | vpn_offset;

	return ((lower_pfn + offset_mask + 1) & aligned_mask) | vpn_offset;
}

/*
 * anchor pages decide the va pa offset in each vma
 *
 */
static int find_anchor_pages_in_vma(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long start_addr)
{
	struct anchor_page_node *anchor_node;
	struct page *anchor_page = NULL;
	unsigned long scan_address = start_addr;
	unsigned long end_addr = vma->vm_end - PAGE_SIZE;
	struct interval_tree_node *existing_anchor = NULL;
	unsigned long existing_anchor_pfn = 0;
	unsigned long new_anchor_vpn = 0;
	unsigned long new_anchor_pfn = 0;

	/* Out of range query  */
	if (start_addr >= vma->vm_end || start_addr < vma->vm_start)
		return -1;

	/*
	 * Clean up unrelated anchor infor
	 *
	 * VMA range can change and leave some anchor info out of range,
	 * so clean it here.
	 * It should be cleaned when vma is changed, but the code there
	 * is too complicated.
	 */
	if (!RB_EMPTY_ROOT(&vma->anchor_page_rb.rb_root) &&
		!interval_tree_iter_first(&vma->anchor_page_rb,
		 vma->vm_start, vma->vm_end - PAGE_SIZE)) {
		struct interval_tree_node *node = NULL;

		for (node = interval_tree_iter_first(&vma->anchor_page_rb,
				0, (unsigned long)-1);
			 node;) {
			struct anchor_page_node *anchor_node = container_of(node,
					struct anchor_page_node, node);
			interval_tree_remove(node, &vma->anchor_page_rb);
			node = interval_tree_iter_next(node, 0, (unsigned long)-1);
			kfree(anchor_node);
		}

		pr_debug("Clean up anchor info. Because all are out of vma range\n");
	}

	/* no range at all  */
	if (RB_EMPTY_ROOT(&vma->anchor_page_rb.rb_root))
		goto insert_new_range;

	/* look for first range has start_addr or after it */
	existing_anchor = interval_tree_iter_first(&vma->anchor_page_rb,
		start_addr, end_addr);

	/* first range has start_addr or after it  */
	if (existing_anchor) {
		/* redundant range, do nothing */
		if (existing_anchor->start == start_addr)
			return 0;
		else if (existing_anchor->start < start_addr &&
				 existing_anchor->last >= start_addr){
			struct anchor_page_node *existing_node = container_of(existing_anchor,
				struct anchor_page_node, node);
			existing_anchor_pfn = existing_node->anchor_pfn;

			pr_debug("Cut existing anchor: range: [%lx, %lx], anchor: vpn: %lx, pfn: %lx\n",
				existing_anchor->start, existing_anchor->last,
				existing_node->anchor_vpn, existing_node->anchor_pfn);
			/* cut existing range, because some not movable pages  */
			interval_tree_remove(existing_anchor, &vma->anchor_page_rb);
			existing_anchor->last = start_addr - PAGE_SIZE;
			interval_tree_insert(existing_anchor, &vma->anchor_page_rb);
			/*  add a new range [start_addr, vm_end] */
			end_addr = vma->vm_end - PAGE_SIZE;
			goto insert_new_range;
		} else { /* a range after start_addr  */
			VM_BUG_ON(!(existing_anchor->start > start_addr));
			/* expand existing range forward  */
			interval_tree_remove(existing_anchor, &vma->anchor_page_rb);
			existing_anchor->start = start_addr;
			interval_tree_insert(existing_anchor, &vma->anchor_page_rb);

			goto out;
		}
	} else {
		struct interval_tree_node *prev_anchor = NULL, *cur_anchor;
		/* there is a range before start_addr  */

		/* find the range just before start_addr  */
		for (cur_anchor = interval_tree_iter_first(&vma->anchor_page_rb,
				vma->vm_start, start_addr - PAGE_SIZE);
			 cur_anchor;
			 prev_anchor = cur_anchor,
			 cur_anchor = interval_tree_iter_next(cur_anchor,
				vma->vm_start, start_addr - PAGE_SIZE));

		if (!prev_anchor) {
			dump_anchor_info(vma, start_addr);
			VM_BUG_ON(1);
		}

		interval_tree_remove(prev_anchor, &vma->anchor_page_rb);
		prev_anchor->last = vma->vm_end;
		interval_tree_insert(prev_anchor, &vma->anchor_page_rb);

		goto out;
	}

insert_new_range: /* start_addr to end_addr  */
	anchor_node =
			kmalloc(sizeof(struct anchor_page_node), GFP_KERNEL | __GFP_ZERO);
	if (!anchor_node)
		return -ENOMEM;

	anchor_node->node.start = start_addr;
	anchor_node->node.last = end_addr;

	/* use first available page  */
	while (!anchor_page && scan_address < end_addr) {
		down_read(&vma->vm_mm->mmap_sem);
		anchor_page = follow_page(vma, scan_address,
			FOLL_MIGRATION | FOLL_REMOTE);
		up_read(&vma->vm_mm->mmap_sem);
		scan_address += anchor_page?get_contig_page_size(anchor_page):PAGE_SIZE;

		if (anchor_page) {
			new_anchor_vpn = (scan_address - get_contig_page_size(anchor_page))>>PAGE_SHIFT;
			new_anchor_pfn = page_to_pfn(anchor_page);

			new_anchor_vpn &= (PMD_MASK>>PAGE_SHIFT);
			new_anchor_pfn &= (PMD_MASK>>PAGE_SHIFT);

			if (existing_anchor_pfn &&
				existing_anchor_pfn == new_anchor_pfn) {
				anchor_page = NULL;
				continue;
			}
		}
	}

	if (!anchor_page) {
		kfree(anchor_node);
		goto out;
	}

	anchor_node->anchor_vpn = new_anchor_vpn;
	anchor_node->anchor_pfn = new_anchor_pfn;

	interval_tree_insert(&anchor_node->node, &vma->anchor_page_rb);

	pr_debug("Add new node: vma: %p, [%lx, %lx], vpn: %lx, pfn: %lx",
			vma, anchor_node->node.start, anchor_node->node.last,
			anchor_node->anchor_vpn, anchor_node->anchor_pfn);

out:
	return 0;
}

static inline bool is_stats_collection(enum mem_defrag_action action)
{
	switch (action) {
		case MEM_DEFRAG_FULL_STATS:
		case MEM_DEFRAG_CONTIG_STATS:
			return true;
		default:
			return false;
	}
	return false;
}

static int unsigned_long_cmp(const void *a, const void *b)
{
	const unsigned long *l = a, *r = b;
	if (*l < *r)
		return -1;
	if (*l > *r)
		return 1;
	return 0;
}

/* must hold mmap_sem read  */
static void scan_all_vma_lifetime(struct defrag_scan_control *sc)
{
	struct mm_struct *mm = sc->mm;
	struct vm_area_struct *vma = NULL;
	unsigned long current_jiffies = jiffies; /* fix one jiffies  */
	unsigned int num_vma = 0, index = 0;
	unsigned long *vma_scan_list = NULL;

	for (vma = find_vma(mm, 0); vma; vma = vma->vm_next)
		/* only care about to-be-defragged vmas  */
		if (mem_defrag_vma_check(vma))
			++num_vma;

	vma_scan_list = kmalloc(num_vma*sizeof(unsigned long),
			GFP_KERNEL | __GFP_ZERO);

	if (ZERO_OR_NULL_PTR(vma_scan_list)) {
		sc->vma_scan_threshold = 1;
		return;
	}

	for (vma = find_vma(mm, 0); vma; vma = vma->vm_next)
		/* only care about to-be-defragged vmas  */
		if (mem_defrag_vma_check(vma)) {
			if (vma_scan_threshold_type == VMA_THRESHOLD_TYPE_TIME)
				vma_scan_list[index] = current_jiffies - vma->vma_create_jiffies;
			else if (vma_scan_threshold_type == VMA_THRESHOLD_TYPE_SIZE)
				vma_scan_list[index] = vma->vm_end - vma->vm_start;
			++index;
			if (index >=num_vma)
				break;
		}

	/* since we do not hold mmap_sem here */
	if (index != num_vma) {
		pr_info("index: %d, num_vma: %d\n", index, num_vma);
		if (index < num_vma)
			num_vma = index;
	}

	sort(vma_scan_list, num_vma, sizeof(unsigned long),
		 unsigned_long_cmp, NULL);

	/* 50 percentile  */
	index = (100 - vma_scan_percentile) * num_vma / 100;

	sc->vma_scan_threshold = vma_scan_list[index];

	kfree(vma_scan_list);
}

/*
 * Scan single mm_struct.
 * The function will down_read mmap_sem.
 *
 */
static int kmem_defragd_scan_mm(struct defrag_scan_control *sc)
{
	struct mm_struct *mm = sc->mm;
	struct vm_area_struct *vma = NULL;
	unsigned long *scan_address = &sc->scan_address;
	char *stats_buf = NULL;
	int remain_buf_len = sc->buf_len;
	int err = 0;
	struct contig_stats contig_stats;


	if (sc->out_buf &&
		sc->buf_len) {
		stats_buf = vzalloc(sc->buf_len);
		if (!stats_buf)
			goto breakouterloop;
	}

	/*down_read(&mm->mmap_sem);*/
	if (unlikely(kmem_defragd_test_exit(mm)))
		vma = NULL;
	else {
		/* get vma_scan_threshold  */
		if (!sc->vma_scan_threshold)
			scan_all_vma_lifetime(sc);

		vma = find_vma(mm, *scan_address);
	}

	for (; vma; vma = vma->vm_next) {
		unsigned long vstart, vend;
		struct anchor_page_node *anchor_node = NULL;
		int scanned_chunks = 0;


		if (unlikely(kmem_defragd_test_exit(mm)))
			break;
		if (!mem_defrag_vma_check(vma)) {
			if (is_stats_collection(sc->action))
				if (do_vma_stat(mm, vma, stats_buf, sc->buf_len - remain_buf_len,
							&remain_buf_len))
					goto breakouterloop;
			*scan_address = vma->vm_end;
			goto done_one_vma;
		}


		vstart = vma->vm_start;
		vend = vma->vm_end;
		if (vstart >= vend)
			goto done_one_vma;
		if (*scan_address > vend)
			goto done_one_vma;
		if (*scan_address < vstart)
			*scan_address = vstart;

		if (sc->action == MEM_DEFRAG_DO_DEFRAG) {
			if (vma_scan_threshold_type == VMA_THRESHOLD_TYPE_TIME) {
				if ((jiffies - vma->vma_create_jiffies) < sc->vma_scan_threshold)
					goto done_one_vma;
			} else if (vma_scan_threshold_type == VMA_THRESHOLD_TYPE_SIZE) {
				if ((vma->vm_end - vma->vm_start) < sc->vma_scan_threshold)
					goto done_one_vma;
			}
			if (vma_no_repeat_defrag &&
				vma->vma_defrag_jiffies > vma->vma_modify_jiffies)
				goto done_one_vma;

			if (remain_buf_len && stats_buf) {
				int used_len;
				int pos = sc->buf_len -remain_buf_len;

				used_len = scnprintf(stats_buf + pos, remain_buf_len, "vma: 0x%lx, 0x%lx, "
									 "0x%lx, -1\n",
									 (unsigned long)vma+vma->vma_create_jiffies, vma->vm_start, vma->vm_end);

				remain_buf_len -= used_len;

				if (remain_buf_len == 1) {
					stats_buf[pos] = '\0';
					remain_buf_len = 0;
				}
			}
			anchor_node = get_anchor_page_node_from_vma(vma, vma->vm_start);

			if (!anchor_node) {
				find_anchor_pages_in_vma(mm, vma, vma->vm_start);
				anchor_node = get_anchor_page_node_from_vma(vma, vma->vm_start);

				if (!anchor_node)
					goto done_one_vma;
			}
		}

		contig_stats = (struct contig_stats) {0};

		while (*scan_address < vend) {
			/*int ret = 1;*/
			struct page *page;
			/*struct anchor_page_info *anchor_page_info = NULL;*/

			cond_resched();
			if (unlikely(kmem_defragd_test_exit(mm)))
				goto breakouterloop;

			if (is_stats_collection(sc->action)) {
				down_read(&vma->vm_mm->mmap_sem);
				page = follow_page(vma, *scan_address,
						FOLL_MIGRATION | FOLL_REMOTE);
				up_read(&vma->vm_mm->mmap_sem);

				if (do_page_stat(mm, vma, page, *scan_address,
							stats_buf, sc->buf_len - remain_buf_len,
							&remain_buf_len, sc->action, &contig_stats,
							sc->scan_in_vma)) {
					/* reset scan_address to the beginning of the contig.
					 * So next scan will get the whole contig.
					 */
					if (contig_stats.err) {
						*scan_address = contig_stats.first_vaddr_in_chunk;
						sc->scan_in_vma = true;
					}
					goto breakouterloop;
				}
				/* move to next address */
				if (page)
					*scan_address += get_contig_page_size(page);
				else
					*scan_address += PAGE_SIZE;
			} else if (sc->action == MEM_DEFRAG_DO_DEFRAG) {
				/* go to nearest 2MB aligned address  */
				unsigned long defrag_end = min_t(unsigned long,
							(*scan_address + HPAGE_PMD_SIZE) & HPAGE_PMD_MASK,
							vend);
				int defrag_result;
				/*bool found_anchor_page;*/
				struct defrag_result_stats defrag_stats = {0};

continue_defrag:
				anchor_node = get_anchor_page_node_from_vma(vma, *scan_address);

				/*  in case VMA size changes */
				if (!anchor_node) {
					find_anchor_pages_in_vma(mm, vma, *scan_address);
					anchor_node = get_anchor_page_node_from_vma(vma, *scan_address);
				}

				if (!anchor_node) {
					goto done_one_vma;
					dump_anchor_info(vma, *scan_address);
					VM_BUG_ON(1);
				}

				defrag_result = defrag_address_range(mm, vma, *scan_address,
					defrag_end,
					pfn_to_page(anchor_node->anchor_pfn), anchor_node->anchor_vpn<<PAGE_SHIFT,
					&defrag_stats);

				if (remain_buf_len && stats_buf) {
					int used_len;
					int pos = sc->buf_len -remain_buf_len;

					/*
					 * aligned, migrated,
					 * src_compound_failed,
					 * dst_out_of_bound_failed,
					 * dst_compound_failed, dst_free_failed,
					 * dst_anon_failed, dst_file_failed,
					 * dst_misc_failed;
					 */
					used_len = scnprintf(stats_buf + pos, remain_buf_len,
						"[0x%lx, 0x%lx):%lu [alig:%lu, migrated:%lu, src: not:%lu, com:%lu, dst: bound:%lu, com:%lu, free:%lu, anon:%lu, file:%lu, misc:%lu], "
						"anchor: (%lx, %lx), range: [%lx, %lx], vma: 0x%lx, not_defrag_vpn: %lx\n",
						*scan_address, defrag_end,
						(defrag_end - *scan_address)/PAGE_SIZE,
						defrag_stats.aligned,
						defrag_stats.migrated,
						defrag_stats.src_not_present,
						defrag_stats.src_compound_failed,
						defrag_stats.dst_out_of_bound_failed,
						defrag_stats.dst_compound_failed,
						defrag_stats.dst_free_failed,
						defrag_stats.dst_anon_failed,
						defrag_stats.dst_file_failed,
						defrag_stats.dst_misc_failed,
						anchor_node->anchor_vpn,
						anchor_node->anchor_pfn,
						anchor_node->node.start,
						anchor_node->node.last,
						(unsigned long)vma+vma->vma_create_jiffies,
						defrag_stats.not_defrag_vpn
						);

					remain_buf_len -= used_len;

					if (remain_buf_len == 1) {
						stats_buf[pos] = '\0';
						remain_buf_len = 0;
					}
				}

				if (defrag_stats.not_defrag_vpn) {
					VM_BUG_ON(defrag_end != vend && defrag_stats.not_defrag_vpn > defrag_end);
					find_anchor_pages_in_vma(mm, vma, defrag_stats.not_defrag_vpn);

					if (defrag_stats.not_defrag_vpn < defrag_end) {
						/* reset and continue  */
						*scan_address = defrag_stats.not_defrag_vpn;
						defrag_stats.not_defrag_vpn = 0;
						goto continue_defrag;
					}
				}

				/* defrag works for the whole chunk, promote to THP in place */
				if (!defrag_result &&
					defrag_stats.aligned_max_order < HPAGE_PMD_ORDER && /* avoid existing THP */
					!(*scan_address & (HPAGE_PMD_SIZE-1)) &&
					!(defrag_end & (HPAGE_PMD_SIZE-1))) {
					int ret = 0;
					pr_debug("find a range to promote: [%lx, %lx)\n", *scan_address, defrag_end);
					down_write(&mm->mmap_sem);
					if (!(ret = promote_huge_page_address(vma, *scan_address))) {
						pr_debug("promote huge page successful!\n");
						if (!(ret = promote_huge_pmd_address(vma, *scan_address)))
							pr_debug("2MB THP created!\n");
					}
					up_write(&mm->mmap_sem);
				}

				*scan_address = defrag_end;
				scanned_chunks++;
				if (num_breakout_chunks && scanned_chunks >= num_breakout_chunks) {
					scanned_chunks = 0;
					goto breakouterloop;
				}
			}
		}
done_one_vma:
		sc->scan_in_vma = false;
		if (sc->action == MEM_DEFRAG_DO_DEFRAG)
			vma->vma_defrag_jiffies = jiffies;
	}
breakouterloop:

	if (sc->out_buf &&
		sc->buf_len) {
		err = copy_to_user(sc->out_buf, stats_buf,
				sc->buf_len - remain_buf_len);
		sc->used_len = sc->buf_len - remain_buf_len;
	}

	if (stats_buf)
		vfree(stats_buf);

	/* 0: scan complete, 1: scan_incomplete  */
	return vma == NULL ? 0 : 1;
}

SYSCALL_DEFINE4(scan_process_memory, pid_t, pid, char __user *, out_buf,
				int, buf_len, int, action)
{
	const struct cred *cred = current_cred(), *tcred;
	struct task_struct *task;
	struct mm_struct *mm;
	int err = 0;
	static struct defrag_scan_control defrag_scan_control = {0};
	struct mm_slot *iter;

	if (action == MEM_DEFRAG_PAGEBLOCK_SCAN) {
		if (pid >= 0 && pid < MAX_NUMNODES && node_online(pid))
			err = pageblock_scan_node(pid, out_buf, buf_len);
		else
			err = -EINVAL;
		return err;
	}

	if (action == MEM_DEFRAG_FLUSH_TLB) {
		unsigned long addr = (unsigned long)out_buf;
		if (pid != 0)
			err = -EINVAL;
		__flush_tlb_one_user(addr);
		return err;
	}

	/* Find the mm_struct */
	rcu_read_lock();
	task = pid ? find_task_by_vpid(pid) : current;
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);

	/*
	 * Check if this process has the right to modify the specified
	 * process. The right exists if the process has administrative
	 * capabilities, superuser privileges or the same
	 * userid as the target process.
	 */
	tcred = __task_cred(task);
	if (!uid_eq(cred->euid, tcred->suid) && !uid_eq(cred->euid, tcred->uid) &&
	    !uid_eq(cred->uid,  tcred->suid) && !uid_eq(cred->uid,  tcred->uid) &&
	    !capable(CAP_SYS_NICE)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out;
	}
	rcu_read_unlock();

	err = security_task_movememory(task);
	if (err)
		goto out;

	mm = get_task_mm(task);
	put_task_struct(task);

	if (!mm)
		return -EINVAL;

	switch (action) {
		case MEM_DEFRAG_SCAN:
		case MEM_DEFRAG_CONTIG_SCAN:
			count_vm_event(MEM_DEFRAG_SCAN_NUM);
			/* reset scan control  */
			if (!defrag_scan_control.mm ||
				defrag_scan_control.mm != mm) {
				defrag_scan_control = (struct defrag_scan_control){0};
				defrag_scan_control.mm = mm;
			}
			defrag_scan_control.out_buf = out_buf;
			defrag_scan_control.buf_len = buf_len;
			if (action == MEM_DEFRAG_SCAN)
				defrag_scan_control.action = MEM_DEFRAG_FULL_STATS;
			else if (action == MEM_DEFRAG_CONTIG_SCAN)
				defrag_scan_control.action = MEM_DEFRAG_CONTIG_STATS;
			else {
				err = -EINVAL;
				break;
			}

			defrag_scan_control.used_len = 0;

			if (unlikely(!access_ok(VERIFY_WRITE, out_buf, buf_len))) {
				err = -EFAULT;
				break;
			}

			/* clear mm once it is fully scanned  */
			if (!kmem_defragd_scan_mm(&defrag_scan_control) &&
				!defrag_scan_control.used_len)
				defrag_scan_control.mm = NULL;

			err = defrag_scan_control.used_len;
			break;
		case MEM_DEFRAG_MARK_SCAN_ALL:
			set_bit(MMF_VM_MEM_DEFRAG_ALL, &mm->flags);
			__kmem_defragd_enter(mm);
			break;
		case MEM_DEFRAG_CLEAR_SCAN_ALL:
			clear_bit(MMF_VM_MEM_DEFRAG_ALL, &mm->flags);
			break;
		case MEM_DEFRAG_DEFRAG:
			count_vm_event(MEM_DEFRAG_DEFRAG_NUM);

			if (!defrag_scan_control.mm ||
				defrag_scan_control.mm != mm) {
				defrag_scan_control = (struct defrag_scan_control){0};
				defrag_scan_control.mm = mm;
			}
			defrag_scan_control.action = MEM_DEFRAG_DO_DEFRAG;

			defrag_scan_control.out_buf = out_buf;
			defrag_scan_control.buf_len = buf_len;

			/* clear mm once it is fully defragged */
			if (buf_len) {
				if (!kmem_defragd_scan_mm(&defrag_scan_control) &&
					!defrag_scan_control.used_len) {
					defrag_scan_control.mm = NULL;
				}
				err = defrag_scan_control.used_len;
			} else {
				if ((err = kmem_defragd_scan_mm(&defrag_scan_control)) == 0)
					defrag_scan_control.mm = NULL;
			}
			break;
		case MEM_DEFRAG_THP_COMPACT:
			khugepaged_scan_mm(mm);
			break;
		default:
			err = -EINVAL;
			break;
	}

	list_for_each_entry(iter, &kmem_defragd_scan.mm_head, mm_node) {
		struct task_struct *mm_task = iter->mm->owner;
		pr_debug("mm_struct: 0x%p is in the list for pid: %d, tpid: %d\n",
			iter->mm,
			mm_task?mm_task->pid: -1,
			mm_task?mm_task->tgid: -1);
	}

	mmput(mm);
	return err;

out:
	put_task_struct(task);
	return err;
}

static unsigned int kmem_defragd_scan_mm_slot(void)
{
	struct mm_slot *mm_slot;
	int scan_status = 0;
	struct defrag_scan_control defrag_scan_control = {0};

	spin_lock(&kmem_defragd_mm_lock);
	if (kmem_defragd_scan.mm_slot)
		mm_slot = kmem_defragd_scan.mm_slot;
	else {
		mm_slot = list_entry(kmem_defragd_scan.mm_head.next,
				     struct mm_slot, mm_node);
		kmem_defragd_scan.address = 0;
		kmem_defragd_scan.mm_slot = mm_slot;
	}
	spin_unlock(&kmem_defragd_mm_lock);

	defrag_scan_control.mm = mm_slot->mm;
	defrag_scan_control.scan_address = kmem_defragd_scan.address;
	defrag_scan_control.action = MEM_DEFRAG_DO_DEFRAG;

	scan_status = kmem_defragd_scan_mm(&defrag_scan_control);

	kmem_defragd_scan.address = defrag_scan_control.scan_address;

	spin_lock(&kmem_defragd_mm_lock);
	VM_BUG_ON(kmem_defragd_scan.mm_slot != mm_slot);
	/*
	 * Release the current mm_slot if this mm is about to die, or
	 * if we scanned all vmas of this mm.
	 */
	if (kmem_defragd_test_exit(mm_slot->mm) || !scan_status) {
		/*
		 * Make sure that if mm_users is reaching zero while
		 * kmem_defragd runs here, kmem_defragd_exit will find
		 * mm_slot not pointing to the exiting mm.
		 */
		if (mm_slot->mm_node.next != &kmem_defragd_scan.mm_head) {
			kmem_defragd_scan.mm_slot = list_first_entry(
				&mm_slot->mm_node,
				struct mm_slot, mm_node);
			kmem_defragd_scan.address = 0;
		} else
			kmem_defragd_scan.mm_slot = NULL;

		if (kmem_defragd_test_exit(mm_slot->mm))
			collect_mm_slot(mm_slot);
		else if (!scan_status) {
			list_del(&mm_slot->mm_node);
			list_add_tail(&mm_slot->mm_node, &kmem_defragd_scan.mm_head);
		}
	}
	spin_unlock(&kmem_defragd_mm_lock);

	return 0;
}

int memdefrag_madvise(struct vm_area_struct *vma,
		     unsigned long *vm_flags, int advice)
{
	switch (advice) {
	case MADV_MEMDEFRAG:
		*vm_flags &= ~VM_NOMEMDEFRAG;
		*vm_flags |= VM_MEMDEFRAG;
		/*
		 * If the vma become good for kmem_defragd to scan,
		 * register it here without waiting a page fault that
		 * may not happen any time soon.
		 */
		if (kmem_defragd_enter(vma, *vm_flags))
			return -ENOMEM;
		break;
	case MADV_NOMEMDEFRAG:
		*vm_flags &= ~VM_MEMDEFRAG;
		*vm_flags |= VM_NOMEMDEFRAG;
		/*
		 * Setting VM_NOMEMDEFRAG will prevent kmem_defragd from scanning
		 * this vma even if we leave the mm registered in kmem_defragd if
		 * it got registered before VM_NOMEMDEFRAG was set.
		 */
		break;
	}

	return 0;
}


void __init kmem_defragd_destroy(void)
{
	kmem_cache_destroy(mm_slot_cache);
}

int __init kmem_defragd_init(void)
{
	mm_slot_cache = kmem_cache_create("kmem_defragd_mm_slot",
					  sizeof(struct mm_slot),
					  __alignof__(struct mm_slot), 0, NULL);
	if (!mm_slot_cache)
		return -ENOMEM;

	return 0;
}

subsys_initcall(kmem_defragd_init)