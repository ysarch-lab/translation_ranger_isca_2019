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

#include <asm/tlb.h>
#include <asm/pgalloc.h>
#include "internal.h"


static DEFINE_SPINLOCK(kmem_defragd_mm_lock);

#define MM_SLOTS_HASH_BITS 10
static __read_mostly DEFINE_HASHTABLE(mm_slots_hash, MM_SLOTS_HASH_BITS);

static struct kmem_cache *mm_slot_cache __read_mostly;

struct defrag_scan_control {
	struct mm_struct *mm;
	unsigned long *scan_address;
	char __user *out_buf;
	int buf_len;
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
	if (shmem_file(vma->vm_file)) {
		if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGE_PAGECACHE))
			return false;
		return IS_ALIGNED((vma->vm_start >> PAGE_SHIFT) - vma->vm_pgoff,
				HPAGE_PMD_NR);
	}
	if (!vma->anon_vma || vma->vm_ops)
		return false;
	if (is_vma_temporary_stack(vma))
		return false;
	return true;
}

/* The caller should down_read mmap_sem  */
static struct page* get_page_from_address(struct mm_struct *mm,
						struct vm_area_struct *vma,
						unsigned long address)
{
	struct page *page = NULL;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmdp;
	pte_t *ptep, pteval;
	spinlock_t *ptl;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;
	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		goto out;
	pmdp = pmd_offset(pud, address);
	if (!pmd_present(*pmdp))
		goto out;

	if (pmd_trans_huge(*pmdp)) {
		ptl = pmd_lock(mm, pmdp);

		if (!pmd_present(*pmdp))
			goto pmd_out_unlock;

		if (pmd_trans_huge(*pmdp))
			page = pmd_page(*pmdp);

pmd_out_unlock:
		spin_unlock(ptl);
	} else {
		if (pmd_trans_unstable(pmdp))
			goto out;

		ptep = pte_offset_map_lock(mm, pmdp, address, &ptl);
		pteval = *ptep;

		page = vm_normal_page(vma, address, pteval);

		pte_unmap_unlock(ptep, ptl);
	}

out:
	return page;
}

static void do_page_stat(struct mm_struct *mm, struct vm_area_struct *vma,
		struct page *page, unsigned long vaddr,
		char *stats_buf, int pos, int* remain_buf_len)
{
	char *kernel_buf;
	int used_len;
	struct anon_vma *anon_vma;

	if (!*remain_buf_len)
		return;

	used_len = scnprintf(kernel_buf + pos, *remain_buf_len, "%p, %p, %ld, %ld, "
						 "0x%lx, 0x%llx",
						 mm, vma, vma->vm_start, vma->vm_end,
						 vaddr, page ? PFN_PHYS(page_to_pfn(page)) : 0);

	*remain_buf_len -= used_len;
	pos += used_len;

	if (!*remain_buf_len)
		return;

	if (page && PageAnon(page)) {
		anon_vma = page_anon_vma(page);
		if (!anon_vma)
			return;
		anon_vma_lock_read(anon_vma);

		do {
			used_len = scnprintf(kernel_buf + pos, *remain_buf_len, ", %p",
								 anon_vma);
			*remain_buf_len -= used_len;
			pos += used_len;

			if (!*remain_buf_len)
				return;
			anon_vma = anon_vma->parent;
		} while (anon_vma != anon_vma->parent);

		anon_vma_unlock_read(anon_vma);
	}

	/* end of one page stat  */
	used_len = scnprintf(kernel_buf + pos, *remain_buf_len, ", 0\n");
	*remain_buf_len -= used_len;
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
 * Scan single mm_struct.
 * The function will down_read mmap_sem.
 *
 */
static unsigned int kmem_defragd_scan_mm(struct defrag_scan_control *sc)
{
	struct mm_struct *mm = sc->mm;
	struct vm_area_struct *vma;
	unsigned long *scan_address = sc->scan_address;
	char __user *stats_buf = sc->out_buf;
	int remain_buf_len = sc->buf_len;

	down_read(&mm->mmap_sem);
	if (unlikely(kmem_defragd_test_exit(mm)))
		vma = NULL;
	else
		vma = find_vma(mm, *scan_address);

	for (; vma; vma = vma->vm_next) {
		unsigned long vstart, vend;

		cond_resched();
		if (unlikely(kmem_defragd_test_exit(mm)))
			break;
		if (!mem_defrag_vma_check(vma)) {
skip:
			continue;
		}
		vstart = vma->vm_start;
		vend = vma->vm_end;
		if (vstart >= vend)
			goto skip;
		if (*scan_address > vend)
			goto skip;
		if (*scan_address < vstart)
			*scan_address = vstart;

		while (*scan_address < vend) {
			/*int ret = 1;*/
			struct page *page;

			cond_resched();
			if (unlikely(kmem_defragd_test_exit(mm)))
				goto breakouterloop;

			page = get_page_from_address(mm, vma, *scan_address);

			do_page_stat(mm, vma, page, *scan_address,
						stats_buf, sc->buf_len - remain_buf_len,
						&remain_buf_len);
			/* move to next address */
			if (page)
				*scan_address += get_contig_page_size(page);
			else
				*scan_address += PAGE_SIZE;

			/* we released mmap_sem so break loop */
			/*if (ret)*/
				/*goto breakouterloop_mmap_sem;*/

		}
	}
breakouterloop:
	up_read(&mm->mmap_sem); /* exit_mmap will destroy ptes after this */
/*breakouterloop_mmap_sem:*/

	/* 0: scan complete, 1: scan_incomplete  */
	return vma == NULL ? 0 : 1;
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
	defrag_scan_control.scan_address = &kmem_defragd_scan.address;

	scan_status = kmem_defragd_scan_mm(&defrag_scan_control);

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