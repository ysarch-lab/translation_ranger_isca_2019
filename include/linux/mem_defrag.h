#ifndef _LINUX_KMEM_DEFRAGD_H
#define _LINUX_KMEM_DEFRAGD_H

#include <linux/sched/coredump.h> /* MMF_VM_MEM_DEFRAG */

#define MEM_DEFRAG_SCAN				0
#define MEM_DEFRAG_MARK_SCAN_ALL	1
#define MEM_DEFRAG_CLEAR_SCAN_ALL	2
#define MEM_DEFRAG_DEFRAG			3
#define MEM_DEFRAG_THP_COMPACT		4
#define MEM_DEFRAG_CONTIG_SCAN		5
#define MEM_DEFRAG_PAGEBLOCK_SCAN	6
#define MEM_DEFRAG_FLUSH_TLB		7

enum mem_defrag_action {
	MEM_DEFRAG_FULL_STATS = 0,
	MEM_DEFRAG_DO_DEFRAG,
	MEM_DEFRAG_CONTIG_STATS,
};

extern int kmem_defragd_always;

extern int __kmem_defragd_enter(struct mm_struct *mm);
extern void __kmem_defragd_exit(struct mm_struct *mm);
extern int memdefrag_madvise(struct vm_area_struct *vma,
		     unsigned long *vm_flags, int advice);
extern int pageblock_scan_node(int node, char __user * out_buf, int buf_len);

static inline int kmem_defragd_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
	 if (test_bit(MMF_VM_MEM_DEFRAG, &oldmm->flags))
		return __kmem_defragd_enter(mm);
	 return 0;
}

static inline void kmem_defragd_exit(struct mm_struct *mm)
{
	if (test_bit(MMF_VM_MEM_DEFRAG, &mm->flags))
		__kmem_defragd_exit(mm);
}

static inline int kmem_defragd_enter(struct vm_area_struct *vma,
				   unsigned long vm_flags)
{
	if (!test_bit(MMF_VM_MEM_DEFRAG, &vma->vm_mm->flags))
		if (((kmem_defragd_always ||
		     ((vm_flags & VM_MEMDEFRAG))) &&
		    !(vm_flags & VM_NOMEMDEFRAG)) ||
			test_bit(MMF_VM_MEM_DEFRAG_ALL, &vma->vm_mm->flags))
			if (__kmem_defragd_enter(vma->vm_mm))
				return -ENOMEM;
	return 0;
}

#endif /* _LINUX_KMEM_DEFRAGD_H */
