/*
 * Scan all pageblock for their migratetypes
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched.h>
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

#include <asm/tlb.h>
#include <asm/pgalloc.h>
#include "internal.h"

#define block_start_pfn(pfn, order)	round_down(pfn, 1UL << (order))
#define block_end_pfn(pfn, order)	ALIGN((pfn) + 1, 1UL << (order))
#define pageblock_start_pfn(pfn)	block_start_pfn(pfn, pageblock_order)
#define pageblock_end_pfn(pfn)		block_end_pfn(pfn, pageblock_order)


struct pg_scan_control {
	int nid;
	unsigned long scan_pfn;
	int remain_buf_len;
	int last_migratetype;
	unsigned long last_pfn;

	char *out_buf;
	int buf_len;
};

static int pageblock_scan_zone(struct zone *scan_zone,
		struct pg_scan_control *cc)
{
	const unsigned long scan_start_pfn = max(scan_zone->zone_start_pfn,
			cc->scan_pfn);
	const unsigned long scan_end_pfn = zone_end_pfn(scan_zone);
	unsigned long block_start_pfn;
	unsigned long block_end_pfn;
	struct page *page;
	int pageblock_migratetype;

	block_start_pfn = pageblock_start_pfn(scan_start_pfn);
	if (block_start_pfn < scan_start_pfn)
		block_start_pfn = scan_start_pfn;

	block_end_pfn = pageblock_end_pfn(scan_start_pfn);

	for (; block_end_pfn < scan_end_pfn;
		 block_start_pfn = block_end_pfn,
		 block_end_pfn += pageblock_nr_pages) {
		page = pageblock_pfn_to_page(block_start_pfn, block_end_pfn, scan_zone);

		if (!page)
			continue;

		cc->scan_pfn = block_start_pfn;

		pageblock_migratetype = get_pageblock_migratetype(page);

		if (cc->last_migratetype != pageblock_migratetype) {
			int used_len;
			int pos = cc->buf_len - cc->remain_buf_len;

			if (cc->last_migratetype < 0) {
				cc->last_migratetype = pageblock_migratetype;
				cc->last_pfn = block_start_pfn;
				continue;
			}

			if (!cc->remain_buf_len || !cc->out_buf)
				return -1;

			used_len = scnprintf(cc->out_buf + pos, cc->remain_buf_len,
				"[%lx, %lx): %s\n", cc->last_pfn, block_start_pfn,
				migratetype_names[cc->last_migratetype]);

			if (used_len + 1 == cc->remain_buf_len) {
				cc->out_buf[pos] = '\0';
				return -1;
			}
			cc->remain_buf_len -= used_len;

			cc->last_migratetype = pageblock_migratetype;
			cc->last_pfn = block_start_pfn;
		}
	}

	/* output last part of the zone  */
	{
		int used_len;
		int pos = cc->buf_len - cc->remain_buf_len;

		if (!cc->remain_buf_len || !cc->out_buf)
			return -1;

		used_len = scnprintf(cc->out_buf + pos, cc->remain_buf_len,
			"[%lx, %lx): %s\n", cc->last_pfn, block_start_pfn,
			migratetype_names[cc->last_migratetype]);

		if (used_len + 1 == cc->remain_buf_len) {
			cc->out_buf[pos] = '\0';
			return -1;
		}

		cc->remain_buf_len -= used_len;

		cc->last_migratetype = -1;
		cc->scan_pfn = cc->last_pfn = scan_end_pfn;
	}

	return 0;
}

int pageblock_scan_node(int nid, char __user * out_buf, int buf_len)
{
	pg_data_t *scan_node = NODE_DATA(nid);
	int zoneid;
	struct zone *zone;
	static struct pg_scan_control cc = {
		.nid = -1,
	};
	int err = 0;

	/* Is it a new scan or a resumed one  */
	if (cc.nid != nid) {
		cc = (struct pg_scan_control){0};
		cc.nid = nid;
		cc.scan_pfn = node_start_pfn(nid);
		cc.last_migratetype = -1;
	}

	/* prepare buffer in the kernel */
	if (out_buf && buf_len) {
		cc.out_buf = vzalloc(buf_len);
		if (!cc.out_buf) {
			err = -ENOMEM;
			goto out;
		}
		cc.buf_len = buf_len;
		cc.remain_buf_len = buf_len;
	}

	for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {
		zone = &scan_node->node_zones[zoneid];
		if (!populated_zone(zone))
			continue;

		if (cc.scan_pfn >= zone_end_pfn(zone))
			continue;

		if (pageblock_scan_zone(zone, &cc) < 0)
			break;
	}

	err = cc.buf_len - cc.remain_buf_len;

	if (cc.scan_pfn >= node_end_pfn(nid))
		cc.nid = -1;

	if (out_buf && buf_len) {
		err = copy_to_user(out_buf, cc.out_buf,
				cc.buf_len - cc.remain_buf_len);
		cc.buf_len = 0;
		cc.remain_buf_len = 0;
	}

	if (cc.out_buf) {
		vfree(cc.out_buf);
		cc.out_buf = NULL;
	}
out:
	return err;
}
