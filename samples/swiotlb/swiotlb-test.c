// SPDX-License-Identifier: GPL-2.0-only
//
#define pr_fmt(fmt) "swiotlb_test: " fmt

#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/swiotlb.h>
#include <xen/page.h>
#include <xen/xen.h>
#define SWIOTLB_TEST  "0.1"

MODULE_AUTHOR("Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>");
MODULE_DESCRIPTION("swiotlb_test");
MODULE_LICENSE("GPL");
MODULE_VERSION(SWIOTLB_TEST);

static struct bus_type fallback_bus_type = {
	.name = "fallback_bus:",
};

static void fake_release(struct device *dev)
{
	/* No kfree as the device was allocated on stack. */
}

struct args {
	int len;
	int offset;
	int err;
	char *name;
	enum dma_data_direction dir;
	unsigned int max_segment_size;
	unsigned int min_align_mask;
};

#define MAGIC_DEVICE 'B'
#define MAGIC_CPU 'E'

static int swiotlb_test_thread(void *arg)
{
	struct page *page;
	dma_addr_t dma_addr = 0;
	struct device_dma_parameters parms = {
		.max_segment_size = 65536,
		.segment_boundary_mask = 0xffffffff,
	};
	struct device fake = {
		.coherent_dma_mask = DMA_BIT_MASK(32),
		.bus = &fallback_bus_type,
		.release = fake_release,
		.dma_parms = &parms,
		.dma_ops = NULL,
	};
	gfp_t gfp = __GFP_COMP | __GFP_NOWARN | GFP_ATOMIC;
	int ret;
	int i;
	void *addr;
	struct page *p;

	struct args *args = (struct args *)arg;
	int dir = args->dir;
	int len = args->len;
	int offset = args->offset;
	int *err = &args->err;

	dev_set_name(&fake, "%s-%s", args->name,
		     dir == DMA_TO_DEVICE ? "TO_DEV" : "TO_CPU");
	fake.dma_mask = &fake.coherent_dma_mask;
/*
	if (args->min_align_mask)
		dma_set_min_align_mask(&fake, args->min_align_mask);
*/
	if (args->max_segment_size)
		dma_set_max_seg_size(&fake, args->max_segment_size);

	ret = device_register(&fake);
	if (ret)
		goto out;

	dev_info(&fake, "len=%d offset=%d pages=%ld, order=%d\n", len, offset,
		 (PAGE_ALIGN(len) / PAGE_SIZE), get_order(PAGE_ALIGN(len)));
	do {
		unsigned long prev_mfn = 0;
		bool bus_and_dma_same;

		page = alloc_pages(gfp, get_order(PAGE_ALIGN(len)));
		if (!page) {
			dev_warn(&fake, "Not enough space %d\n",
				 PAGE_ALIGN(len));
			*err = __LINE__;
			break;
		}
		p = page;
		/* Check that the bus addresses are contingous. */

		for (i = 0; i < PAGE_ALIGN(len) / PAGE_SIZE; i++, p++) {
			unsigned long pfn, mfn;

			addr = page_address(p);
			pfn = PFN_DOWN(virt_to_phys(addr));
			if (xen_domain())
				mfn = pfn_to_mfn(pfn);
			else
				mfn = pfn;
			if (i != 0) {
				if (prev_mfn + 1 != mfn) {
					dev_warn(&fake,
						 "va: %lx (pfn:%lx, mfn:%lx) w.r.t prev mfn: %lx!\n",
						 (unsigned long)addr, pfn, mfn,
						 prev_mfn);
					*err = __LINE__;
					break;
				}
			}
			prev_mfn = mfn;
		}
		dma_addr = dma_map_page(&fake, page, offset, len, dir);
		/* Note, dma_addr is the physical address ! */
		if (dma_mapping_error(&fake, dma_addr)) {
			dev_warn(&fake, "DMA %lx for %lx is not right\n",
				 (unsigned long)dma_addr,
				 (unsigned long)page_address(page));
			__free_pages(page, get_order(PAGE_ALIGN(len)));
			page = NULL;
			*err = __LINE__;
			break;
		}
		/* If booting with swiotlb=force then bus_and_dma_same will be true. */
		bus_and_dma_same = false;
		if (page) {
			unsigned long phys;
			unsigned long pfn, mfn, bus_addr_mfn;
			unsigned long bus_addr = 0;
			int rem_len = len;

			p = page;
			for (i = 0; i < PAGE_ALIGN(len) / PAGE_SIZE; i++, p++) {
				void *bus_va;
				int len_in_p;

				addr = page_address(p);
				phys = virt_to_phys(addr);
				pfn = PFN_DOWN(phys);

				bus_va = (void *)(dma_addr + (i * PAGE_SIZE));
				/* This loop iterates over PAGE_SIZE, so we need to
				 * account for odd sizes, like 9K */
				len_in_p = min((int)PAGE_SIZE, rem_len);
				if (rem_len > PAGE_SIZE)
					rem_len -= PAGE_SIZE;

				if (xen_domain()) {
					void *tmp;

					/* Find the bus frame for the physical frame */
					mfn = pfn_to_mfn(pfn);
					/* and .. voodoo time! */
					bus_addr_mfn =
					    PFN_DOWN(dma_addr +
						     (i * PAGE_SIZE));
					bus_addr =
					    PFN_PHYS(mfn_to_pfn(bus_addr_mfn));
					tmp = __va(bus_addr);
					bus_va = mfn_to_virt(bus_addr_mfn);
					WARN(bus_va != tmp,
					     "Expected %lx (%lx+%d*PAGE_SIZE), got: %lx (pfn: %lx, mfn: %lx)!\n",
					     (unsigned long)bus_va,
					     (unsigned long)dma_addr, i,
					     (unsigned long)tmp,
					     PFN_DOWN(bus_addr), bus_addr_mfn);
					if (bus_va != tmp)
						*err = __LINE__;
				} else {
					mfn = pfn;
					bus_addr = (unsigned long)bus_va;
					/* Assume DMA addr == physical addr */
					bus_addr_mfn = PFN_DOWN(bus_addr);
					bus_va = __va(PFN_PHYS(bus_addr_mfn));
				}

				dev_info(&fake,
					 "%lx (pfn:%lx, bus frame: %lx) %s %lx (addr: %lx, frame: %lx) [offset=%d, len=%d]\n",
					 (unsigned long)addr, pfn, mfn,
					 dir == DMA_TO_DEVICE ? "=>" : "<=",
					 (unsigned long)bus_va, bus_addr,
					 bus_addr_mfn, offset, len_in_p);

				if (!virt_addr_valid(bus_va)) {
					*err = __LINE__;
					break;
				}
				if (!virt_addr_valid(addr)) {
					*err = __LINE__;
					break;
				}
				/* Depending on whether we copy from CPU or from DEVICE, we
				 * want preset values. The MAGIC_CPU is what should show up
				 * in bus_addr after we do dma_sync_single_for_device.
				 */
				memset(addr + offset, MAGIC_CPU, len_in_p);

				/* .. while if we are doing DEVICE to CPU (DMA_FROM_DEVICE)
				 * we want the the MAGIC_DEVICE show up in addr after we do
				 * dma_sync_single_for_cpu
				 */
				memset(bus_va + offset, MAGIC_DEVICE, len_in_p);

				/* Offsets are interesting. We poison both pages with
				 * values, so that you have:
				 *
				 * space| @0.. | @offset|  to len
				 * BUS: | AA   | BB..BB | CC
				 * ADDR:| DD   | EE..EE | FF
				 */
				if (offset) {
					memset(bus_va, 'A', offset);
					memset(addr, 'D', offset);
					if (offset + len_in_p < PAGE_SIZE) {
						memset(bus_va + offset + len_in_p, 'C',
						       PAGE_SIZE - len_in_p - offset);
						memset(addr + offset + len_in_p, 'F',
						       PAGE_SIZE - len_in_p - offset);
					}
				}

				if (addr == bus_va)
					bus_and_dma_same = true;

				if (offset && IS_ENABLED(DEBUG)) {
					print_hex_dump(KERN_DEBUG, "bus: ", DUMP_PREFIX_NONE,
						       16, 8, bus_va, PAGE_SIZE, true);
					print_hex_dump(KERN_DEBUG, "page: ", DUMP_PREFIX_NONE,
						       16, 8, addr, PAGE_SIZE, true);
				}
			}
		}

		/* Lets pretend we are a device and a bit slow.. */
		if (!page || *err)
			break;

		/* Let it rip!! */
		if (dir == DMA_FROM_DEVICE)
			/* Sync from dma_addr to page_address(page). Contents of page should have MAGIC_DEVICE */
			dma_sync_single_for_cpu(&fake, dma_addr, len, dir);
		else if (dir == DMA_TO_DEVICE)
			/* Sync from addr to dma_addr (contents of page should have MAGIC_CPU) */
			dma_sync_single_for_device(&fake, dma_addr, len, dir);
		else {
			*err = __LINE__;
			break;
		}
		p = page;

		/*
		 * Touch dma_addr _after_ we have unmapped means it may
		 * have been re-used.
		 */
		dma_unmap_page(&fake, dma_addr, len, dir);
		for (i = 0; i < PAGE_ALIGN(len) / PAGE_SIZE; i++, p++) {
			u8 check_val = 0;
			u8 data;
			u8 *q;
			ssize_t j, len_in_p;

			addr = page_address(p);

			if (dir == DMA_TO_DEVICE)
				check_val = MAGIC_CPU;
			else if (dir == DMA_FROM_DEVICE)
				check_val = MAGIC_DEVICE;
			else
				break;

			len_in_p = min((int)PAGE_SIZE, len);
			q = ((u8 *) addr) + offset;

			for (j = 0; j < len_in_p; j++, q++) {
				void *bus_va;
				data = *q;

				if (data == check_val)
					continue;

				bus_va = __va(PFN_PHYS (PFN_DOWN (dma_addr + (i * PAGE_SIZE))));

				dev_warn(&fake, "%lx[+0x%lx] has '%c' (expected '%c'). Starting at offset=0x%x\n",
					 (unsigned long)addr,
					 offset + j, data, check_val, offset);

				print_hex_dump(KERN_INFO, "p: ", DUMP_PREFIX_OFFSET,
					       16, 1, q, len_in_p, true);

				dev_warn(&fake,
					 "DMA %lx[+0x%lx]. Starting at offset=0x%x)\n",
					 (unsigned long)(dma_addr + (i * PAGE_SIZE)),
					 offset + j, offset);

				if (virt_addr_valid(bus_va))
					print_hex_dump(KERN_INFO, "bus: ", DUMP_PREFIX_OFFSET,
						       16, 1, bus_va + (i * PAGE_SIZE) +
						       offset, len_in_p, true);

				*err = __LINE__;
				break;
			}
			if (*err)
				break;
		}
		dma_addr = 0;
		__free_pages(page, get_order(PAGE_ALIGN(len)));
		page = NULL;
	}
	while (0);

	if (dma_addr)
		dma_unmap_page(&fake, dma_addr, len, dir);
	if (page)
		__free_pages(page, get_order(PAGE_ALIGN(len)));

	dev_info(&fake, "%s\n", *err ? "FAILURE" : "SUCCESS");
	device_unregister(&fake);
 out:
	return *err;
}

#define TESTS 13
static struct args a[TESTS] = {
	{
	 .len = 32768,
	 .dir = DMA_TO_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "32k_to_dev",
	 },
	{
	 .len = 4096,
	 .dir = DMA_TO_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "4k_to_dev",
	 },
	{
	 .len = 2048,
	 .dir = DMA_TO_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "2k_to_dev",
	 },
	{
	 .len = 256,
	 .dir = DMA_TO_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "256_to_dev",
	 },
	{
	 .len = 256,
	 .dir = DMA_TO_DEVICE,
	 .offset = 128,
	 .err = 0,
	 .name = "256_to_dev_128_offset",
	 },
	{
	 .len = 16384,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "16k_from_dev",
	 },
	{
	 .len = 4096,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "4k_from_dev",
	 },
	{
	 .len = 2048,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "2k_from_dev",
	 },
	{
	 .len = 2048,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 2048,
	 .err = 0,
	 .name = "2k_from_dev_2k_offset",
	},
	{
	 .len = 1024,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 0,
	 .err = 0,
	 .name = "1k_from_dev",
	},
	{
	 .len = 1024,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 2048,
	 .err = 0,
	 .name = "1k_from_dev_2k_offset",
	},
	{
	 .len = 256,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 128,
	 .err = 0,
	 .name = "256_from_dev_128_offset",
	 },
	{
	 .len = 64,
	 .dir = DMA_FROM_DEVICE,
	 .offset = 1024,
	 .err = 0,
	 .name = "64_from_dev_1k_offset",
	 }
};

static int __init swiotlb_test_init(void)
{
	int ret;
	unsigned int i = 0;

	/* No point doing this without SWIOTLB */
	if (!swiotlb_max_segment())
		return -ENODEV;

	ret = bus_register(&fallback_bus_type);
	if (ret)
		return ret;

	for (i = 0; i < TESTS; i++) {
		if (!a[i].name)
			continue;

		(void)swiotlb_test_thread(&a[i]);

		ret |= a[i].err;
		if (a[i].err) {
			printk("Test %s failed at %d\n", a[i].name, a[i].err);
		}
	}
	printk("Tests %s\n", ret ? "FAILED" : "SUCCESS");

	bus_unregister(&fallback_bus_type);

	return ret > 0 ? -EINVAL : ret;
}

static void __exit swiotlb_test_exit(void)
{
}

module_init(swiotlb_test_init);
module_exit(swiotlb_test_exit);
