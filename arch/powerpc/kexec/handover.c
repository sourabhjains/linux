// SPDX-License-Identifier: GPL-2.0-only
/*
 * powerpc overrides for kexec handover (KHO) early memory access.
 */

#include <linux/init.h>
#include <linux/printk.h>
#include <linux/memblock.h>
#include <linux/kexec_handover.h>

#include <asm/page.h>

void * __init kho_early_memremap(phys_addr_t phys, unsigned long size)
{
	/*
	 * This runs too early for early_memremap(): early_ioremap_setup()
	 * has not run yet, and on powerpc the MMU is off. So don't map
	 * anything. Use the kernel's linear mapping (__va()) to reach the
	 * memory directly.
	 *
	 * That is only safe for real RAM, so first check that the range
	 * is known to memblock. If it is not, return NULL so the caller
	 * disables KHO instead of accessing an invalid address.
	 */
	if (!size || !memblock_is_region_memory(phys, size)) {
		pr_warn("KHO: region 0x%llx+0x%lx is not in memblock memory\n",
			(unsigned long long)phys, size);
		return NULL;
	}

	return __va(phys);
}

void __init kho_early_memunmap(void *addr, unsigned long size)
{
	/* Nothing was mapped, so nothing to unmap. */
}
