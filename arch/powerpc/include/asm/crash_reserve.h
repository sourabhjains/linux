/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_CRASH_RESERVE_H
#define _ASM_POWERPC_CRASH_RESERVE_H

/* crash kernel regions are Page size agliged */
#define CRASH_ALIGN             PAGE_SIZE

#define DEFAULT_CRASH_KERNEL_LOW_SIZE SZ_256M

#define CRASH_ADDR_LOW_MAX	ppc64_rma_size
#define CRASH_ADDR_HIGH_MAX	memblock_end_of_DRAM()


#endif /* _ASM_POWERPC_CRASH_RESERVE_H */
