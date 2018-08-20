/*
  Copyright (C) 2018-2018 Intel Corporation.  All Rights Reserved.

  This file is part of SEP Development Kit

  SEP Development Kit is free software; you can redistribute it
  and/or modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.

  SEP Development Kit is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with SEP Development Kit; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

  As a special exception, you may use this file as part of a free software
  library without restriction.  Specifically, if other files instantiate
  templates or use macros or inline functions from this file, or you compile
  this file and link it with other files to produce an executable, this
  file does not by itself cause the resulting executable to be covered by
  the GNU General Public License.  This exception does not however
  invalidate any other reasons why the executable file might be covered by
  the GNU General Public License.
*/

#ifndef _VTSS_MEMORY_POOL_H_
#define _VTSS_MEMORY_POOL_H_


#include "vtss_autoconf.h"
#include <linux/types.h>        // for size_t
#include <linux/gfp.h>

int vtss_memory_pool_init(void);
void vtss_memory_pool_fini(void);
void vtss_memory_pool_clear(void);

unsigned long vtss_get_free_pages_internal(gfp_t gfp_mask, unsigned int order);
void vtss_free_pages_internal(unsigned long addr, unsigned int order);
unsigned long vtss_get_free_page_internal(gfp_t gfp_mask);
void vtss_free_page_internal(unsigned long addr);
unsigned long vtss_get_free_block(gfp_t gfp_mask, size_t size);
void vtss_free_block(unsigned long addr, size_t size);

void* vtss_kmalloc_internal(size_t size, gfp_t flags);
void vtss_kfree_internal(const void *);
        
#endif /* _VTSS_MEMORY_POOL_H_ */
