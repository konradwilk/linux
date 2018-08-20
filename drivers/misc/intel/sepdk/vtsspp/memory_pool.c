/*
  Copyright (C) 2018 Intel Corporation.  All Rights Reserved.

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

#include "vtss_config.h"
#include "globals.h"
#include "memory_pool.h"

#include <linux/delay.h> // for msleep_interruptible()
#include <linux/nmi.h>   // for touch_nmi_watchdog()
#include <linux/slab.h>
#include <linux/hardirq.h> //in_atomic for kernel 2.6.32

#define DEBUG_MP TRACE

// when number of cores too big we need many 
// allocated buffers to access from different 
// cores whithout delay
#define VTSS_ALLOC_ORDER_MIN 4 
#define VTSS_ALLOC_ORDER_ATOMIC 8 
#define VTSS_ALLOC_ORDER_MAX 10 

#define VTSS_NR_CHUNKS_MIN 0x8
#define VTSS_NR_CHUNKS_MAX 0x100

#define VTSS_WAIT_TIME 100

//block of memory reserved in preallocated pages
struct vtss_memory_block
{
    struct vtss_memory_block* prev;
    struct vtss_memory_block* next;
    size_t size;

    atomic_t is_free;
    char memblock[0];            //  placeholder memory blocks, should be the last in the structure
};

// block of memory header
struct vtss_memchunk
{
    struct list_head    list;

    struct vtss_memory_block* head; // list of allocated blocks
    struct vtss_memory_block* tail; // list of allocated blocks

    atomic_t busy;

    size_t size;                   // allocated size - sizeof(vtss_memchunk)
    atomic_t free_space;
    
    gfp_t flags;
    
    char memblocks[0];            //  placeholder memory blocks, should be the last in the structure
};

static LIST_HEAD(g_memchunk_list);

static atomic_t g_vtss_memchunk_list_write = ATOMIC_INIT(0);
static atomic_t g_vtss_memchunk_list_read = ATOMIC_INIT(0);

static atomic_t g_vtss_chunk_list_length = ATOMIC_INIT(0);

static inline void vtss_memchunk_list_write_lock(void)
{
    int i = 0;
    while (atomic_cmpxchg(&g_vtss_memchunk_list_write, 0, 1))
    {
        touch_nmi_watchdog();
        if (i == VTSS_WAIT_TIME) DEBUG_MP("Cannot lock for write");
        i++;
    }
    i = 0;
    while (atomic_read(&g_vtss_memchunk_list_read))
    {
        touch_nmi_watchdog();
        if (i == VTSS_WAIT_TIME) DEBUG_MP("Read lock is not free");
        i++;
    }
}

static inline void vtss_memchunk_list_write_unlock(void)
{
    atomic_set(&g_vtss_memchunk_list_write,0);
}

static inline void vtss_memchunk_list_read_lock(void)
{
    int i = 0;
    do
    {
        while (atomic_read(&g_vtss_memchunk_list_write));
        atomic_inc(&g_vtss_memchunk_list_read);
        if (atomic_read(&g_vtss_memchunk_list_write)) atomic_dec(&g_vtss_memchunk_list_read);
        else break;
        touch_nmi_watchdog();
        if (i == VTSS_WAIT_TIME) DEBUG_MP("Cannot lock for read");
        i++;
    }
    while (1);
}

static inline void vtss_memchunk_list_read_unlock(void)
{
    atomic_dec(&g_vtss_memchunk_list_read);
}

static atomic_t g_vtss_kernel_task_in_progress = ATOMIC_INIT(0);
static atomic_t g_vtss_mempool_init = ATOMIC_INIT(0);

static void vtss_init_memchunk(struct vtss_memchunk* chunk)
{
    memset(chunk, 0, sizeof(struct vtss_memchunk));
    atomic_set(&chunk->busy,0);
    chunk->flags = GFP_NOWAIT;
}

void vtss_memory_pool_clear(void)
{
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;

    list_for_each_safe(p, tmp, &g_memchunk_list)
    {
        struct vtss_memchunk* chunk = list_entry(p, struct vtss_memchunk, list);
        struct vtss_memory_block* temp = NULL;
        touch_nmi_watchdog();
        if (chunk == NULL)
        {
             ERROR("Chunk in list is NULL");
             continue;
        }
        if (atomic_read(&chunk->busy) != 0)
        {
            ERROR("Chunk is busy");
            continue;
        }
        if (atomic_read(&chunk->free_space) != chunk->size)
        {
           ERROR("Memoty leaks detected, free_space = %zx, size = %zx", (size_t)atomic_read(&chunk->free_space), chunk->size);
           atomic_set(&chunk->free_space,chunk->size);
        }
#if 0
        temp = chunk->head;
        while (temp && atomic_read(&temp->is_free) != 1)
        {
            ERROR("Error in memory pool logic detected, temp = %p", temp);
            temp = temp->next;
        }
#endif
        chunk->head = NULL;
        chunk->tail = NULL;

    }
    return;
}

struct vtss_memchunk* vtss_create_memchunk(gfp_t flags, unsigned int size)
{
    struct vtss_memchunk* chunk = NULL;
    unsigned int order = get_order(size) >= VTSS_ALLOC_ORDER_MIN ? get_order(size) : VTSS_ALLOC_ORDER_MIN;
    int i = 0;

    if (atomic_read(&g_vtss_chunk_list_length) >= VTSS_NR_CHUNKS_MAX)
    {
        DEBUG_MP("Max number of memory chunks is reached");
        return NULL;
    }
    do
    {
        chunk = (struct vtss_memchunk*)__get_free_pages(flags | (flags == GFP_NOWAIT ? __GFP_NORETRY : 0) | __GFP_NOWARN, order);
        if (!chunk)
        {
            ERROR("cannot allocate order = %d", order);
        }
    }
    while ((!chunk) && (--order) >= VTSS_ALLOC_ORDER_MIN);

    DEBUG_MP("chunk = %p  allocated, order = %x", chunk, order);

    if (chunk == NULL)
    {
       ERROR("Not enough memory to create memchunk");
       return NULL;
    }
    atomic_inc(&g_vtss_chunk_list_length);
    vtss_init_memchunk(chunk);
    chunk->flags = flags;
    chunk->size = (PAGE_SIZE<<order) - sizeof(struct vtss_memchunk);
    atomic_set(&chunk->free_space,chunk->size);
    DEBUG_MP("Chunk created: order = 0x%x, (PAGE_SIZE<<order) = %lx, sizeof(vtss_memchunk)= 0x%llx, sizeof(*chunk)=%llx, &chunk->memblocks = %llx, chunk->memblocks = %llx,chunk->size = %zu",
              order, (PAGE_SIZE<<order), (unsigned long long)sizeof(struct vtss_memchunk), (unsigned long long)sizeof(*chunk), (unsigned long long)&chunk->memblocks, (unsigned long long)chunk->memblocks,chunk->size);
    i = 0;
    vtss_memchunk_list_write_lock();
    list_add(&chunk->list, &g_memchunk_list);
    vtss_memchunk_list_write_unlock();
    return chunk;
}

struct vtss_memchunk_alloc_data
{
    gfp_t flags;
    size_t size;
};

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_create_memchunk_work(struct work_struct *work)
#else
static void vtss_create_memchunk_work(void *work)
#endif
{
    struct vtss_work* my_work = (struct vtss_work*)work;
    struct vtss_memchunk_alloc_data* alloc_data = NULL;
    struct vtss_memchunk* chunk = NULL;
    DEBUG_MP("Creating new chunc async.");
    if (!my_work)
    {
        ERROR("Empty work");
        return;
    }
    if (!atomic_read(&g_vtss_mempool_init))
    {
        vtss_kfree(my_work);
        ERROR("mempoolnot init");
        atomic_dec(&g_vtss_kernel_task_in_progress);
        return;
    }
    alloc_data = (struct vtss_memchunk_alloc_data*)my_work->data;
    if (!alloc_data)
    {
        ERROR("Unknown parameters");
        vtss_kfree(my_work);
        atomic_dec(&g_vtss_kernel_task_in_progress);
        return;
    }
    chunk = vtss_create_memchunk(alloc_data->flags, alloc_data->size);
    vtss_kfree(my_work);
    atomic_dec(&g_vtss_kernel_task_in_progress);
    DEBUG_MP("done!");
}

struct vtss_memchunk* vtss_create_memchunk_async(gfp_t flags, unsigned int size)
{

    if (in_atomic())
    {
        struct vtss_memchunk_alloc_data data;
        // create async
        DEBUG_MP("The attempt to allocate memory in irqs disabled mode. Start async");
        data.flags = flags;
        data.size = size;
        atomic_inc(&g_vtss_kernel_task_in_progress);
        if (atomic_read(&g_vtss_kernel_task_in_progress) > 1)
        { 
            DEBUG_MP("Cannot create async, g_vtss_kernel_task_in_progress = %d", atomic_read(&g_vtss_kernel_task_in_progress));
            atomic_dec(&g_vtss_kernel_task_in_progress);
            return NULL;
        }
        if (vtss_queue_work(-1, vtss_create_memchunk_work, &data, sizeof(data)))
        {
            DEBUG_MP("cannot create !!!");
            atomic_dec(&g_vtss_kernel_task_in_progress);
        }
        // no need to wait memory creation. caller decides if it's reasonable                                                                                                                                                                                                         }
        //while (atomic_read(&g_vtss_kernel_task_in_progress));
        return NULL;
    }
    DEBUG_MP("creating chunk...");
    return vtss_create_memchunk(flags, size);
}

void vtss_destroy_memchunk(struct vtss_memchunk* chunk)
{
    DEBUG_MP("chunk = %p, size = 0x%lx, deleting....", chunk, (unsigned long)chunk - (unsigned long)&chunk->memblocks + chunk->size);

    free_pages((unsigned long)chunk, get_order(sizeof(struct vtss_memchunk) + chunk->size));

    DEBUG_MP("done");
}

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_destroy_memchunk_work(struct work_struct *work)
#else
static void vtss_destroy_memchunk_work(void *work)
#endif
{
    struct vtss_work* my_work = (struct vtss_work*)work;
    struct vtss_memchunk* chunk = NULL;
    if (!my_work)
    {
        ERROR("Empty work");
        return;
    }
    if (!atomic_read(&g_vtss_mempool_init))
    {
        vtss_kfree(my_work);
        atomic_dec(&g_vtss_kernel_task_in_progress);
        return;
    }
    chunk = (struct vtss_memchunk*)my_work->data;
    if (!chunk)
    {
        ERROR("Nothing to delete");
        vtss_kfree(my_work);
        atomic_dec(&g_vtss_kernel_task_in_progress);
        return;
    }
    vtss_destroy_memchunk(chunk);
    vtss_kfree(my_work);
    atomic_dec(&g_vtss_kernel_task_in_progress);
}

void vtss_destroy_memchunk_async(struct vtss_memchunk* chunk)
{
    if (in_atomic())
    {
        DEBUG_MP("The attempt to deallocate memory in irqs disabled mode. Start async");
        atomic_inc(&g_vtss_kernel_task_in_progress);
        if (vtss_queue_work(-1, vtss_destroy_memchunk_work, &chunk, sizeof(chunk)))
        {
            DEBUG_MP("failed create work");
            atomic_dec(&g_vtss_kernel_task_in_progress);
        }
        return;
    }
    vtss_destroy_memchunk(chunk);
}

static void vtss_delete_chunk_list(void)
{
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;

    vtss_memchunk_list_write_lock();
    list_for_each_safe(p, tmp, &g_memchunk_list)
    {
        struct vtss_memchunk* chunk = list_entry(p, struct vtss_memchunk, list);
        touch_nmi_watchdog();
        if (chunk == NULL)
        {
             ERROR("Chunk in list is NULL");
             continue;
        }
        list_del(p);
        atomic_dec(&g_vtss_chunk_list_length);
        DEBUG_MP("chunk %p destroying ....", chunk);
        vtss_destroy_memchunk(chunk);
        DEBUG_MP("done.");
    }
    INIT_LIST_HEAD(&g_memchunk_list);
    vtss_memchunk_list_write_unlock();
    return;
}

int vtss_memory_pool_init(void)
{
    int i = 0;

    int nr_chunks = num_present_cpus();
    unsigned long long prealloc_buf_size = PAGE_SIZE << VTSS_ALLOC_ORDER_MAX;
    struct vtss_memchunk *chunk = NULL;
    nr_chunks += 4;
    nr_chunks = nr_chunks > VTSS_NR_CHUNKS_MAX ? VTSS_NR_CHUNKS_MAX : nr_chunks;
    nr_chunks = nr_chunks < VTSS_NR_CHUNKS_MIN ? VTSS_NR_CHUNKS_MIN : nr_chunks;
    DEBUG_MP("prealloc_buf_size = %llx,  num_present_cpus = %d", prealloc_buf_size, num_present_cpus());

    vtss_memchunk_list_write_lock();
    INIT_LIST_HEAD(&g_memchunk_list);
    vtss_memchunk_list_write_unlock();
    
    atomic_set(&g_vtss_chunk_list_length, 0);
    
    for (i = 0; i < nr_chunks - 5; i++)
    {
        chunk = vtss_create_memchunk(GFP_NOWAIT, prealloc_buf_size);
        if (!chunk)
        {
            ERROR("Not enough memory for GFP_NOWAIT chunk[%d]", i);
            return -1;
        }
    }
    chunk = vtss_create_memchunk(GFP_KERNEL, prealloc_buf_size);
    if (!chunk)
    {
        ERROR("Not enough memory for GFP_KERNEL chunk");
        return -1;
    }
    chunk = vtss_create_memchunk(GFP_KERNEL, prealloc_buf_size);
    if (!chunk)
    {
        ERROR("Not enough memory for GFP_KERNEL chunk");
        return -1;
    }
    chunk = vtss_create_memchunk(GFP_KERNEL, prealloc_buf_size);
    if (!chunk)
    {
        ERROR("Not enough memory for GFP_KERNEL chunk");
        return -1;
    }
    chunk = vtss_create_memchunk(GFP_ATOMIC, PAGE_SIZE<<VTSS_ALLOC_ORDER_ATOMIC);
    if (!chunk)
    {
        ERROR("Not enough memory for GFP_ATOMIC chunk");
        return -1;
    }

    chunk = vtss_create_memchunk(GFP_ATOMIC, PAGE_SIZE<<VTSS_ALLOC_ORDER_ATOMIC);
    if (!chunk)
    {
        ERROR("Not enough memory for GFP_ATOMIC chunk");
        return -1;
    }
/*    chunk = vtss_create_memchunk(GFP_ATOMIC, PAGE_SIZE<<VTSS_ALLOC_ORDER_MIN);
    if (!chunk)
    {
        ERROR("Not enough memory for GFP_ATOMIC chunk");
        return -1;
    }*/
    atomic_inc(&g_vtss_mempool_init);

    return 0;
}

void vtss_memory_pool_fini(void)
{
    int i = 0;
    atomic_dec(&g_vtss_mempool_init);

    while (atomic_read(&g_vtss_kernel_task_in_progress))
    {
         i++;
         if (i == VTSS_WAIT_TIME) ERROR("Awaiting unfinishing kernel tasks...");
         msleep_interruptible(1);
         touch_nmi_watchdog();
    };
    DEBUG_MP("Ok. No active kernel tasks.");
    i = 0;
    vtss_delete_chunk_list();
    DEBUG_MP("empty memory pool");

    return;
}

static struct vtss_memory_block* vtss_find_free_block(struct vtss_memchunk* chunk, size_t size)
{
    struct vtss_memory_block* block = NULL;
    struct vtss_memory_block* temp = NULL;
    unsigned long start_addr = 0;
    unsigned long end_addr = 0;
    
    //search from tail
    DEBUG_MP("start");
    temp = chunk->tail;
    atomic_sub(size + sizeof(struct vtss_memory_block), &chunk->free_space);
    while (temp && atomic_read(&temp->is_free))
    {
        DEBUG_MP("finding tail, temp = %p", temp);
        temp = temp->prev;
        if (temp) temp->next = NULL;
        chunk->tail = temp;
    }
    if (temp)
    {
        start_addr = (unsigned long)temp + sizeof(struct vtss_memory_block) + temp->size;
        DEBUG_MP("(unsigned long)temp + sizeof(*temp) + temp->size;%lx", start_addr);
        
        end_addr = (unsigned long)(&chunk->memblocks) + chunk->size;
        if (end_addr - start_addr >= size + sizeof(struct vtss_memory_block))
        {
            block = (struct vtss_memory_block* )start_addr;
            block->prev = temp;
            block->next = NULL;
            block->size = size;
            atomic_set(&block->is_free, 0);
            temp->next = block;
            chunk->tail = block;
            return block;
         }
    }
    else
    {
        chunk->head = NULL;
    }

    //search from head
    temp = chunk->head;

    start_addr = (unsigned long)(chunk) + sizeof(struct vtss_memchunk);


    if (!temp)
    {
        if (chunk->size >= size + sizeof(struct vtss_memory_block))
        {
            block = (struct vtss_memory_block* )start_addr;
            block->prev = NULL;
            block->next = NULL;
            block->size = size;
            atomic_set(&block->is_free, 0);
        }
        chunk->head = chunk->tail = block;
        DEBUG_MP("Chunk is empty. Return %p", block);
        if (!block)
        {
           ERROR("Error in alghorithm");
           atomic_add(size+sizeof(struct vtss_memory_block), &chunk->free_space);
        }
        return block;
    }

    //search free space in the middle and merge garbage
    end_addr = (unsigned long)(temp);

    while (temp)
    {
        //DEBUG_MP("Searching free space in the middle of the chunk");
        if (atomic_read(&temp->is_free))
        {
            if (temp->prev) temp->prev->next = temp->next;
            if (temp->next) temp->next->prev = temp->prev;
            if (temp == chunk->head) chunk->head = temp->next;
            if (temp == chunk->tail) chunk->tail = temp->prev;
            temp = temp->next;
            end_addr = (temp) ? (unsigned long)(temp) : (unsigned long)(chunk) + sizeof(struct vtss_memchunk)+ chunk->size;
            continue;
        }
        if (end_addr - start_addr >= size + sizeof(struct vtss_memory_block))
        {
            block = (struct vtss_memory_block* )(start_addr);
            if (temp->prev)
            {
                block->prev = temp->prev;
                temp->prev->next = block;
            }
            else
            {
                block->prev = NULL;
                chunk->head = block;
            }
            temp->prev = block;
            block->next = temp;
            block->size = size;
            atomic_set(&block->is_free, 0);
            return block;
        }
        start_addr = end_addr = (unsigned long)(temp) + sizeof(struct vtss_memory_block)+ temp->size;
        temp = temp->next;
        end_addr = (temp) ? (unsigned long)(temp) : (unsigned long)(chunk) + sizeof(struct vtss_memchunk)+ chunk->size;
    }

    if (end_addr - start_addr >= size + sizeof(struct vtss_memory_block))
    {
        DEBUG_MP("Return tail block that was deallocated in different thread");
        block = (struct vtss_memory_block* )start_addr;
        block->prev = chunk->tail;
        if (chunk->tail) chunk->tail->next = block;
        block->next = NULL;
        block->size = size;
        atomic_set(&block->is_free, 0);
        chunk->tail = block;
        if (!chunk->head) chunk->head = block;
    }
    if (!block) atomic_add(size+sizeof(struct vtss_memory_block), &chunk->free_space);
    return block;
}

unsigned long vtss_get_free_block(gfp_t gfp_mask, size_t size)
{
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;
    unsigned long block_addr = 0;
    vtss_memchunk_list_read_lock();
    list_for_each_safe(p, tmp, &g_memchunk_list)
    {
        struct vtss_memchunk* chunk = list_entry(p, struct vtss_memchunk, list);
        touch_nmi_watchdog();
        if (chunk == NULL)
        {
             ERROR("Chunk in list is NULL");
             continue;
        }
        if (chunk->flags != gfp_mask)
        {
            //DEBUG_MP("GFP FLAGS are different");
            continue;
        }
        if (atomic_cmpxchg(&chunk->busy, 0, 1))
        {
            DEBUG_MP("Chunk is busy");
            continue;
        };
        if (atomic_read(&chunk->free_space) > size + sizeof(struct vtss_memory_block))
        {
            struct vtss_memory_block* block =  vtss_find_free_block(chunk, size);
            if (block)
            {
                block_addr = (unsigned long)block + sizeof(struct vtss_memory_block);
            }
        }
        atomic_set(&chunk->busy, 0);
        if (block_addr > 0)
        {
            if (block_addr + size >= (unsigned long)chunk + chunk->size + sizeof(struct vtss_memchunk))
            {
                 DEBUG_MP("ERROR!!! chunk = %p, &chunk->memblocks = %lx, chunk->size = %zx, block_addr = %lx,size = %lx, memblock+size=%lx", chunk, (unsigned long)&chunk->memblocks, chunk->size, block_addr, size, (unsigned long)(&chunk->memblocks) + chunk->size);
                 vtss_free_block(block_addr, size);
                 block_addr = 0;
            }
            break;
        }
    }
    vtss_memchunk_list_read_unlock();
    
    DEBUG_MP("getting block size = %zu, found block_addr = %lx", size, block_addr);
    return block_addr;
}

void vtss_free_block(unsigned long block_addr, size_t size)
{
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;
    unsigned long addr = block_addr - sizeof(struct vtss_memory_block);

    DEBUG_MP("free addr = %lx, block_addr = %lx", addr, block_addr);
    vtss_memchunk_list_read_lock();
    list_for_each_safe(p, tmp, &g_memchunk_list)
    {
        struct vtss_memchunk* chunk = list_entry(p, struct vtss_memchunk, list);
        touch_nmi_watchdog();
        if (chunk == NULL)
        {
             ERROR("Chunk in list is NULL");
             continue;
        }
        if ((unsigned long)&chunk->memblocks[0] <= addr && addr < (unsigned long)chunk + sizeof(struct vtss_memchunk) + chunk->size)
        {
           struct vtss_memory_block* block = (struct vtss_memory_block*)(addr); // - offsetof(struct vtss_memory_block, memblock))
           struct vtss_memory_block* block_next = NULL;
           size_t removed_size = 0;
           do
           {
               DEBUG_MP("Block will be marked as free: %p, size = %zx",block, block->size );
               if (atomic_read(&block->is_free))
               {
                   ERROR("Freeing block several times, block = %p", block);
               }
               removed_size = removed_size + block->size + sizeof(struct vtss_memory_block);
               if (size > removed_size)
               {
                  DEBUG_MP("removing wrong size");
               }
               block_next = block->next;
               atomic_set(&block->is_free, 1);
               block = block_next;
           }
           while (block && size > removed_size);
           DEBUG_MP("removed_size = %zx", removed_size );
           atomic_add(removed_size, &chunk->free_space);
           break;
        }
    }
    vtss_memchunk_list_read_unlock();
    return;
}

static unsigned long vtss_try_get_free_block(gfp_t flags, size_t size, int cnt)
{
    void* block = NULL;
    if (flags != GFP_ATOMIC) //to avoid recursion
    {
        vtss_create_memchunk_async(flags, size+sizeof(struct vtss_memchunk)+sizeof(struct vtss_memory_block));
    }
    while (!block && (cnt--) > 0)
    {
        block = (void*)vtss_get_free_block(flags, size);
        DEBUG_MP("Cannot get block! trying again");
    }
    return (unsigned long) block;
}

unsigned long vtss_get_free_pages_internal(gfp_t gfp_mask, unsigned int order)
{
    unsigned long block = vtss_get_free_block(gfp_mask, PAGE_SIZE<<order);
    if (block == 0)
    {
        block = vtss_try_get_free_block(gfp_mask, PAGE_SIZE<<order, 3);
    }
    return block;
}

void vtss_free_pages_internal(unsigned long addr, unsigned int order)
{
   vtss_free_block(addr, PAGE_SIZE<<order);
   return;
}

unsigned long vtss_get_free_page_internal(gfp_t gfp_mask)
{
    return vtss_get_free_block(gfp_mask, PAGE_SIZE);
}

void vtss_free_page_internal(unsigned long addr)
{
   vtss_free_block(addr, PAGE_SIZE);
   return;
}

void* vtss_kmalloc_internal(size_t size, gfp_t flags)
{
    void* block = (void*)vtss_get_free_block(flags, size);
    if (!block)
    {
        DEBUG_MP("attempt to create async, flags = %x\n", (int)flags);
        block = (void*)vtss_try_get_free_block(flags, size, 1000);
    }
    return block;
}

void vtss_kfree_internal(const void * item)
{
    vtss_free_block((unsigned long) item, 0);
}
