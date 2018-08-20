/*[6~
  Copyright (C) 2010-2015 Intel Corporation.  All Rights Reserved.

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
#include "memory_pool.h"
#include "task_map.h"

#include <linux/jhash.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nmi.h>

#define VTSS_DEBUG_TASKMAP TRACE

#ifdef VTSS_CONFIG_REALTIME
static DEFINE_RAW_SPINLOCK(vtss_task_map_lock);
#else
static DEFINE_SPINLOCK(vtss_task_map_lock);
#endif

/* Should be 2^n */
#define HASH_TABLE_SIZE (1 << 10)

static struct hlist_head vtss_task_map_hash_table[HASH_TABLE_SIZE] = { {NULL} };
static atomic_t  vtss_map_initialized = ATOMIC_INIT(0);
/** Compute the map hash */
static inline u32 vtss_task_map_hash(pid_t key) __attribute__ ((always_inline));
static inline u32 vtss_task_map_hash(pid_t key)
{
    return (jhash_1word(key, 0) & (HASH_TABLE_SIZE - 1));
}

/**
 * Reclaim an item after grace period is expired.
 * Returns void.
 */
void vtss_task_map_reclaim_item(struct rcu_head *rp)
{
    vtss_task_map_item_t *item = container_of(rp, vtss_task_map_item_t, rcu);
    VTSS_DEBUG_TASKMAP("start, item = %p", item);
    if (atomic_read(&item->usage) == 0) {
        VTSS_DEBUG_TASKMAP("usage 0, item = %p", item);
        if (item->dtor)
            item->dtor(item, NULL);
        item->dtor = NULL;
        vtss_kfree(item);
    }
    VTSS_DEBUG_TASKMAP("end");
}

/**
 * Get an item if it's present in the hash table and increment its usage.
 * Returns NULL if not present.
 */
vtss_task_map_item_t* vtss_task_map_get_item(pid_t key)
{
    struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    struct hlist_node *node = NULL;
#endif
    vtss_task_map_item_t *item;
    if (atomic_read(&vtss_map_initialized)==0) return NULL;

    rcu_read_lock();
    head = &vtss_task_map_hash_table[vtss_task_map_hash(key)];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    hlist_for_each_entry_rcu(item, node, head, hlist)
#else
    hlist_for_each_entry_rcu(item, head,  hlist)
#endif
    {
        if (key == item->key) {
            if (atomic_read(&item->in_list)){
                atomic_inc(&item->usage);
            } else {
                item = NULL;
            }
            rcu_read_unlock();
            return item;
        }
    }
    rcu_read_unlock();
    return NULL;
}

/**
 * Decrement count and destroy if usage == 0.
 * Returns 1 if item was destroyed otherwise 0.
 */
int vtss_task_map_put_item(vtss_task_map_item_t* item)
{
    unsigned long flags;

    if ((item != NULL) && atomic_dec_and_test(&item->usage)) {
        //Here soebody can increment usage!
        if (atomic_read(&item->in_list)) {
            vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
            if (atomic_read(&item->in_list)) {
                VTSS_DEBUG_TASKMAP("removing from the list");
                atomic_set(&item->in_list, 0);
                hlist_del_init_rcu(&item->hlist);
            }
            vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
        }
        if (atomic_read(&item->usage) == 0) { // do not remove this check
            VTSS_DEBUG_TASKMAP("before call_rcu, item = %p",item );
            call_rcu(&item->rcu, vtss_task_map_reclaim_item);
            VTSS_DEBUG_TASKMAP("after call_rcu");
            return 1;
        }
    }

    return 0;
}

/**
 * Add the item into the hash table with incremented usage.
 * Remove the item with the same key.
 * Returns 1 if old item was destroyed otherwise 0.
 */
int vtss_task_map_add_item(vtss_task_map_item_t* item2)
{
    unsigned long flags;
    int replaced = 0;
    struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    struct hlist_node *node = NULL;
#endif
    struct hlist_node *temp = NULL;
    vtss_task_map_item_t *item = NULL;

    if ((item2 != NULL) && !atomic_read(&item2->in_list)) {
        vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
        if (!atomic_read(&item2->in_list))
        {
            head = &vtss_task_map_hash_table[vtss_task_map_hash(item2->key)];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
            hlist_for_each_entry_safe(item, node, temp, head, hlist)
#else
            hlist_for_each_entry_safe(item, temp, head, hlist)
#endif
            {
                if (item2->key == item->key) {
                    /* already there, replace it */
                    atomic_set(&item->in_list, 0);
                    atomic_inc(&item2->usage);
                    hlist_replace_rcu(&item->hlist, &item2->hlist);
                    atomic_set(&item2->in_list, 1);
                    if (atomic_read(&item->usage) != 0) {
                        if (atomic_dec_and_test(&item->usage)) {
                            VTSS_DEBUG_TASKMAP("before call_rcu, item = %p",item );
                            call_rcu(&item->rcu, vtss_task_map_reclaim_item);
                            VTSS_DEBUG_TASKMAP("after call_rcu");
                        }
                    }
                    replaced = 1;
                    break;
                }
            }
            if (!replaced) {
                atomic_inc(&item2->usage);
                hlist_add_head_rcu(&item2->hlist, head);
                atomic_set(&item2->in_list, 1);
            }
        }
        vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
    }
    return replaced;
}

/**
 * Remove the item from the hash table and destroy if usage == 0.
 * Returns 1 if item was destroyed otherwise 0.
 */
int vtss_task_map_del_item(vtss_task_map_item_t* item)
{
    unsigned long flags;

    if (item != NULL) {
        if (atomic_read(&item->in_list)) {
            vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
            if (atomic_read(&item->in_list)) {
                atomic_set(&item->in_list, 0);
                hlist_del_init_rcu(&item->hlist);
            }
            vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
        }
        if (atomic_dec_and_test(&item->usage)) {
            VTSS_DEBUG_TASKMAP("before call_rcu, item = %p",item );
            call_rcu(&item->rcu, vtss_task_map_reclaim_item);
            VTSS_DEBUG_TASKMAP("after call_rcu");
            return 1;
        }
    }
    return 0;
}

/**
 * allocate item + data but not insert it into the hash table, usage = 1
 */
vtss_task_map_item_t* vtss_task_map_alloc(pid_t key, size_t size, vtss_task_map_func_t* dtor, gfp_t flags)
{
    vtss_task_map_item_t *item = NULL;
    
    if (atomic_read(&vtss_map_initialized) == 0)
        return NULL;
    item = (vtss_task_map_item_t*)vtss_kmalloc(sizeof(vtss_task_map_item_t) + size, flags);
    if (item != NULL) {
        memset(item, 0, sizeof(vtss_task_map_item_t) + size);
        atomic_set(&item->usage, 1);
        item->key     = key;
        atomic_set(&item->in_list,0);
        item->dtor    = dtor;
    }
    return item;
}

int vtss_task_map_foreach(vtss_task_map_func_t* func, void* args)
{
    int i;
    struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    struct hlist_node *node = NULL;
#endif
    vtss_task_map_item_t *item;

    if (func == NULL) {
        ERROR("Function pointer is NULL");
        return -EINVAL;
    }
    rcu_read_lock();
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        head = &vtss_task_map_hash_table[i];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
        hlist_for_each_entry_rcu(item, node, head, hlist)
#else
        hlist_for_each_entry_rcu(item, head, hlist)
#endif
        {
            func(item, args);
        }
    }
    rcu_read_unlock();
    return 0;
}

int vtss_task_map_init(void)
{
    int i;
    unsigned long flags;
    struct hlist_head *head;

    vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        head = &vtss_task_map_hash_table[i];
        INIT_HLIST_HEAD(head);
    }
    vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
    synchronize_rcu();
    
    atomic_set(&vtss_map_initialized,1);

    return 0;
}

void vtss_task_map_fini(void)
{
    int i;
    unsigned long flags;
    struct hlist_head *head;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    struct hlist_node *node = NULL;
#endif
    struct hlist_node *temp = NULL;
    vtss_task_map_item_t *item = NULL;

    atomic_set(&vtss_map_initialized,0);
    vtss_spin_lock_irqsave(&vtss_task_map_lock, flags);
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        head = &vtss_task_map_hash_table[i];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
        hlist_for_each_entry_safe(item, node, temp, head, hlist)
#else
        hlist_for_each_entry_safe(item, temp, head, hlist)
#endif
        {
            atomic_set(&item->in_list, 0);
            hlist_del_init_rcu(&item->hlist);
            if (atomic_read(&item->usage) != 0) {
                if (atomic_dec_and_test(&item->usage)) {
                    VTSS_DEBUG_TASKMAP("before call_rcu, item = %p", item);
                    call_rcu(&item->rcu, vtss_task_map_reclaim_item);
                    VTSS_DEBUG_TASKMAP("after call_rcu");
                }
            }
        }
        INIT_HLIST_HEAD(head);
    }
    vtss_spin_unlock_irqrestore(&vtss_task_map_lock, flags);
    synchronize_rcu();
}
