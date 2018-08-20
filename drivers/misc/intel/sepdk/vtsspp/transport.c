/*
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
#include "transport.h"
#include "procfs.h"
#include "globals.h"
#include "memory_pool.h"
#ifdef VTSS_USE_UEC
#include "uec.h"
#else
#include <linux/ring_buffer.h>
#include <asm/local.h>
#endif

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/delay.h>        /* for msleep_interruptible() */
#include <linux/fs.h>           /* for struct file_operations */
#include <linux/namei.h>        /* for struct nameidata       */
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/nmi.h>

#include "vtsstrace.h"
#include "time.h"
#define DEBUG_TR TRACE

#ifndef VTSS_MERGE_MEM_LIMIT
#define VTSS_MERGE_MEM_LIMIT 0x200 /* max pages allowed */
#endif

/* Define this to wake up transport by timeout */
/* transprot timer interval in jiffies  (default 10ms) */
#define VTSS_TRANSPORT_TIMER_INTERVAL   (10 * HZ / 1000)
#define VTSS_TRANSPORT_COMPLETE_TIMEOUT 10000 /*< wait count about 100sec */

#ifdef CONFIG_X86_64
#define VTSS_ALLOC_BUFSIZE_MAX 0x10000000L
#else
#define VTSS_ALLOC_BUFSIZE_MAX 0x2000000L
#endif

#define VTSS_PREALLOC_TR_SIZE 5

#ifndef VTSS_USE_UEC

struct vtss_transport_entry
{
    unsigned long  seqnum;
    unsigned short size;
    unsigned long  rb_start;
    unsigned long long  cputsc; //record creation time
    char           data[0];
};

struct vtss_transport_temp
{
    struct vtss_transport_temp* prev;
    struct vtss_transport_temp* next;
    unsigned long seq_begin;
    unsigned long seq_end;
    size_t        size;
    unsigned int  order;
    char          data[0];
};

/* The value was gotten from the kernel's ring_buffer code. */
#define VTSS_RING_BUFFER_PAGE_SIZE      4080
#define VTSS_TRANSPORT_MAX_RESERVE_SIZE (VTSS_RING_BUFFER_PAGE_SIZE - \
                                        sizeof(struct ring_buffer_event) - \
                                        sizeof(struct vtss_transport_entry) - 64)
#define VTSS_TRANSPORT_IS_EMPTY(trnd)   (1 + (atomic_read(&trnd->seqnum) - atomic_read(&trnd->seqdone)) == 0)
#define VTSS_TRANSPORT_DATA_READY(trnd) (1 + atomic_read(&trnd->commited) - atomic_read(&trnd->seqdone) > 0/*VTSS_MERGE_MEM_LIMIT/4 || atomic_read(&trnd->is_overflow)*/)

struct rb_page
{
    u64     ts;
    local_t commit;
    char    data[VTSS_RING_BUFFER_PAGE_SIZE];
};


#endif /* VTSS_USE_UEC */


#define VTSS_RB_STEP 0x1000
#define VTSS_RB_MASK (VTSS_RB_STEP-1)
#define VTSS_RB_MARK(num)(num - (num&VTSS_RB_MASK)+ VTSS_RB_STEP)

extern int uid;
extern int gid;
extern int mode;

static struct timer_list vtss_transport_timer;

#ifdef VTSS_CONFIG_REALTIME
static DEFINE_RAW_SPINLOCK(vtss_transport_list_lock);
#else
static DEFINE_SPINLOCK(vtss_transport_list_lock);
#endif
static LIST_HEAD(vtss_transport_list);
static atomic_t vtss_free_tr_cnt = ATOMIC_INIT(0);
static atomic_t vtss_transport_mode = ATOMIC_INIT(VTSS_TR_MODE_REG);
static atomic_t vtss_transport_npages = ATOMIC_INIT(0);
static atomic_t vtss_is_transport_init = ATOMIC_INIT(0);
static atomic_t vtss_kernel_task_in_progress = ATOMIC_INIT(0);
static atomic_t vtss_ring_buffer_stopped = ATOMIC_INIT(0);
static atomic_t vtss_ring_buffer_paused = ATOMIC_INIT(0);

void vtss_transport_start_ring_bufer(void)
{
    atomic_set(&vtss_ring_buffer_stopped, 0);
}

void vtss_transport_stop_ring_bufer(void)
{
    atomic_set(&vtss_ring_buffer_stopped, 1);
}

void vtss_transport_resume_ring_bufer(void)
{
    atomic_set(&vtss_ring_buffer_paused, 0);
}

void vtss_transport_pause_ring_bufer(void)
{
    atomic_set(&vtss_ring_buffer_paused, 1);
}

#define VTSS_TR_REG    0x1
#define VTSS_TR_CFG    0x2 /* aux */
#define VTSS_TR_RB     0x4 /* ring buffer */

#if defined(__i386__)
#define VTSS_UEC_CHAIN_SIZE 16
#else
#define VTSS_UEC_CHAIN_SIZE 32
#endif

#define VTSS_TRANSPORT_COPY_TO_USER(src, len) do { \
    if (buf){ \
        if (copy_to_user(buf, (void*)(src), (len))) { \
            ERROR("copy_to_user(0x%p, 0x%p, %zu): error", buf, (src), (len)); \
        } \
        size -= (len); \
        buf += (len); \
    } \
    rc += (len); \
} while (0)

struct vtss_transport_data
{
    struct list_head    list;
    struct file*        file;
    wait_queue_head_t   waitq;
    char                name[36];    /* enough for "%d-%d.%d.aux" */

    atomic_t            refcount;
    atomic_t            loscount;
    atomic_t            is_attached;
    atomic_t            is_complete;
    atomic_t            is_overflow;

    atomic_t            reserved;

    atomic_t            seqdone;
    atomic_t            rb_mark;
    int                 magic;

#ifdef VTSS_USE_UEC
    uec_t*              uec;
    uec_t uec_chain[VTSS_UEC_CHAIN_SIZE];
#else
    struct vtss_transport_temp* head;

    struct ring_buffer* buffer;

    unsigned long       seqcpu[NR_CPUS];
    atomic_t            seqnum;
    atomic_t            commited;
    int                 is_abort;

    atomic_t            locked_size_cpu[NR_CPUS];
    int       ring_buffer_size;
    //0 - writing
    //1 - clearning
    //2 - reading
    atomic_t processing_state;

    unsigned long long bufcputsc;
#endif
    int type;
};

void vtss_transport_addref(struct vtss_transport_data* trnd)
{
    atomic_inc(&trnd->refcount);
}

int vtss_transport_delref(struct vtss_transport_data* trnd)
{
    return atomic_dec_return(&trnd->refcount);
}

char *vtss_transport_get_filename(struct vtss_transport_data* trnd)
{
    return trnd->name;
}

int vtss_transport_is_overflowing(struct vtss_transport_data* trnd)
{
    return atomic_read(&trnd->is_overflow);
}
int vtss_transport_is_attached(struct vtss_transport_data* trnd)
{
    return atomic_read(&trnd->is_attached);
}
int vtss_transport_is_ready(struct vtss_transport_data* trnd)
{
    /*if (atomic_read(&trnd->is_complete)) {
        TRACE("Transport is COMPLETED");
        return 0;
    }
    return (trnd->seqdone > 1 || waitqueue_active(&trnd->waitq));*/
    return atomic_read(&trnd->is_attached);
}

#if 0
#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_transport_data_wake_up_work(struct work_struct *work)
#else
static void vtss_transport_data_wake_up_work(void *work)
#endif
{
    struct vtss_work* my_work = (struct vtss_work*)work;
    struct vtss_transport_data* trnd = NULL;

    if (!my_work){
        ERROR("empty work!");
        return;
    }
    if (atomic_read(&vtss_is_transport_init) == 0)
    {
        vtss_kfree(my_work);
        return;
    }
    
    trnd = *((struct vtss_transport_data**)(&my_work->data));

    if (atomic_read(&trnd->is_attached) == 0) 
    {
        vtss_kfree(my_work);
        return;
    }

    if (atomic_read(&trnd->is_complete))
    {
        vtss_kfree(my_work);
        return;
    }


    if (trnd->type & VTSS_TR_RB)
    {
        vtss_kfree(my_work);
        return;
    }

    
    while (!waitqueue_active(&trnd->waitq))
    {
        msleep_interruptible(10);
        if (atomic_read(&vtss_is_transport_init) == 0)
        {
           vtss_kfree(my_work);
           return;
        }
    }

    wake_up_interruptible(&trnd->waitq);
    
    vtss_kfree(my_work);
}
#endif

#ifdef VTSS_USE_UEC

void vtss_transport_callback(uec_t* uec, int reason, void *context)
{
    TRACE("context=0x%p, reason=%d", context, reason);
}

#define UEC_FREE_SIZE(uec) \
({ (uec->tail <= uec->head) ? \
        uec->hsize - (size_t)(uec->head - uec->tail) \
    : \
        (size_t)(uec->tail - uec->head); \
})

#define UEC_FILLED_SIZE(uec) \
({  size_t tsize = 0; \
    if (uec->head > uec->tail) { \
        tsize = (size_t)(uec->head - uec->tail); \
    } else if (uec->head < uec->tail || (uec->head == uec->tail && uec->ovfl)) { \
        tsize = (size_t)(uec->tsize - (uec->tail - uec->buffer)); \
    } \
    tsize; \
})

#define VTSS_TRANSPORT_IS_EMPTY(trnd)   (UEC_FILLED_SIZE(trnd->uec) == 0)
#define VTSS_TRANSPORT_DATA_READY(trnd) (UEC_FILLED_SIZE(trnd->uec) != 0)
 
int vtss_transport_record_write(struct vtss_transport_data* trnd, void* part0, size_t size0, void* part1, size_t size1, int is_safe)
{
    int rc = 0;

    if (trnd == NULL) {
        ERROR("Transport is NULL");
        return -EINVAL;
    }

    if (atomic_read(&trnd->is_complete)) {
        ERROR("Transport is COMPLETED");
        return -EINVAL;
    }

    /* Don't use spill notifications from uec therefore its UECMODE_SAFE always */
    if (trnd->type & VTSS_TR_RB) {
        rc = trnd->uec_chain->put_record(trnd->uec_chain, part0, size0, part1, size1, UECMODE_SAFE);
    } else {
        rc = trnd->uec->put_record(trnd->uec, part0, size0, part1, size1, UECMODE_SAFE);

#ifndef VTSS_USE_NMI
        if (is_safe) {
            DEBUG_TR("WAKE UP");
            if (waitqueue_active(&trnd->waitq))
                wake_up_interruptible(&trnd->waitq);
        }
#endif
    }
    if (rc) {
        atomic_inc(&trnd->loscount);
    }
    return rc;
}

#else  /* VTSS_USE_UEC */

static void vtss_transport_temp_free_all(struct vtss_transport_data* trnd, struct vtss_transport_temp** head)
{
    struct vtss_transport_temp* temp;
    struct vtss_transport_temp** pstore = head;

    while ((temp = *pstore) != NULL) {
        if (temp->prev) {
            pstore = &(temp->prev);
            continue;
        }
        if (temp->next) {
            pstore = &(temp->next);
            continue;
        }
        TRACE("'%s' [%lu, %lu), size=%zu of %lu",
                trnd->name, temp->seq_begin, temp->seq_end,
                temp->size, (PAGE_SIZE << temp->order));
        {
            unsigned int temp_order = temp->order;
            vtss_free_pages((unsigned long)temp, temp->order);
            atomic_sub(1<<temp_order, &vtss_transport_npages);
        }
        *pstore = NULL;
        pstore = head; /* restart from head */
    }
}

static struct vtss_transport_temp* vtss_transport_temp_merge(struct vtss_transport_data* trnd, struct vtss_transport_temp** pstore)
{
    struct vtss_transport_temp* temp = *pstore;

    if (temp != NULL) {
        struct vtss_transport_temp* prev = temp->prev;
        struct vtss_transport_temp* next = temp->next;

        /* try to merge with prev element... */
        if (prev != NULL && (prev->seq_end == temp->seq_begin) && ((VTSS_RB_MASK&temp->seq_begin) != 1)&&
            /* check for enough space in buffer */
            ((prev->size + temp->size + sizeof(struct vtss_transport_temp)) < (PAGE_SIZE << prev->order)))
        {
            TRACE("'%s' [%lu - %lu), size=%zu <+ [%lu - %lu), size=%zu", trnd->name,
                prev->seq_begin, prev->seq_end, prev->size,
                temp->seq_begin, temp->seq_end, temp->size);
            memcpy(&(prev->data[prev->size]), temp->data, temp->size);
            prev->size += temp->size;
            prev->seq_end = temp->seq_end;
            if (prev->next) {
                ERROR("'%s' [%lu, %lu) incorrect next link", trnd->name,
                        prev->seq_begin, prev->seq_end);
                vtss_transport_temp_free_all(trnd, &(prev->next));
            }
            prev->next = temp->next;
            *pstore = prev;
            {
                unsigned int temp_order = temp->order;
                vtss_free_pages((unsigned long)temp, temp->order);
                atomic_sub(1<<temp_order, &vtss_transport_npages);
            }
            return prev;
        }
        /* try to merge with next element... */
        if (next != NULL && (next->seq_begin == temp->seq_end) && ((VTSS_RB_MASK&next->seq_begin) != 1)&&
            /* check for enough space in buffer */
            ((next->size + temp->size + sizeof(struct vtss_transport_temp)) < (PAGE_SIZE << temp->order)))
        {
            TRACE("'%s' [%lu - %lu), size=%zu +> [%lu - %lu), size=%zu", trnd->name,
                temp->seq_begin, temp->seq_end, temp->size,
                next->seq_begin, next->seq_end, next->size);
            memcpy(&(temp->data[temp->size]), next->data, next->size);
            temp->size += next->size;
            temp->seq_end = next->seq_end;
            temp->next = next->next;
            if (next->prev) {
                ERROR("'%s' [%lu, %lu) incorrect prev link", trnd->name,
                        next->seq_begin, next->seq_end);
                vtss_transport_temp_free_all(trnd, &(next->prev));
            }
            {
                unsigned int next_order = next->order;
                vtss_free_pages((unsigned long)next, next->order);
                atomic_sub(1<<next_order, &vtss_transport_npages);
            }
            return temp;
        }
    }
    return temp;
}

static int vtss_transport_temp_store_data(struct vtss_transport_data* trnd, unsigned long seqnum, void* data, unsigned short size)
{
    struct vtss_transport_temp* temp = NULL;
    struct vtss_transport_temp** pstore = &(trnd->head);
    unsigned int order = get_order(size + sizeof(struct vtss_transport_temp));

    while (((temp = vtss_transport_temp_merge(trnd, pstore)) != NULL) && (seqnum != temp->seq_end)) {
        TRACE("0: '%s' new [%lu - %lu), size=%u", trnd->name, seqnum, seqnum + 1, size);
        pstore = (seqnum < temp->seq_begin) ? &(temp->prev) : &(temp->next);
    }
    if (temp == NULL) {
        struct vtss_transport_temp* temp1;
        struct vtss_transport_temp** pstore1 = &(trnd->head);
        while (((temp1 = *pstore1) != NULL) && ((seqnum + 1) != temp1->seq_begin)) {
            pstore1 = (seqnum < temp1->seq_begin) ? &(temp1->prev) : &(temp1->next);
        }
        if (temp1 != NULL) { /* try to prepend */
            /* check for enough space in buffer */
            if ((temp1->size + size + sizeof(struct vtss_transport_temp)) < (PAGE_SIZE << temp1->order) && (VTSS_RB_MASK&seqnum) != 1) {
                TRACE("1: '%s' [%lu - %lu), size=%u +> [%lu - %lu), size=%zuv",
                        trnd->name, seqnum, seqnum + 1, size,
                        temp1->seq_begin, temp1->seq_end, temp1->size);
                memmove(&(temp1->data[size]), temp1->data, temp1->size);
                memcpy(temp1->data, data, size);
                temp1->seq_begin = seqnum;
                temp1->size += size;
                vtss_transport_temp_merge(trnd, pstore1);
                return 0;
            }
        }
        TRACE("2: '%s' new [%lu - %lu), size=%u", trnd->name, seqnum, seqnum + 1, size);
        temp = (struct vtss_transport_temp*)vtss_get_free_pages(GFP_NOWAIT, order);
        if (temp == NULL) {
            return -ENOMEM;
        }
        atomic_add(1<<order, &vtss_transport_npages);
        temp->prev  = NULL;
        temp->next  = NULL;
        temp->seq_begin = seqnum;
        temp->size  = 0;
        temp->order = order;
        if (*pstore) {
            ERROR("'%s' new [%lu - %lu), size=%u ==> [%lu - %lu)", trnd->name,
                    seqnum, seqnum + 1, size, (*pstore)->seq_begin, (*pstore)->seq_end);
        }
        *pstore = temp;
    } else {
        /* check for enough space in buffer */
        if ((temp->size + size + sizeof(struct vtss_transport_temp)) >= (PAGE_SIZE << temp->order) || (VTSS_RB_MASK&seqnum) == 1) {
            struct vtss_transport_temp* next;
            TRACE("3: '%s' new [%lu - %lu), size=%u, temp->size=%zu", trnd->name,
                    seqnum, seqnum + 1, size, temp->size);
            next = (struct vtss_transport_temp*)vtss_get_free_pages(GFP_NOWAIT, order);
            if (next == NULL) {
                return -ENOMEM;
            }
            atomic_add(1<<order, &vtss_transport_npages);
            next->prev  = NULL;
            next->next  = temp->next;
            next->seq_begin = seqnum;
            next->size  = 0;
            next->order = order;
            temp->next  = next;
            pstore = &(temp->next);
            temp = next;
        } else {
            TRACE("4:'%s' [%lu - %lu), size=%zu <+ [%lu - %lu), size=%u", trnd->name,
                    temp->seq_begin, temp->seq_end, temp->size,
                    seqnum, seqnum + 1, size);
        }
    }
    memcpy(&(temp->data[temp->size]), data, size);
    temp->seq_end = seqnum + 1;
    temp->size += size;
    vtss_transport_temp_merge(trnd, pstore);
    return 0;
}

static int vtss_transport_temp_store_blob(struct vtss_transport_data* trnd, unsigned long seqnum, struct vtss_transport_temp* blob)
{
    struct vtss_transport_temp* temp;
    struct vtss_transport_temp** pstore = &(trnd->head);

    TRACE("'%s' blob [%lu - %lu), size=%zu", trnd->name, seqnum, seqnum + 1, blob->size);
    while (((temp = vtss_transport_temp_merge(trnd, pstore)) != NULL) && (seqnum != temp->seq_end)) {
        pstore = (seqnum < temp->seq_begin) ? &(temp->prev) : &(temp->next);
    }
    blob->prev      = NULL;
    blob->seq_begin = seqnum;
    blob->seq_end   = seqnum + 1;
    if (temp == NULL) {
        blob->next = NULL;
        if (*pstore) {
            ERROR("'%s' blob [%lu - %lu), size=%zu ==> [%lu - %lu)", trnd->name,
                    seqnum, seqnum + 1, blob->size, (*pstore)->seq_begin, (*pstore)->seq_end);
        }
        *pstore = blob;
    } else {
        blob->next = temp->next;
        temp->next = blob;
    }
    return 0;
}

static size_t vtss_transport_temp_flush(struct vtss_transport_data* trnd, char __user* buf, size_t size, int max_seqdone)
{
    size_t rc = 0;

    if (!trnd->is_abort) {
        struct vtss_transport_temp* temp;
        struct vtss_transport_temp** pstore = &(trnd->head);

        TRACE("'%s' -== flush begin ==- :: %d (%d bytes) at seq=%d", trnd->name,
                atomic_read(&vtss_transport_npages), (int)(atomic_read(&vtss_transport_npages)*PAGE_SIZE), atomic_read(&trnd->seqdone));
        /* Look for output seq with merge on the way */
        while ((temp = vtss_transport_temp_merge(trnd, pstore)) != NULL) {
            if (atomic_read(&trnd->seqdone) == temp->seq_begin) {
                if (buf && (size < temp->size))
                    break;
                TRACE("'%s' output [%lu, %lu), size=%zu", trnd->name,
                        temp->seq_begin, temp->seq_end, temp->size);
                if (max_seqdone > 0 && temp->seq_begin > max_seqdone){
                    DEBUG_TR("flush stopped, temp->seq_begin = %d, maxseqdone = %d", (int)temp->seq_begin, max_seqdone);
                    break;
                }
                VTSS_TRANSPORT_COPY_TO_USER(temp->data, temp->size);
                atomic_set(&trnd->seqdone,temp->seq_end);
                *pstore = temp->next;
                if (temp->prev) {
                    ERROR("'%s' [%lu, %lu) incorrect prev link", trnd->name, temp->seq_begin, temp->seq_end);
                    vtss_transport_temp_free_all(trnd, &(temp->prev));
                }
                {
                    unsigned int temp_order = temp->order;
                    DEBUG_TR("temp = %p, temp->next = %p, *pstore = %p", temp, temp->next, *pstore);
                    vtss_free_pages((unsigned long)temp, temp->order);
                    atomic_sub(1<<temp_order, &vtss_transport_npages);
                }
                pstore = &(trnd->head); /* restart from head */
            } else {
                pstore = (atomic_read(&trnd->seqdone) < temp->seq_begin) ? &(temp->prev) : &(temp->next);
            }
        }
        TRACE("'%s' -== flush  end  ==- :: %d (%d bytes) at seq=%d", trnd->name,
                atomic_read(&vtss_transport_npages), (int)(atomic_read(&vtss_transport_npages)*PAGE_SIZE), atomic_read(&trnd->seqdone));
    }
    return rc;
}

static size_t vtss_transport_temp_parse_event(struct vtss_transport_data* trnd, struct ring_buffer_event* event, char __user* buf, size_t size, int cpu)
{
    size_t rc = 0;
    struct vtss_transport_entry* data = (struct vtss_transport_entry*)ring_buffer_event_data(event);
    unsigned long seqnum = data->seqnum;

    atomic_sub(data->size + sizeof(struct vtss_transport_entry), &trnd->locked_size_cpu[cpu]);
    trnd->seqcpu[cpu] = seqnum;
    if (trnd->is_abort || atomic_read(&trnd->seqdone) > seqnum) {
        if (data->size) {
            DEBUG_TR("DROP seqdone=%d, seq=%lu, size=%u, from cpu%d", atomic_read(&trnd->seqdone), seqnum, data->size, cpu);
        } else { /* blob */
            struct vtss_transport_temp* blob = *((struct vtss_transport_temp**)(data->data));
            unsigned int blob_order;
            DEBUG_TR("DROP seq=%lu, size=%zu, from cpu%d", seqnum, blob->size, cpu);
            blob_order = blob->order;
            vtss_free_pages((unsigned long)blob, blob->order);
            atomic_sub(1<<blob_order, &vtss_transport_npages);
    }
#ifndef VTSS_NO_MERGE
    } else if (atomic_read(&trnd->seqdone) != seqnum) { /* disordered event */
        if (data->size) {
            if (vtss_transport_temp_store_data(trnd, seqnum, data->data, data->size)) {
                ERROR("'%s' seq=%d => store data seq=%lu error", trnd->name,atomic_read(&trnd->seqdone), seqnum);
            }
        } else { /* blob */
            struct vtss_transport_temp* blob = *((struct vtss_transport_temp**)(data->data));
             if (vtss_transport_temp_store_blob(trnd, seqnum, blob)) {
                ERROR("'%s' seq=%d => store blob seq=%lu error", trnd->name, (int)atomic_read(&trnd->seqdone), seqnum);
            }
        }
#endif
    } else { /* ordered event */
        if (data->size) {
            TRACE("'%s' output [%lu - %lu), size=%u from cpu%d", trnd->name, seqnum, seqnum+1, data->size, cpu);
#ifndef VTSS_NO_MERGE
            if (buf && (size < data->size)) {
                if (vtss_transport_temp_store_data(trnd, seqnum, data->data, data->size)) {
                    ERROR("'%s' seq=%d => store data seq=%lu error", trnd->name, atomic_read(&trnd->seqdone), seqnum);
                }
            } else
#endif
            {
                VTSS_TRANSPORT_COPY_TO_USER(data->data, (size_t)data->size);
                atomic_inc(&trnd->seqdone);
            }
        } else { /* blob */
            struct vtss_transport_temp* blob = *((struct vtss_transport_temp**)(data->data));
            TRACE("'%s' output [%lu - %lu), size=%zu from cpu%d", trnd->name, seqnum, seqnum+1, blob->size, cpu);
#ifndef VTSS_NO_MERGE
            if (buf && (size < blob->size)) {
                if (vtss_transport_temp_store_blob(trnd, seqnum, blob)) {
                    ERROR("'%s' seq=%d => store blob seq=%lu error", trnd->name, atomic_read(&trnd->seqdone), seqnum);
                }
            } else
#endif
            {
                unsigned int blob_order;
                VTSS_TRANSPORT_COPY_TO_USER(blob->data,
#ifndef VTSS_NO_MERGE
                    blob->size
#else
                    (size_t)8UL /* FIXME: just something is not overflowed output buffer */
#endif
                );
                blob_order = blob->order;
                DEBUG_TR("remove blob = %p", blob);
                vtss_free_pages((unsigned long)blob, blob->order);
                atomic_sub(1<<blob_order, &vtss_transport_npages);
                atomic_inc(&trnd->seqdone);

            }
        }
    }
    return rc;
}

static ssize_t vtss_transport_read_rb(struct vtss_transport_data* trnd, char __user* buf, size_t size)
{
    int i, cpu;
    size_t len;
    ssize_t rc = 0;

    for (i = 0;
        (i < 30) && /* no more 30 loops on each online cpu */
        (size >= VTSS_RING_BUFFER_PAGE_SIZE) && /* while buffer size is enough */
        !VTSS_TRANSPORT_IS_EMPTY(trnd) /* have something to output */
        ; i++)
    {
        int fast = 1;
        void* bpage;
        struct ring_buffer_event *event;
        unsigned long seqdone = (unsigned long)atomic_read(&trnd->seqdone);

        for_each_online_cpu(cpu) {
#ifndef VTSS_NO_MERGE
            /* Flush buffers if possible first of all */
            len = vtss_transport_temp_flush(trnd, buf, size, -1);
            size -= len;
            buf += len;
            rc += len;
#endif
            if (ring_buffer_entries_cpu(trnd->buffer, cpu) == 0)
                continue; /* nothing to read on this cpu */
            DEBUG_TR("cpu = %d, seqcpu(cpu) = %d, seqdone = %d, locked_size=%d", cpu,(int)trnd->seqcpu[cpu], (int)seqdone, atomic_read(&trnd->locked_size_cpu[cpu]) );
            if  (trnd->seqcpu[cpu] > seqdone &&
                (((1 + trnd->seqcpu[cpu] - seqdone) > VTSS_MERGE_MEM_LIMIT/3 &&
                !trnd->is_abort && !atomic_read(&trnd->is_complete)) || (atomic_read(&vtss_transport_npages) > VTSS_MERGE_MEM_LIMIT)))
            {
                DEBUG_TR("'%s' cpu%d=%lu :: %u (%lu bytes) at seq=%lu", trnd->name,
                        cpu, trnd->seqcpu[cpu], atomic_read(&vtss_transport_npages), atomic_read(&vtss_transport_npages)*PAGE_SIZE, seqdone);
                continue; /* skip it for a while */
            }
            if (atomic_read(&vtss_transport_npages) > VTSS_MERGE_MEM_LIMIT/2) {
                DEBUG_TR("'%s' cpu%d=%lu :: %u (%lu bytes) at seq=%lu", trnd->name,
                        cpu, trnd->seqcpu[cpu], atomic_read(&vtss_transport_npages), atomic_read(&vtss_transport_npages)*PAGE_SIZE, seqdone);
                fast = 0; // Carefully get events to avoid memory overflow
            }
#ifdef VTSS_AUTOCONF_RING_BUFFER_ALLOC_READ_PAGE
            bpage = ring_buffer_alloc_read_page(trnd->buffer, cpu);
#else
            bpage = ring_buffer_alloc_read_page(trnd->buffer);
#endif
            if (bpage == NULL) {
                ERROR("'%s' cannot allocate free rb read page", trnd->name);
                return -EFAULT;
            }
            if (fast && ring_buffer_read_page(trnd->buffer, &bpage, PAGE_SIZE, cpu, (!trnd->is_abort && !atomic_read(&trnd->is_complete))) >= 0) {
                int i, inc;
                struct rb_page* rpage = (struct rb_page*)bpage;
                /* The commit may have missed event flags set, clear them */
                unsigned long commit = local_read(&rpage->commit) & 0xfffff;

                TRACE("page[%d]=[0 - %4lu) :: rc=%zd, size=%zu", cpu, commit, rc, size);
                for (i = 0; i < commit; i += inc) {
                    if (i >= (PAGE_SIZE - offsetof(struct rb_page, data))) {
                        ERROR("'%s' incorrect data index", trnd->name);
                        break;
                    }
                    inc = -1;
                    event = (void*)&rpage->data[i];
                    switch (event->type_len) {
                    case RINGBUF_TYPE_PADDING:
                        /* failed writes or may be discarded events */
                        inc = event->array[0] + 4;
                        break;
                    case RINGBUF_TYPE_TIME_EXTEND:
                        inc = 8;
                        break;
                    case RINGBUF_TYPE_TIME_STAMP:
                        inc = 16;
                        break;
                    case 0:
                        len = vtss_transport_temp_parse_event(trnd, event, buf, size, cpu);
                        size -= len;
                        buf += len;
                        rc += len;
                        if (!event->array[0]) {
                            ERROR("'%s' incorrect event data", trnd->name);
                            break;
                        }
                        inc = event->array[0] + 4;
                        break;
                    default:
                       if (event->type_len <= RINGBUF_TYPE_DATA_TYPE_LEN_MAX){
                            len = vtss_transport_temp_parse_event(trnd, event, buf, size, cpu);
                            size -= len;
                            buf += len;
                            rc += len;
                            inc = ((event->type_len + 1) * 4);
                        }
                    }
                    if (inc <= 0) {
                        ERROR("'%s' incorrect next data index", trnd->name);
                        break;
                    }
                } /* for each event in page */
                TRACE("page[%d] -==end==-  :: rc=%zd, size=%zu", cpu, rc, size);
            } else { /* reader page is not full of careful, so read one by one */
                u64 ts;
                int count;

                for (count = 0; count < 10 && NULL !=
#ifdef VTSS_AUTOCONF_RING_BUFFER_LOST_EVENTS
                    (event = ring_buffer_peek(trnd->buffer, cpu, &ts, NULL))
#else
                    (event = ring_buffer_peek(trnd->buffer, cpu, &ts))
#endif
                    ; count++)
                {
                    struct vtss_transport_entry* data = (struct vtss_transport_entry*)ring_buffer_event_data(event);

                    trnd->seqcpu[cpu] = data->seqnum;
                    if ((1 + trnd->seqcpu[cpu] - seqdone) > VTSS_MERGE_MEM_LIMIT/4 &&
                        !trnd->is_abort && !atomic_read(&trnd->is_complete))
                    {
                        break; /* will not read this event */
                    }
#ifdef VTSS_AUTOCONF_RING_BUFFER_LOST_EVENTS
                    event = ring_buffer_consume(trnd->buffer, cpu, &ts, NULL);
#else
                    event = ring_buffer_consume(trnd->buffer, cpu, &ts);
#endif
                    if (event != NULL) {
                        len = vtss_transport_temp_parse_event(trnd, event, buf, size, cpu);
                        size -= len;
                        buf += len;
                        rc += len;
                    }
                } /* for */
            }
#ifdef VTSS_AUTOCONF_RING_BUFFER_FREE_READ_PAGE
            ring_buffer_free_read_page(trnd->buffer, cpu, bpage);
#else
            ring_buffer_free_read_page(trnd->buffer, bpage);
#endif
#ifndef VTSS_NO_MERGE
            /* Flush buffers if possible */
            len = vtss_transport_temp_flush(trnd, buf, size, -1);
            size -= len;
            buf += len;
            rc += len;
#endif
            if (size < VTSS_RING_BUFFER_PAGE_SIZE) {
                TRACE("'%s' read %zd bytes [%d]...", trnd->name, rc, i);
                return rc;
            }
        } /* for each online cpu */
    } /* while have something to output */
    if (rc == 0 && !trnd->is_abort && !atomic_read(&trnd->is_complete)) { /* !!! something wrong !!! */
        ERROR("'%s' [%d] rb=%lu :: %u (%lu bytes) evtstore=%d of %d", trnd->name, i,
                ring_buffer_entries(trnd->buffer), atomic_read(&vtss_transport_npages), atomic_read(&vtss_transport_npages)*PAGE_SIZE,
                atomic_read(&trnd->seqdone)-1, atomic_read(&trnd->seqnum));
        if  (!ring_buffer_empty(trnd->buffer)) {
            for_each_online_cpu(cpu) {
                unsigned long count = ring_buffer_entries_cpu(trnd->buffer, cpu);
                if (count)
                    ERROR("'%s' evtcount[%03d]=%lu", trnd->name, cpu, count);
            }
        }
        /* We cannot return 0 if transport is not complete, so write the magic */
        *((unsigned int*)buf) = UEC_MAGIC;
        buf += sizeof(unsigned int);
        *((unsigned int*)buf) = UEC_MAGICVALUE;
        buf += sizeof(unsigned int);
        size -= 2*sizeof(unsigned int);
        rc += 2*sizeof(unsigned int);
    }
    atomic_set(&trnd->is_overflow, 0);
    return rc;
}

void vtss_consume_ring_buffer(struct vtss_transport_data* trnd, unsigned long maxdone)
{
    int cpu;
    int num_cpu_overflowed = 0;
    int num_entries_to_clean = 0;
    //unsigned long maxdone = 0;
    unsigned long seqdone = atomic_read(&trnd->seqdone);

    if (!trnd){
        ERROR("Wrong arguments");
        return;
    }
    
    if (!(trnd->type & VTSS_TR_RB)) {
        ERROR("Wrong arguments, wrong trnd type");
        return;
    }

    if (!trnd->buffer){
        ERROR("Wrong arguments, invalid trnd");
        return;
    }

    if (maxdone == 0) {
        for_each_online_cpu(cpu) {
            unsigned long locked_size_cpu = atomic_read(&trnd->locked_size_cpu[cpu]);
            if (locked_size_cpu > (trnd->ring_buffer_size - trnd->ring_buffer_size/4)) {
                unsigned long num_entries = ring_buffer_entries_cpu(trnd->buffer, cpu);
                num_entries_to_clean += num_entries/4;
                num_cpu_overflowed++;
            }
        }
        maxdone = seqdone + num_entries_to_clean;
    }

    if (maxdone && VTSS_TRANSPORT_DATA_READY(trnd))
    {
        int old_state = atomic_cmpxchg(&trnd->processing_state, 0, 1);
        if (old_state == 0) {
            size_t len = 0;
            int rc = 0;
            void* data = NULL;
            int cpu;
#ifndef VTSS_NO_MERGE
            /* Flush buffers if possible first of all */
            len = vtss_transport_temp_flush(trnd, NULL, 0, maxdone);
#endif
            TRACE("start: seqdone=%d, maxdone=%d, num_cpu_overflowed=%d, num_entries_to_clean=%d", (int)seqdone, (int)maxdone, num_cpu_overflowed, num_entries_to_clean);
            while (((seqdone <= maxdone) && (atomic_read(&trnd->processing_state) == 1))) {
                for_each_online_cpu(cpu) {
                    u64 ts;
                    int count;
                    struct ring_buffer_event *event;

                    if (ring_buffer_entries_cpu(trnd->buffer, cpu) == 0)
                        continue; // nothing to read on this cpu
                    for (count = 0; count < 10 && NULL !=
#ifdef VTSS_AUTOCONF_RING_BUFFER_LOST_EVENTS
                            (event = ring_buffer_peek(trnd->buffer, cpu, &ts, NULL))
#else
                            (event = ring_buffer_peek(trnd->buffer, cpu, &ts))
#endif
                            ; count++)
                    {
                        struct vtss_transport_entry* data = (struct vtss_transport_entry*)ring_buffer_event_data(event);

                        /// skip unordered event
                        //if(data->seqnum != seqdone) break;
                        
                        /// skip unwanted event
                        if(data->seqnum > maxdone) break;

                        trnd->seqcpu[cpu] = data->seqnum;

                        if ((1 + trnd->seqcpu[cpu] - atomic_read(&trnd->seqdone)) > VTSS_MERGE_MEM_LIMIT/4 &&
                                !trnd->is_abort && !atomic_read(&trnd->is_complete))
                        {
                            break; /* will not read this event */
                        }
#ifdef VTSS_AUTOCONF_RING_BUFFER_LOST_EVENTS
                        event = ring_buffer_consume(trnd->buffer, cpu, &ts, NULL);
#else
                        event = ring_buffer_consume(trnd->buffer, cpu, &ts);
#endif
                        if (event != NULL) {
                            if ((len = vtss_transport_temp_parse_event(trnd, event, NULL, 0, cpu)) > 0)
                            {
                                TRACE("consume[cpu=%d]: num_entries=%ld, buf_size=%d, (maxdone=%d, trnd->seqdone=%d)",
                                        cpu, ring_buffer_entries_cpu(trnd->buffer, cpu), 
                                        (int)atomic_read(&trnd->locked_size_cpu[cpu]),
                                        (int)maxdone, (int)atomic_read(&trnd->seqdone));
                            }
                        }
                        if (atomic_read(&trnd->seqdone) > maxdone) break;
                    } /* for */
                    if (atomic_read(&trnd->seqdone) > maxdone) break;
                } // for each cpu
                len = vtss_transport_temp_flush(trnd, NULL, 0, maxdone);
                if (seqdone < atomic_read(&trnd->seqdone)){
                    seqdone = atomic_read(&trnd->seqdone);
                } else {
                    ERROR("Nothing to consume");
                    break;
                }
            }
            atomic_cmpxchg(&trnd->processing_state, 1, 0);
        }// old state = 0
    }
}

static void vtss_consume_ring_buffer_cpu(struct vtss_transport_data* trnd, int cpu)
{
    struct ring_buffer_event* event = NULL;
    struct vtss_transport_entry* data = NULL;
    u64 ts;

    if (ring_buffer_entries_cpu(trnd->buffer, cpu) != 0)
    {
#ifdef VTSS_AUTOCONF_RING_BUFFER_LOST_EVENTS
        event = ring_buffer_peek(trnd->buffer, cpu, &ts, NULL);
#else
        event = ring_buffer_peek(trnd->buffer, cpu, &ts);
#endif
        if (event != NULL) {
            struct vtss_transport_entry* data = (struct vtss_transport_entry*)ring_buffer_event_data(event);
            unsigned long maxdone = data->seqnum + 1;
            if(maxdone > atomic_read(&trnd->seqdone)) {
                TRACE("maxdone=%d (seqcpu[%d]=%ld) [seqdone=%d - seqnum=%d] nev=%d)", 
                    (int)maxdone, cpu, trnd->seqcpu[cpu],
                    atomic_read(&trnd->seqdone), atomic_read(&trnd->seqnum),
                    1 + (atomic_read(&trnd->seqnum) - atomic_read(&trnd->seqdone)));
                vtss_consume_ring_buffer(trnd, maxdone);
            }
        }
    }
}

struct ring_buffer_event* vtss_ring_buffer_lock_reserve(struct vtss_transport_data* trnd, size_t size)
{
    struct ring_buffer_event* event = NULL;
    int cnt = (trnd->type & VTSS_TR_RB) ? 100 : 10;
    while(!event && cnt > 0){
#ifdef VTSS_AUTOCONF_RING_BUFFER_FLAGS
        event = ring_buffer_lock_reserve(trnd->buffer, size + sizeof(struct vtss_transport_entry), 0);
#else
        event = ring_buffer_lock_reserve(trnd->buffer, size + sizeof(struct vtss_transport_entry));
#endif
        if (trnd->type & VTSS_TR_RB)
        {
            if (event == NULL && atomic_read(&vtss_ring_buffer_paused) == 0)
            {
                int cnt2 = 100000;
                while(atomic_read(&trnd->processing_state) == 1 && cnt2 > 0)
                {
                    if(cnt2%1000 == 0) touch_nmi_watchdog();
                    cnt2--;
                }
                if(cnt2) {
                    int cpu = raw_smp_processor_id();
                    vtss_consume_ring_buffer_cpu(trnd, cpu);
                }
            }
        }
        cnt--;
    }
    if (event){
        int cpu = raw_smp_processor_id();
        atomic_add(size + sizeof(struct vtss_transport_entry), &trnd->locked_size_cpu[cpu]);
    }
    return event;
}
static struct vtss_transport_entry* vtss_ring_buffer_event_data(struct vtss_transport_data* trnd, struct ring_buffer_event* event, unsigned long* chunk_id)
{
    struct vtss_transport_entry* data;
    data = (struct vtss_transport_entry*)ring_buffer_event_data(event);
    data->seqnum = atomic_inc_return(&trnd->seqnum);
    data->rb_start = 0;
    if (chunk_id && (trnd->type & VTSS_TR_RB)){
        *chunk_id = data->seqnum - ((data->seqnum-1)&VTSS_RB_MASK);
        data->rb_start = *chunk_id;
    }
    if ((data->seqnum&VTSS_RB_MASK) == 1){
        atomic_set(&trnd->rb_mark, data->rb_start);
    }
    data->cputsc = vtss_time_cpu();
    return data;
}

void* vtss_transport_record_reserve_internal(struct vtss_transport_data* trnd, void** entry, size_t size, unsigned long* chunk_id)
{
    struct ring_buffer_event* event;
    struct vtss_transport_entry* data;

    if (unlikely(trnd == NULL || entry == NULL)) {
        ERROR("Transport or Entry is NULL");
        return NULL;
    }

    if (unlikely(!atomic_read(&vtss_is_transport_init))) {
        ERROR("'%s' is initialized", trnd->name);
        return NULL;
    }
    //return NULL;
    atomic_inc(&trnd->reserved);
    if (unlikely(atomic_read(&trnd->is_complete))) {
        ERROR("'%s' is COMPLETED", trnd->name);
        atomic_dec(&trnd->reserved);
        return NULL;
    }

    if (unlikely(size == 0 || size > 0xffff /* max short */)) {
        ERROR("'%s' incorrect size (%zu bytes)", trnd->name, size);
        atomic_dec(&trnd->reserved);
        return NULL;
    }

    if(atomic_read(&vtss_ring_buffer_stopped)) {
        /* collection was stopped */
        atomic_dec(&trnd->reserved);
        return NULL;
    }

    if (likely(size < VTSS_TRANSPORT_MAX_RESERVE_SIZE)) {
        event = vtss_ring_buffer_lock_reserve(trnd, size);
        if (unlikely(event == NULL)) {
            atomic_inc(&trnd->loscount);
            atomic_inc(&trnd->is_overflow);
            DEBUG_TR("'%s' ring_buffer_lock_reserve failed 1, size = %d", trnd->name, (int)(size + sizeof(struct vtss_transport_entry)));
            atomic_dec(&trnd->reserved);
            return NULL;
        }
        *entry = (void*)event;
        data = vtss_ring_buffer_event_data(trnd, event, chunk_id);
        data->size = size;
        return (void*)data->data;
    } else { /* blob */
        unsigned int order = get_order(size + sizeof(struct vtss_transport_temp));
        struct vtss_transport_temp* blob;
        /*if (atomic_read(&vtss_transport_npages) > VTSS_MERGE_MEM_LIMIT/3) {
            DEBUG_TR("'%s' memory limit for blob %zu bytes", trnd->name, size);
            atomic_inc(&trnd->is_overflow);
            atomic_inc(&trnd->loscount);
            return NULL;
        } else if (atomic_read(&vtss_transport_npages) > VTSS_MERGE_MEM_LIMIT/4) {
            DEBUG_TR("'%s' memory limit for blob is  going to happen soon; %zu bytes", trnd->name, size);
            atomic_inc(&trnd->is_overflow);
        }*/
        if (order > 10){
            DEBUG_TR("'%s' cannot allocate %zu bytes", trnd->name, size);
            atomic_inc(&trnd->loscount);
            atomic_dec(&trnd->reserved);
            return NULL;
        }
        DEBUG_TR("'%s' allocated size  = %zu", trnd->name, size);
        blob = (struct vtss_transport_temp*)vtss_get_free_pages(GFP_NOWAIT, order);
        if (blob == NULL)
        {
            vtss_consume_ring_buffer(trnd,0); //this function helps to free memory
            blob = (struct vtss_transport_temp*)vtss_get_free_pages(GFP_NOWAIT, order);
        }
        if (unlikely(blob == NULL)) {
            DEBUG_TR("'%s' no memory for blob %zu bytes", trnd->name, size);
            atomic_inc(&trnd->loscount);
            atomic_dec(&trnd->reserved);
            return NULL;
        }
        atomic_add(1<<order, &vtss_transport_npages);
        blob->size  = size;
        blob->order = order;
        event = vtss_ring_buffer_lock_reserve(trnd, sizeof(void*) + sizeof(struct vtss_transport_entry));
        if (unlikely(event == NULL)) {
            vtss_free_pages((unsigned long)blob, order);
            atomic_sub(1<<order, &vtss_transport_npages);
            atomic_inc(&trnd->loscount);
            atomic_inc(&trnd->is_overflow);
            DEBUG_TR("'%s' ring_buffer_lock_reserve failed overflow", trnd->name);
            atomic_dec(&trnd->reserved);
            return NULL;
        }
        blob->prev = NULL;
        blob->next = NULL;
        *entry = (void*)event;
        data = vtss_ring_buffer_event_data(trnd, event, chunk_id);
        data->size   = 0;
        *((void**)&(data->data)) = (void*)blob;
        return (void*)blob->data;
    }
}
void* vtss_transport_record_reserve(struct vtss_transport_data* trnd, void** entry, size_t size)
{
    return vtss_transport_record_reserve_internal(trnd, entry, size, NULL);
}
void* vtss_transport_activity_record_reserve(struct vtss_transport_data* trnd, void** entry, size_t size, unsigned long* chunk_id)
{
    return vtss_transport_record_reserve_internal(trnd, entry, size, chunk_id);
}


int vtss_transport_record_commit(struct vtss_transport_data* trnd, void* entry, int is_safe)
{
    int rc = 0;
    struct ring_buffer_event* event = (struct ring_buffer_event*)entry;

    if (unlikely(trnd == NULL || entry == NULL)) {
        ERROR("Transport or Entry is NULL");
        return -EINVAL;
    }
#ifdef VTSS_AUTOCONF_RING_BUFFER_FLAGS
    rc = ring_buffer_unlock_commit(trnd->buffer, event, 0);
#else
    rc = ring_buffer_unlock_commit(trnd->buffer, event);
#endif
    if (rc) {
        struct vtss_transport_entry* data = (struct vtss_transport_entry*)ring_buffer_event_data(event);
        ERROR("'%s' commit error: seq=%lu, size=%u", trnd->name, data->seqnum, data->size);
    } else {
        atomic_inc(&trnd->commited);
        if (unlikely(is_safe && trnd->type != VTSS_TR_RB && VTSS_TRANSPORT_DATA_READY(trnd))) {
            if (waitqueue_active(&trnd->waitq))
            {
                DEBUG_TR("commit OK, waitqueue active");
                wake_up_interruptible(&trnd->waitq);
            } 
        }
    }
    atomic_dec(&trnd->reserved);
    return rc;
}

int vtss_transport_record_write(struct vtss_transport_data* trnd, void* part0, size_t size0, void* part1, size_t size1, int is_safe)
{
    int rc = -EFAULT;
    void* entry;
    void* p = vtss_transport_record_reserve(trnd, &entry, size0 + size1);
    if (p) {
        memcpy(p, part0, size0);
        if (size1)
            memcpy(p + size0, part1, size1);
        rc = vtss_transport_record_commit(trnd, entry, is_safe);
    }
    return rc;
}

#endif /* VTSS_USE_UEC */

int vtss_transport_record_write_all(void* part0, size_t size0, void* part1, size_t size1, int is_safe)
{
    int rc = 0;
    unsigned long flags;
    struct list_head *p;
    struct vtss_transport_data *trnd = NULL;

    vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
    list_for_each(p, &vtss_transport_list) {
        trnd = list_entry(p, struct vtss_transport_data, list);
        TRACE("put_record(%d) to trnd=0x%p => '%s'", atomic_read(&trnd->is_complete), trnd, trnd->name);
        if (likely((trnd->name[0] != '\0') && (!atomic_read(&trnd->is_complete)) && trnd->type == VTSS_TR_REG)) {
#ifdef VTSS_USE_UEC
            /* Don't use spill notifications from uec therefore its UECMODE_SAFE always */
            int rc1;    
            if (VTSS_PT_FLUSH_MODE){
                rc1 = trnd->uec_chain->put_record(trnd->uec_chain, part0, size0, part1, size1, UECMODE_SAFE);
            } else {
                rc1 = trnd->uec->put_record(trnd->uec, part0, size0, part1, size1, UECMODE_SAFE);
            }
            if (rc1) {
                atomic_inc(&trnd->loscount);
                rc = -EFAULT;
            }
#ifndef VTSS_USE_NMI
            if (unlikely(is_safe && VTSS_TRANSPORT_DATA_READY(trnd))) {
                TRACE("WAKE UP");
                if (waitqueue_active(&trnd->waitq))
                    wake_up_interruptible(&trnd->waitq);
            }
#endif
#else  /* VTSS_USE_UEC */
            void* entry;
            void* p = vtss_transport_record_reserve(trnd, &entry, size0 + size1);
            if (likely(p)) {
                memcpy(p, part0, size0);
                if (size1)
                    memcpy(p + size0, part1, size1);
                rc = vtss_transport_record_commit(trnd, entry, is_safe) ? -EFAULT : rc;
            } else {
                rc = -EFAULT;
            }
#endif /* VTSS_USE_UEC */
        }
    }
    vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
    return rc;
}

static unsigned int vtss_magic_marker[2] = {UEC_MAGIC, UEC_MAGICVALUE};

static ssize_t vtss_transport_read(struct file *file, char __user* buf, size_t size, loff_t* ppos)
{
    ssize_t rc = 0;
    int rc1 = 0;
    int magic = 0;
#ifndef VTSS_USE_UEC
    int cnt = 0;
#endif
    struct vtss_transport_data* trnd = (struct vtss_transport_data*)file->private_data;

    if (unlikely(trnd == NULL || trnd->file == NULL || buf == NULL || size < sizeof(vtss_magic_marker))){
        ERROR("Failed read file!, trnd = %p, buf = %p, size = %d", trnd, buf, (int)size);
        return -EINVAL;
    }
    DEBUG_TR("read, file = %p, name = %s", file, trnd->name ? trnd->name : "null");
    while (!atomic_read(&trnd->is_complete) && !VTSS_TRANSPORT_DATA_READY(trnd)) {
#ifndef VTSS_USE_UEC
        cnt++;
        if (cnt == 1000){
             int data_size = 1 + (atomic_read(&trnd->seqnum) - atomic_read(&trnd->seqdone));
             DEBUG_TR("Trying to read not ready data, data size = %d", data_size);
        }
#endif
        if (file->f_flags & O_NONBLOCK){
            return -EAGAIN;
        }
#if defined(VTSS_CONFIG_REALTIME)
        {
            unsigned long delay;
            delay = msecs_to_jiffies(1000);
            rc = wait_event_interruptible_timeout(trnd->waitq,
                 (atomic_read(&trnd->is_complete) || VTSS_TRANSPORT_DATA_READY(trnd)), delay);
        }
#else
        rc = wait_event_interruptible(trnd->waitq,
             (atomic_read(&trnd->is_complete) || VTSS_TRANSPORT_DATA_READY(trnd)));
#endif
        if (rc < 0){
            DEBUG_TR("Waitq is empty");
            return -ERESTARTSYS;
        }
    }

#ifndef VTSS_USE_UEC
    if (trnd->type & VTSS_TR_RB) {
        {
            int old_state = atomic_cmpxchg(&trnd->processing_state, 0, 2);
            int state_error = 0;
            if (old_state == 4) atomic_cmpxchg(&trnd->processing_state, 4, 2);
            while (old_state == 1)
            {
                old_state = atomic_cmpxchg(&trnd->processing_state, 0, 2);
                state_error++;
                if (state_error == 1000)
                {
                  DEBUG_TR("awaiting right state takes too long!!!");
                  return 0;
                }
            }
        }
    }
#endif
    rc = 0;
    if (trnd->magic == 0){
        VTSS_TRANSPORT_COPY_TO_USER((void*)vtss_magic_marker, sizeof(vtss_magic_marker));
        trnd->magic++;
        magic++;
    }


#ifdef VTSS_USE_UEC
    if (trnd->type & VTSS_TR_RB) {
        rc1 = trnd->uec_chain->pull(trnd->uec_chain, buf, size);
    } else {
        rc1 = trnd->uec->pull(trnd->uec, buf, size);
    }
#else
    rc1  = vtss_transport_read_rb(trnd, buf, size);
#endif /* VTSS_USE_UEC */
    if (rc1 < 0) {
        if (magic > 0) trnd->magic--;
        return rc1;
    }
    rc += rc1;
    if(trnd->type & VTSS_TR_RB)
        TRACE("'%s' read %zd bytes", trnd->name, rc);
    return rc;
}

static ssize_t vtss_transport_write(struct file *file, const char __user * buf, size_t count, loff_t * ppos)
{
    /* the transport is read only */
    return -EINVAL;
}

static unsigned int vtss_transport_poll(struct file *file, poll_table* poll_table)
{
    unsigned int rc = 0;
    struct vtss_transport_data* trnd = NULL;
    
    if (file == NULL){
        ERROR("Invalid poll. File is empty");
        return (POLLERR | POLLNVAL);
    }
    trnd = (struct vtss_transport_data*)file->private_data;
    if (trnd == NULL){
        ERROR("Invalid poll. File data is empty");
        return (POLLERR | POLLNVAL);
    }
    if (trnd->file == NULL){
        ERROR("Invalid poll. File was already closed.");
        return 0;
    }
    poll_wait(file, &trnd->waitq, poll_table);
    if (atomic_read(&trnd->is_complete) || (VTSS_TRANSPORT_DATA_READY(trnd) && trnd->type != VTSS_TR_RB))
        rc = (POLLIN | POLLRDNORM);
    else
        atomic_set(&trnd->is_overflow, 0);
    DEBUG_TR("%s: file=0x%p, trnd=0x%p", (rc ? "READY" : "-----"), file, trnd);
    return rc;
}

static int vtss_transport_open(struct inode *inode, struct file *file)
{
    int rc;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct vtss_transport_data *trnd = (struct vtss_transport_data *)PDE(inode)->data;
#else
    struct vtss_transport_data *trnd = (struct vtss_transport_data *)PDE_DATA(inode);
#endif
    DEBUG_TR("inode=0x%p, file=0x%p, trnd=0x%p", inode, file, trnd);
    if (trnd == NULL)
        return -ENOENT;

    rc = generic_file_open(inode, file);
    if (rc)
        return rc;

    if (atomic_read(&trnd->is_complete) && VTSS_TRANSPORT_IS_EMPTY(trnd)) {
        return -EINVAL;
    }
    if (atomic_inc_return(&trnd->is_attached) > 1) {
        atomic_dec(&trnd->is_attached);
        return -EBUSY;
    }
    trnd->file = file;
    file->private_data = trnd;
    /* Increase the priority for trace reader to avoid lost events */
    set_user_nice(current, -19);
    return rc;
}

static int vtss_transport_close(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct vtss_transport_data *trnd = (struct vtss_transport_data*)PDE(inode)->data;
#else
    struct vtss_transport_data *trnd = (struct vtss_transport_data*)PDE_DATA(inode);
#endif
    if (!file)
    {
        ERROR("File is empty");
        return 0;
    }
    file->private_data = NULL;
    /* Restore default priority for trace reader */
    set_user_nice(current, 0);
    DEBUG_TR("inode=0x%p, file=0x%p, trnd=0x%p", inode, file, trnd);
    if (trnd == NULL)
    {
        ERROR("Internal error");
        return -ENOENT;
    }
    DEBUG_TR("Closing the file %s", trnd->name);
    trnd->file = NULL;
    if (!atomic_dec_and_test(&trnd->is_attached)) {
        ERROR("'%s' wrong state", trnd->name);
        atomic_set(&trnd->is_attached, 0);
        return -EFAULT;
    }
    return 0;
}

static struct file_operations vtss_transport_fops = {
    .owner   = THIS_MODULE,
    .read    = vtss_transport_read,
    .write   = vtss_transport_write,
    .open    = vtss_transport_open,
    .release = vtss_transport_close,
    .poll    = vtss_transport_poll,
};

static void vtss_transport_remove(struct vtss_transport_data* trnd)
{
    struct proc_dir_entry *procfs_root = NULL;
    if (trnd->name[0]=='\0') return;
    procfs_root = vtss_procfs_get_root();

    if (procfs_root != NULL) {
        remove_proc_entry(trnd->name, procfs_root);
    }
    trnd->name[0]='\0';
}

static void vtss_transport_destroy_trnd(struct vtss_transport_data* trnd)
{
#ifdef VTSS_USE_UEC
    if (trnd->uec){
        destroy_uec(trnd->uec);
        vtss_kfree(trnd->uec);
    }
    trnd->uec_chain->destroy(trnd->uec_chain);
#else
    int seqnum = atomic_read(&trnd->seqnum);
    int seqdone = atomic_read(&trnd->seqdone);
    
    if ((seqdone - 1) != seqnum) {
        ERROR("'%s' drop %d events seqnum = %d, segdone = %d", trnd->name, seqnum - seqdone - 1, seqnum, seqdone);
    }
    if (trnd->buffer) {
        ring_buffer_free(trnd->buffer);
        trnd->buffer = NULL;
    }
    if (trnd->head){
        vtss_transport_temp_free_all(trnd, &(trnd->head));
        trnd->head = NULL;
    }
#endif
    DEBUG_TR("trnd = %p  destroyed", trnd);
    vtss_kfree(trnd);
}

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_transport_destroy_trnd_work(struct work_struct *work)
#else
static void vtss_transport_destroy_trnd_work(void *work)
#endif
{
    struct vtss_work* my_work = (struct vtss_work*)work;
    struct vtss_transport_data* trnd = NULL;
    if (!my_work){
        ERROR("empty work!");
        return;
    }
    trnd = *((struct vtss_transport_data**)(&my_work->data));
    if (trnd)
    {
        vtss_transport_destroy_trnd(trnd);
    }
    else
    {
        ERROR("Trying to destroy empty transport data");
    }
    vtss_kfree(my_work);
    atomic_dec(&vtss_kernel_task_in_progress);
}

#ifndef VTSS_USE_UEC
static unsigned long vtss_ring_buffer_alloc(struct vtss_transport_data* trnd, unsigned long size)
{
    if (size < 2*PAGE_SIZE) size = 2*PAGE_SIZE;
    if (size > VTSS_ALLOC_BUFSIZE_MAX) size = VTSS_ALLOC_BUFSIZE_MAX;
    trnd->buffer = ring_buffer_alloc(size, 0);
    return trnd->buffer ? size : 0;
}
#endif

static void vtss_transport_init_trnd(struct vtss_transport_data* trnd)
{
#ifndef VTSS_USE_UEC
    int cpu;
#endif
    init_waitqueue_head(&trnd->waitq);
    atomic_set(&trnd->refcount,    1);
    atomic_set(&trnd->loscount,    0);
    atomic_set(&trnd->is_attached, 0);
    atomic_set(&trnd->is_complete, 0);
    atomic_set(&trnd->is_overflow, 0);
    trnd->file = NULL;
    atomic_set(&trnd->seqdone,1);
    trnd->magic    = 0;
#ifndef VTSS_USE_UEC
    atomic_set(&trnd->processing_state, 0);
    atomic_set(&trnd->reserved, 0);
    trnd->is_abort = 0;
    if (trnd->head){
         vtss_transport_temp_free_all(trnd, &(trnd->head));
         trnd->head  = NULL;
    }
    atomic_set(&trnd->seqnum, 0);
    atomic_set(&trnd->commited, 0);
    trnd->bufcputsc = 0;
    for_each_online_cpu(cpu) atomic_set(&trnd->locked_size_cpu[cpu], 0);
// the line below leads hang on 52.166 machine
//    if (trnd->buffer) ring_buffer_reset(trnd->buffer); 
#endif
}

#define VTSS_AH_BUFSIZE_SEC 0x200000L
#define VTSS_PT_BUFSIZE_SEC 0x1800000L

struct vtss_transport_data* vtss_transport_create_trnd(int type, struct vtss_transport_data* buf_src_trnd)
{
    unsigned long rb_size = 0;
    struct vtss_transport_data* trnd = NULL;
#ifdef VTSS_USE_UEC
    int rc = -1;
#endif
    // This function cannot be called in irqs disabled mode, as it allocates huge ammount of memory.
    // Return 0 for the case
    if (irqs_disabled()){
        DEBUG_TR("The attempt to create transport in irqs disabled mode failed.");
        return NULL;
    }
    trnd = (struct vtss_transport_data*)vtss_kmalloc(sizeof(struct vtss_transport_data), GFP_KERNEL);
    DEBUG_TR("trnd = %p  allocated", trnd);
    if (trnd == NULL) {
        ERROR("Not enough memory for transport data");
        return NULL;
    }
    memset(trnd, 0, sizeof(struct vtss_transport_data));
    vtss_transport_init_trnd(trnd);
    trnd->type = type;
#ifdef VTSS_USE_UEC
    if (reqcfg.ipt_cfg.size)
    {
        int msec = reqcfg.ipt_cfg.size;

        if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT)
        {
            rb_size = (hardcfg.cpu_no/2 * msec * VTSS_PT_BUFSIZE_SEC) / 1000;
        }
        else
        {
            int si = vtss_cpuevents_get_sampling_interval();
            unsigned long cpuevents_size = 0;
 
            if (reqcfg.cpuevent_count_v1 > 10) cpuevents_size = reqcfg.cpuevent_count_v1*8*1000;
            rb_size = (hardcfg.cpu_no/2 * msec * (VTSS_AH_BUFSIZE_SEC + cpuevents_size))/(1000*si);
        }
        DEBUG_TR("RB: %s mode: %d msec, %ld bytes (%ldMb)", 
            reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT ? "PT" : "EBS", msec, rb_size, rb_size/0x100000L);
    }
    rc = init_uec_chain(trnd->uec_chain, rb_size/VTSS_UEC_CHAIN_SIZE, NULL, VTSS_UEC_CHAIN_SIZE);
    if (rc) {
            ERROR("Unable to init UEC chain");
            vtss_transport_destroy_trnd(trnd);
            return NULL;
    }
    if (buf_src_trnd) {
        DEBUG_TR("take new buffer");
        trnd->uec = buf_src_trnd->uec;
        buf_src_trnd->uec = NULL;
        rc = 0;
    }
    else
    {
        trnd->uec = (uec_t*)vtss_kmalloc(sizeof(uec_t), GFP_KERNEL);
        rc = -1;
    }
    if (trnd->uec != NULL) {
        size_t size = VTSS_UEC_BUFSIZE;
        trnd->uec->callback = vtss_transport_callback;
        trnd->uec->context  = (void*)trnd;
        if (rc == -1) rc = init_uec(trnd->uec, size, NULL, 0);
        if (rc) {
            ERROR("Unable to init UEC");
            vtss_transport_destroy_trnd(trnd);
            return NULL;
        }
        TRACE("Use %zu bytes for UEC", size);
    } else {
        ERROR("Could not create UEC");
        vtss_transport_destroy_trnd(trnd);                    
        return NULL;
    }
#else
    trnd->buffer = NULL;


    if (buf_src_trnd){
         if (buf_src_trnd->type < type){
             //we cannot use this buffer! the size is different
             buf_src_trnd = NULL;
         }
    }
    if (buf_src_trnd && buf_src_trnd->buffer){
        trnd->buffer = buf_src_trnd->buffer;
        buf_src_trnd->buffer = NULL;
    //    ring_buffer_reset(trnd->buffer);
    }
    else {
        int msec = reqcfg.ipt_cfg.size ? reqcfg.ipt_cfg.size : 1000;

        if (type == VTSS_TR_RB) {
            if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) {
                //PT writes only headers to RB
                rb_size = (msec * VTSS_AH_BUFSIZE_SEC)/1000;
            }
            else {
                int si = vtss_cpuevents_get_sampling_interval();
                unsigned long cpuevents_size = 0;
 
                if (reqcfg.cpuevent_count_v1 > 10) cpuevents_size = reqcfg.cpuevent_count_v1*8*1000;
                rb_size = (msec * (VTSS_AH_BUFSIZE_SEC + cpuevents_size))/(1000*si);
                DEBUG_TR("cpuevent_count=%d, sampling_interval=%d", reqcfg.cpuevent_count_v1, si);
            }
            DEBUG_TR("RB: %s mode: %d msec, %ld bytes (%ldMb)", 
                reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT ? "PT" : "EBS", msec, rb_size, rb_size/0x100000L);
        }
        else {
            if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) {
                rb_size = VTSS_AH_BUFSIZE_SEC;
            }
            else {
                rb_size = (num_present_cpus() > 32) ? 32*PAGE_SIZE : 64*PAGE_SIZE;
            }
        }
        rb_size = PAGE_ALIGN(rb_size);
        trnd->ring_buffer_size = vtss_ring_buffer_alloc(trnd, rb_size);
        DEBUG_TR("allocated size=%x, type=%d", trnd->ring_buffer_size, type);
    }
    if (trnd->buffer == NULL) {
        trnd->ring_buffer_size = 0;
        ERROR("Unable to allocate %lu bytes for transport buffer (nth=%d)", rb_size, num_present_cpus()/2);
        vtss_transport_destroy_trnd(trnd);
        return NULL;
    }
#endif
   return trnd;
}

#if 0
#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_transport_prealloc_item_work(struct work_struct *work)
#else
static void vtss_transport_prealloc_item_work(void *work)
#endif
{
    struct vtss_work* my_work = (struct vtss_work*)work;
    int* type_ptr = NULL;
    struct vtss_transport_data *trnd = NULL;
    unsigned long flags;

    if (!my_work){
        ERROR("empty work!");
        return;
    }
    type_ptr = (int*)my_work->data;
    if (!type_ptr){
        ERROR("unknown type");
        vtss_kfree(my_work);
        return;
    }
    trnd=vtss_transport_create_trnd(*type_ptr, NULL);
    if (trnd) {
        vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
        list_add_tail(&trnd->list, &vtss_transport_list);
        atomic_inc(&vtss_free_tr_cnt);
        vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
    }
    vtss_kfree(my_work);
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,32)
static int vtss_transport_prealloc_transport_items(void)
{
    int i;
    int aux_type = (atomic_read(&vtss_transport_mode) == VTSS_TR_MODE_RB) ? VTSS_TR_RB : VTSS_TR_CFG;

    int max = (VTSS_PREALLOC_TR_SIZE + VTSS_PREALLOC_TR_SIZE);
    unsigned long flags;
    if (atomic_read(&vtss_free_tr_cnt) >= max) return 0;
    //preallocate transport items
    for(i = 0; i < VTSS_PREALLOC_TR_SIZE; i++){
        struct vtss_transport_data *trnd = NULL;
        trnd=vtss_transport_create_trnd(aux_type, NULL);
        if (trnd) {
            vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
            list_add_tail(&trnd->list, &vtss_transport_list);
            atomic_inc(&vtss_free_tr_cnt);
            vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
        } else {
            if (i == 0) return -1;
            else break;
        }

        trnd=vtss_transport_create_trnd(VTSS_TR_REG, NULL);
        if (trnd){
            vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
            list_add_tail(&trnd->list, &vtss_transport_list);
            atomic_inc(&vtss_free_tr_cnt);
            vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
        } else {
            if (i == 0) return -1;
            else break;
        }
    }
    return 0;
}
#endif

struct vtss_transport_data* vtss_transport_get_trnd(int type)
{
    struct vtss_transport_data* trnd = NULL;
    struct vtss_transport_data* trnd_ret = NULL;
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;
    unsigned long flags;
    int cnt = 100;
    
    while ((!trnd_ret) && (cnt > 0))
    {
        vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
        if(atomic_read(&vtss_is_transport_init) == 0){
            vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
            return NULL;
        }
        list_for_each_safe(p, tmp, &vtss_transport_list) {
            trnd = list_entry(p, struct vtss_transport_data, list);
            if (trnd == NULL){
                ERROR("trnd in list is NULL");
                continue;
            }
            if (trnd->type != type){
                continue;
            }
            if (atomic_read(&trnd->is_attached)) {
                continue;
            }
            if  (VTSS_TRANSPORT_IS_EMPTY(trnd)){
                if (trnd->name[0]=='\0'){
                    trnd_ret = trnd;
                    atomic_dec(&vtss_free_tr_cnt);
                    list_del(p);
                } else {
#ifdef VTSS_USE_UEC
                    if (!trnd->uec)
#else
                    if (!trnd->buffer)
#endif
                        continue;
                    trnd_ret = vtss_transport_create_trnd(type, trnd /* use already allocated buffers*/ );
                }
                break;
            }
        }
        vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
        cnt--;
        if (!trnd_ret){
            if (!irqs_disabled()){
                trnd_ret = vtss_transport_create_trnd(type, NULL);
            } else {
              break;
            }
        }
    }
    DEBUG_TR("end, trnd_ret = %p", trnd_ret);
    return trnd_ret;
}

static void vtss_transport_create_trnd_name(struct vtss_transport_data* trnd, pid_t ppid, pid_t pid, uid_t cuid, gid_t cgid)
{
    int seq = -1;
    struct path path;
    char buf[MODULE_NAME_LEN + sizeof(trnd->name) + 8 /* strlen("/proc/<MODULE_NAME>/%d-%d.%d") */];

    do { /* Find out free name */
        if (++seq > 0) path_put(&path);
        snprintf(trnd->name, sizeof(trnd->name)-1, "%d-%d.%d", ppid, pid, seq);
        snprintf(buf, sizeof(buf)-1, "%s/%s", vtss_procfs_path(), trnd->name);
        TRACE("lookup '%s'", buf);
    } while (!kern_path(buf, 0, &path));
    /* Doesn't exist, so create it */
    return;
}

int vtss_transport_create_pde (struct vtss_transport_data* trnd, uid_t cuid, gid_t cgid)
{
    unsigned long flags;
    struct proc_dir_entry* pde;
    struct proc_dir_entry* procfs_root = vtss_procfs_get_root();

    if (procfs_root == NULL) {
        ERROR("Unable to get PROCFS root");
        return 1;
    }
    pde = proc_create_data(trnd->name, (mode_t)(mode ? (mode & 0444) : 0440), procfs_root, &vtss_transport_fops, trnd);

    if (pde == NULL) {
        ERROR("Could not create '%s/%s'", vtss_procfs_path(), trnd->name);
        vtss_transport_destroy_trnd(trnd);
        return 1;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#ifdef VTSS_AUTOCONF_PROCFS_OWNER
    pde->owner = THIS_MODULE;
#endif
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    pde->uid = cuid ? cuid : uid;
    pde->gid = cgid ? cgid : gid;
#else
#if defined CONFIG_UIDGID_STRICT_TYPE_CHECKS || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
{
    kuid_t kuid = KUIDT_INIT(cuid ? cuid : uid);
    kgid_t kgid = KGIDT_INIT(cgid ? cgid : gid);
    proc_set_user(pde, kuid, kgid);
}
#else
    proc_set_user(pde, cuid ? cuid : uid, cgid ? cgid : gid);
#endif
#endif
    vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
    list_add_tail(&trnd->list, &vtss_transport_list);
    vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
    TRACE("trnd=0x%p => '%s' done", trnd, trnd->name);
    return 0;
}
struct vtss_transport_data* vtss_transport_create(pid_t ppid, pid_t pid, uid_t cuid, gid_t cgid)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,6,32)
    struct vtss_transport_data* trnd = vtss_transport_create_trnd(VTSS_TR_REG, NULL);
#else
    struct vtss_transport_data* trnd = vtss_transport_get_trnd(VTSS_TR_REG);
#endif

    if (trnd == NULL) {
        if (!irqs_disabled()) ERROR("Not enough memory for transport data");
        return NULL;
    }
    vtss_transport_create_trnd_name(trnd, ppid, pid, cuid, cgid);
    /* Doesn't exist, so create it */
    if (vtss_transport_create_pde(trnd, cuid, cgid)){
        ERROR("Could not create '%s/%s'", vtss_procfs_path(), trnd->name);
        vtss_transport_destroy_trnd(trnd);
        return NULL;
    }
    DEBUG_TR("returned outside trnd = %p", trnd);
    return trnd;
}
struct vtss_transport_data* vtss_transport_create_aux(struct vtss_transport_data* main_trnd, uid_t cuid, gid_t cgid, int is_rb)
{
    char* main_trnd_name = main_trnd->name;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,6,32)
    struct vtss_transport_data* trnd = vtss_transport_create_trnd(is_rb == VTSS_TR_MODE_RB ? VTSS_TR_RB : VTSS_TR_CFG, NULL);
#else
    struct vtss_transport_data* trnd = vtss_transport_get_trnd(is_rb == VTSS_TR_MODE_RB ? VTSS_TR_RB : VTSS_TR_CFG);
#endif

    if (trnd == NULL) {
        ERROR("Not enough memory for transport data");
        return NULL;
    }
#ifndef VTSS_USE_UEC
    if (trnd->type == VTSS_TR_RB) {
        trnd->bufcputsc = vtss_time_cpu();
    }
#endif
    memcpy((void*)trnd->name, (void*)main_trnd_name, strlen(main_trnd_name));
    memcpy((void*)trnd->name+strlen(main_trnd_name),(void*)".aux", 5);
    /* Doesn't exist, so create it */
    if (vtss_transport_create_pde(trnd, cuid, cgid)){
        ERROR("Could not create '%s/%s'", vtss_procfs_path(), trnd->name);
        vtss_transport_destroy_trnd(trnd);
        return NULL;
    }
    DEBUG_TR("returned outside trnd = %p", trnd);
    return trnd;
}

int vtss_transport_complete(struct vtss_transport_data* trnd)
{
    if (trnd == NULL)
        return -ENOENT;
    DEBUG_TR("start, trnd->name = %s", trnd->name);
    if (atomic_read(&trnd->refcount)) {
        ERROR("'%s' refcount=%d != 0", trnd->name, atomic_read(&trnd->refcount));
    }
    atomic_inc(&trnd->is_complete);
    if (waitqueue_active(&trnd->waitq)) {
        DEBUG_TR("wake up!");
        wake_up_interruptible(&trnd->waitq);
    }

    return 0;
}
void vtss_transport_wake_up_all(void)
{
    unsigned long flags;
    struct list_head *p;
    struct vtss_transport_data *trnd = NULL;
#ifdef VTSS_USE_NMI
    if(!vtss_spin_trylock_irqsave(&vtss_transport_list_lock, flags))
        return;
#else
    vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
#endif
    list_for_each(p, &vtss_transport_list) {
        touch_nmi_watchdog();
        trnd = list_entry(p, struct vtss_transport_data, list);
        if (trnd == NULL){
             ERROR("tick: trnd in list is NULL");
             continue;
        }
	
	if (trnd->type & VTSS_TR_RB && (!atomic_read(&trnd->is_complete))) {
#ifndef VTSS_USE_UEC
        //currently we use vtss_consume_ring_buffer_cpu
        //vtss_consume_ring_buffer(trnd, 0);
#endif
	    continue;
	}
        if (atomic_read(&trnd->is_attached)) {
            if (waitqueue_active(&trnd->waitq)) {
                DEBUG_TR("trnd=0x%p => '%s'", trnd, trnd->name);
                wake_up_interruptible(&trnd->waitq);
            }
        }
    }
    vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);

}
#ifdef VTSS_TRANSPORT_TIMER_INTERVAL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void vtss_transport_tick(struct timer_list *unused)
#else
static void vtss_transport_tick(unsigned long val)
#endif
{
    if (atomic_read(&vtss_is_transport_init)==0){
        DEBUG_TR("Transport tick while uninit. Ignore.");
        return;
    }
    vtss_transport_wake_up_all();
    mod_timer(&vtss_transport_timer, jiffies + VTSS_TRANSPORT_TIMER_INTERVAL);

}
#endif /* VTSS_TRANSPORT_TIMER_INTERVAL */

int vtss_transport_debug_info(struct seq_file *s)
{
    unsigned long flags;
    struct list_head *p;
    struct vtss_transport_data *trnd = NULL;

    seq_printf(s, "\n[transport]\nnbuffers=%u (%lu bytes)\n", atomic_read(&vtss_transport_npages), atomic_read(&vtss_transport_npages)*PAGE_SIZE);
    vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
    list_for_each(p, &vtss_transport_list) {
        trnd = list_entry(p, struct vtss_transport_data, list);
        seq_printf(s, "\n[proc %s]\nis_attached=%s\nis_complete=%s\nis_overflow=%s\nrefcount=%d\nloscount=%d\nevtcount=%lu\n",
                    trnd->name,
                    atomic_read(&trnd->is_attached) ? "true" : "false",
                    atomic_read(&trnd->is_complete) ? "true" : "false",
                    atomic_read(&trnd->is_overflow) ? "true" : "false",
                    atomic_read(&trnd->refcount),
                    atomic_read(&trnd->loscount),
#ifdef VTSS_USE_UEC
                    0UL);
#else

                    ring_buffer_entries(trnd->buffer));
        if (!ring_buffer_empty(trnd->buffer)) {
            int cpu;
            for_each_online_cpu(cpu) {
                unsigned long count = ring_buffer_entries_cpu(trnd->buffer, cpu);
                if (count)
                    seq_printf(s, "evtcount[%03d]=%lu\n", cpu, count);
            }
        }
        seq_printf(s, "evtstore=%d of %d\n", atomic_read(&trnd->seqdone)-1, atomic_read(&trnd->seqnum));
        seq_printf(s, "is_abort=%s\n", trnd->is_abort ? "true" : "false");
#endif /* VTSS_USE_UEC */
    }
    vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
    return 0;
}

int vtss_transport_init(int rb)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,32)
    int rc;
#endif
    unsigned long flags;
    atomic_set(&vtss_transport_npages, 0);
    atomic_set(&vtss_transport_mode, rb);
    atomic_set(&vtss_free_tr_cnt, 0);
    atomic_set(&vtss_ring_buffer_stopped, 0);
    atomic_set(&vtss_ring_buffer_paused, 0);

    vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
    INIT_LIST_HEAD(&vtss_transport_list);
    vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,32)
    rc = vtss_transport_prealloc_transport_items();
    if (rc == -1) {
        ERROR("Cannot preallocate transport items");
        return -1;
    }
#endif
#ifdef VTSS_TRANSPORT_TIMER_INTERVAL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    timer_setup(&vtss_transport_timer, vtss_transport_tick, 0);
    vtss_transport_timer.expires = jiffies + VTSS_TRANSPORT_TIMER_INTERVAL;
#else
    init_timer(&vtss_transport_timer);
    vtss_transport_timer.expires  = jiffies + VTSS_TRANSPORT_TIMER_INTERVAL;
    vtss_transport_timer.function = vtss_transport_tick;
    vtss_transport_timer.data     = 0;
#endif
    add_timer(&vtss_transport_timer);
#endif
    atomic_set(&vtss_is_transport_init, 1);
#ifdef VTSS_USE_UEC
    INFO("TRANSPORT: use UEC");
#endif
    return 0;
}

void vtss_transport_fini(void)
{
    int wait_count = VTSS_TRANSPORT_COMPLETE_TIMEOUT;
    unsigned long flags, count;
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;
    struct vtss_transport_data *trnd = NULL;

    DEBUG_TR("start, in_atomic = %d", in_atomic());
    if (!atomic_dec_and_test(&vtss_is_transport_init))
    {
        ERROR("transport does not initialized: %d", atomic_read(&vtss_is_transport_init));
        atomic_set(&vtss_is_transport_init, 0);
        return;
    }
#ifdef VTSS_TRANSPORT_TIMER_INTERVAL
    del_timer_sync(&vtss_transport_timer);
#endif
    count = 0;
    while (atomic_read(&vtss_kernel_task_in_progress)){
         count++;
         if (count == 10000) ERROR("kernel task in progress, atomic_read(&vtss_kernel_task_in_progress)=%d", atomic_read(&vtss_kernel_task_in_progress));
    }
again:
    //vtss_transport_wake_up_all();
    vtss_spin_lock_irqsave(&vtss_transport_list_lock, flags);
    list_for_each_safe(p, tmp, &vtss_transport_list) {
        trnd = list_entry(p, struct vtss_transport_data, list);
        touch_nmi_watchdog();
        if (trnd == NULL){
             ERROR("fini: trnd in list is NULL");
             continue;
        }
#ifndef VTSS_USE_UEC
        if (trnd->type & VTSS_TR_RB) {
            int old_state = atomic_cmpxchg(&trnd->processing_state, 0, 3);
            while (old_state == 1) old_state = atomic_cmpxchg(&trnd->processing_state, 0, 3);
            if (old_state == 2 || old_state == 4) atomic_set(&trnd->processing_state, 3);
        }
#endif
        atomic_inc(&trnd->is_complete);
#ifndef VTSS_USE_UEC
        while  (atomic_read(&trnd->reserved))
        {
            DEBUG_TR("trnd is reserved");
            msleep_interruptible(1);
        }
#endif
        if (atomic_read(&trnd->is_attached)) {
            int cnt = 1000;
            if (--wait_count > 0) {
                //if (waitqueue_active(&trnd->waitq)) {
                //    wake_up_interruptible(&trnd->waitq);
                //}
                vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
                while (!waitqueue_active(&trnd->waitq) && (cnt--)) {
                    msleep_interruptible(1);
                }
                if (waitqueue_active(&trnd->waitq)) {
                    wake_up_interruptible(&trnd->waitq);
                }
                else
                {
                  INFO("%s: queue is not active!", trnd->name);
                }
                msleep_interruptible(20);
                goto again;
            }
            ERROR("%s: complete timeout", trnd->name);
            if (trnd->file){
                trnd->file->private_data = NULL;
                trnd->file = NULL;
            }
        }
        list_del(p);
        if (atomic_read(&trnd->loscount)) {
            ERROR("TRANSPORT: '%s' lost %d events", trnd->name, atomic_read(&trnd->loscount));
        }
        vtss_transport_remove(trnd);
#ifdef VTSS_CONFIG_REALTIME
        atomic_inc(&vtss_kernel_task_in_progress);
        if( !in_atomic() || vtss_queue_work(-1, vtss_transport_destroy_trnd_work, &trnd, sizeof(trnd)))
        {
                ERROR("Cannot remove transport!");
                //vtss_transport_destroy_trnd(trnd);
                atomic_dec(&vtss_kernel_task_in_progress);
        }

#else
        vtss_transport_destroy_trnd(trnd);
#endif
        wait_count = VTSS_TRANSPORT_COMPLETE_TIMEOUT;
    }
    INIT_LIST_HEAD(&vtss_transport_list);
    vtss_spin_unlock_irqrestore(&vtss_transport_list_lock, flags);
    while (atomic_read(&vtss_kernel_task_in_progress))
    {
      count++;
      if (count == 10000) DEBUG_TR("2:kernel task in progress, atomic_read(&vtss_kernel_task_in_progress)=%d", atomic_read(&vtss_kernel_task_in_progress));
    }
    if (atomic_read(&vtss_transport_npages)) {
        ERROR("lost %u (%lu bytes) buffers", atomic_read(&vtss_transport_npages), atomic_read(&vtss_transport_npages)*PAGE_SIZE);
    }
    atomic_set(&vtss_transport_npages, 0);
    INFO("TRANSPORT: stopped");
}
