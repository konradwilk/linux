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
#include "globals.h"
#include "uec.h"
#include "time.h"
#include "memory_pool.h"

#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
#include <linux/uaccess.h>
#endif
#include <asm/uaccess.h>

//The maximum allowed value for order is 10 or 11 (corresponding to 1024 or 2048 pages), depending on the architecture.
// but these are huge memory chunks fro 32-bit kernel, so decrease to 8
#define VTSS_MAX_ORDER_SIZE 8
#if defined(__i386__)
#define VTSS_MAX_UEC_ORDER_SIZE 8
#else
#define VTSS_MAX_UEC_ORDER_SIZE 10
#endif
#define VTSS_MIN_UEC_ORDER_SIZE 4

/**
// Universal Event Collector: system mode implementation
*/

/// chained UEC operations

int init_uec_chain(uec_t* uec, size_t size, char* name, int chain_size)
{
    int order = 0, alloc_order = 0;
    int i;
    int rc = 0;
    uec_t* curr = uec;

    for(i = 0; i < chain_size; i++, uec++)
    {
        /// initialize methods
        uec->put_record = put_record_chain;
        uec->destroy = destroy_uec_chain;
        uec->pull = pull_uec_chain;
        uec->init = init_uec_chain;

        if (reqcfg.ipt_cfg.size) {
            /// allocate buffers
            alloc_order = order = get_order(size);
            if (alloc_order > VTSS_MAX_UEC_ORDER_SIZE) alloc_order =  VTSS_MAX_UEC_ORDER_SIZE;
            if (alloc_order <= VTSS_MIN_UEC_ORDER_SIZE) alloc_order = VTSS_MIN_UEC_ORDER_SIZE + 1; 
            while (alloc_order > VTSS_MIN_UEC_ORDER_SIZE) {
                if ((uec->buffer = (char*)__get_free_pages(GFP_KERNEL | __GFP_NOWARN, alloc_order))) {
                    ERROR("order %d, allocated order %d", order, alloc_order);
                    break;
                }
                alloc_order--;
           }
            if (alloc_order == VTSS_MIN_UEC_ORDER_SIZE) {
                ERROR("No memory for UEC chain buffer[%d]", i);
                rc = VTSS_ERR_NOMEMORY;
            }
        }
        else {
            uec->buffer = NULL;
        }
        /// initialize fields
        uec->last_rec_ptr = uec->head = uec->head_ = uec->tail = uec->tail_ = uec->buffer;
        uec->hsize = uec->tsize = alloc_order ? (PAGE_SIZE << alloc_order) : 0;

        uec->ovfl = 0;
        uec->spill_active = 0;
        uec->chain_busy = 0;
        uec->writer_count = 0;
        uec->reader_count = 0;
        uec->cputsc = 0;

        vtss_spin_lock_init(&uec->lock);
        /// chain up the UECs
        uec->curr = curr;
        uec->next = uec + 1;
        uec->full_next = uec + 1;
    }
    (uec - chain_size + 1)->next = curr;
    (uec - 1)->full_next = curr;
    return rc;
}

/// for safety reasons (quick initialization)
static int put_record_stub(uec_t* uec, void *part0, size_t size0, void *part1, size_t size1, int mode)
{
    return 0;
}
void destroy_uec_chain(uec_t* uec)
{
//    static unsigned int marker[2] = {UEC_MAGIC, UEC_MAGICVALUE};
//    uec->put_record(uec, marker, 8, 0, 0, UECMODE_NORMAL);
    /// find head of chain
    while(uec != uec->curr)
    {
        uec = uec->next;
    }
    /// destroy UECs one by one
    do
    {
        uec = uec->full_next;
        destroy_uec(uec);
    }
    while(uec != uec->curr);
}

#if 0
void spill_uec_chain(uec_t* uec)
{
    uec_t* chain = uec;
    unsigned long flags;
    INFO("start");
    /// synchronize spills and buffer switches
    vtss_spin_lock_irqsave(&uec->lock, flags);

    if(chain->chain_busy)
    {
        vtss_spin_unlock_irqrestore(&uec->lock, flags);
        INFO("end1");
        return;
    }
    chain->chain_busy = 1;

    vtss_spin_unlock_irqrestore(&uec->lock, flags);


    /// find head of chain
    while(uec != uec->curr)
    {
        uec = uec->next;
    }
    /// spill UECs one by one
    do
    {
        uec = uec->next;
       //spill_uec_file(uec);
    }
    while(uec != uec->curr);

    /// synchronize spills and buffer switches
    vtss_spin_lock_irqsave(&uec->lock, flags);

    chain->chain_busy = 0;

    vtss_spin_unlock_irqrestore(&uec->lock, flags);
    INFO("end");
}
#endif

int put_record_chain(uec_t* uec, void* part0, size_t size0, void* part1, size_t size1, int mode)
{
    uec_t* chain = uec, *extra_uec = NULL;
    int res = 0;
    unsigned long flags = 0, flags1 = 0;
    unsigned long extra_count = 0;
    long long buffer_time = 0;
    
    /// find head; write; if nomem, lock{find head, if same, switch buffers, else, continue}
    for(;;)
    {
        uec = chain;
        /// find head of chain
        while(uec != uec->curr)
        {
            uec = uec->next;
        }
        /// write a record and switch UECs if the current one gets full
        if((uec->tail == uec->head && uec->ovfl) ||
            (res = put_record_async(uec, part0, size0, part1, size1, UECMODE_SAFE)) == VTSS_ERR_BUFFERFULL)
        {
            uec_t* uec_locked = uec;
            /// synchronize spills and buffer switches
            vtss_spin_lock_irqsave(&uec_locked->lock, flags);

            if(chain->chain_busy)
            {
                /// lose data when spilling the chain
                vtss_spin_unlock_irqrestore(&uec->lock, flags);
                return res;
            }
            if(uec->curr != uec)
            {
                /// buffer switched, retry
                vtss_spin_unlock_irqrestore(&uec->lock, flags);
                continue;
            }

            // increase buffers in tail only
            if (uec->next != uec->full_next)
            {
                if (uec->cputsc)
                {
#if defined(__i386__)
                    if (hardcfg.cpu_freq)
                    {
                        buffer_time = 1000*(vtss_time_cpu() - uec->cputsc);
                        do_div(buffer_time, hardcfg.cpu_freq);
                        if (buffer_time)
                        {
                            extra_count = reqcfg.ipt_cfg.size;
                            do_div(extra_count, buffer_time);
                        }
                        else
                        {
                            extra_count = 1;
                        }
                    }
#else
                    if (hardcfg.cpu_freq > 0 && (buffer_time = (1000 * (vtss_time_cpu() - uec->cputsc)) / hardcfg.cpu_freq) > 0)
                    {
                        extra_count = reqcfg.ipt_cfg.size / buffer_time;
                    }
#endif
                    else
                    {
                        extra_count = 1;
                    }
                    if (extra_count)
                    {
                        extra_count += 1;
                        extra_uec = uec;
                        while(extra_count && extra_uec->full_next != extra_uec->next)
                        {
                            extra_count--;
                            extra_uec->full_next->next = extra_uec->next;
                            extra_uec->next = extra_uec->full_next;
                            extra_uec = extra_uec->next;
                        }
                    }
                }
                else uec->cputsc = vtss_time_cpu();
                extra_count = 0;
            }

            /// switch UECs
            uec->curr = uec->next;
            uec = uec->next;
            uec->curr = uec;

            /// clear UEC circular buffer
            if(chain != uec)
            {
                vtss_spin_lock_irqsave(&uec->lock, flags1);
            }
            uec->last_rec_ptr = uec->head = uec->head_ = uec->tail = uec->tail_ = uec->buffer;
            uec->ovfl = 0;

            if(chain != uec)
            {
                vtss_spin_unlock_irqrestore(&uec->lock, flags1);
            }

            /// synchronize spills and buffer switches
            vtss_spin_unlock_irqrestore(&uec_locked->lock, flags);
        }
        else
        {
            break;
        }
    }
    return res;
}

int pull_uec_chain(uec_t* uec, char __user* buffer, size_t len)
{
    /// TODO: implement transparent puuling of data from chained UECs
    ///       may be needed when exposing PT traces to a debugger
    uec_t* chain = uec;
    unsigned long flags;
    int rc = 0;
    /// synchronize spills and buffer switches
    vtss_spin_lock_irqsave(&uec->lock, flags);

    if(chain->chain_busy)
    {
        vtss_spin_unlock_irqrestore(&uec->lock, flags);
        return VTSS_ERR_BUSY;
    }
    chain->chain_busy= 1;

    vtss_spin_unlock_irqrestore(&uec->lock, flags);


    /// find head of chain
    while(uec != uec->curr)
    {
        uec = uec->next;
    }
    
    /// spill UECs one by one
    do
    {
        int rc1 = 0;
        uec = uec->next;
        buffer = buffer + rc;
    
        rc1 = pull_uec(uec, buffer, len);
        if (rc1 < 0){
            if (rc > 0) break;
            vtss_spin_lock_irqsave(&uec->lock, flags);
            chain->chain_busy = 0;
            vtss_spin_unlock_irqrestore(&uec->lock, flags);
            ERROR("Cannot pull record, rc = %d, rc1 =%d", rc, rc1);
            return rc1;
        }
        if(len < rc1) break;

        len -= rc1;
        rc += rc1;
    }
    while(uec != uec->curr);

    /// synchronize spills and buffer switches
    vtss_spin_lock_irqsave(&uec->lock, flags);

    chain->chain_busy = 0;

    vtss_spin_unlock_irqrestore(&uec->lock, flags);
    return rc;
}

//normal uec implementation


int init_uec(uec_t* uec, size_t size, char *name, int instance)
{
    int order, alloc_order;
    /// initialize methods
    uec->put_record = put_record_async;
    uec->init = init_uec;
    uec->destroy = destroy_uec;
    uec->pull = pull_uec;

    if (size == 0) { /// change name request
        ERROR("UEC size is 0");
        return VTSS_ERR_INTERNAL;
    }

    /// allocate buffers
    alloc_order = order = get_order(size);
    if (alloc_order > VTSS_MAX_UEC_ORDER_SIZE) alloc_order =  VTSS_MAX_UEC_ORDER_SIZE;

    while (alloc_order > VTSS_MIN_UEC_ORDER_SIZE) {
        if ((uec->buffer = (char*)__get_free_pages(GFP_KERNEL | __GFP_NOWARN, alloc_order))) {
            break;
        }
        alloc_order--;
    }
    if (alloc_order == VTSS_MIN_UEC_ORDER_SIZE) {
        ERROR("No memory for UEC buffer");
        return VTSS_ERR_NOMEMORY;
    }

    uec->last_rec_ptr = uec->head = uec->head_ = uec->tail = uec->tail_ = uec->buffer;
    uec->hsize = uec->tsize = PAGE_SIZE << alloc_order;

    uec->ovfl = 0;
    uec->spill_active = 0;
    uec->writer_count = 0;
    uec->reader_count = 0;

    vtss_spin_lock_init(&uec->lock);
    /// notify on the creation of a new trace
//    uec->callback(uec, UECCB_NEWTRACE, uec->context);
    return 0;
}

void destroy_uec(uec_t* uec)
{
    uec->put_record = put_record_stub;

    if (uec->buffer) {
        free_pages((unsigned long)uec->buffer, get_order(uec->hsize));
        uec->buffer = NULL;
    }
}

#define safe_memcpy(dst, src, size) memcpy(dst, src, size)
#define spill_uec() /* empty */

int put_record_async(uec_t* uec, void *part0, size_t size0, void *part1, size_t size1, int mode)
{
    size_t tsize;                  /// total record size
    size_t fsize = 0;              /// free area length
    size_t psize;                  /// partial size
    size_t tmp;
    char *last_rec_ptr;
    char *head = 0;
    char *tail = 0;
    size_t hsize = 0;
    unsigned long flags;

    if (!uec->buffer || !part0 || !size0 || ((!size1) ^ (!part1))) {
        return VTSS_ERR_BADARG;
    }
    tsize = size0 + size1;

    /// lock UEC
#ifdef VTSS_USE_NMI
    if(!vtss_spin_lock_irqsave_timeout(&uec->lock, flags, 10000))
        return VTSS_ERR_BUSY;
#else
    vtss_spin_lock_irqsave(&uec->lock, flags);
#endif

    /// sample the uec variables
    head = (char*)uec->head_;
    tail = (char*)uec->tail;
    last_rec_ptr = head;
    hsize = uec->hsize;

    /// is buffer full?
    if (uec->ovfl) {
        *((unsigned int*)uec->last_rec_ptr) |= UEC_OVERFLOW;
        /// signal overflow to overlying components
//        uec->callback(uec, UECCB_OVERFLOW, uec->context);
        vtss_spin_unlock_irqrestore(&uec->lock, flags);
        spill_uec();
        return VTSS_ERR_BUFFERFULL;
    }
    /// compute free size
    if (tail <= head) {
        fsize = uec->hsize - (size_t)(head - tail);
    } else {
        fsize = (size_t)(tail - head);
    }
    /// handle 'no room' case
    if (fsize < tsize) {
        uec->ovfl = 1;
        *((unsigned int*)uec->last_rec_ptr) |= UEC_OVERFLOW;
        /// signal overflow to overlying components
//        uec->callback(uec, UECCB_OVERFLOW, uec->context);
        vtss_spin_unlock_irqrestore(&uec->lock, flags);
        spill_uec();
        return VTSS_ERR_BUFFERFULL;//VTSS_ERR_NOMEMORY;
    }
    /// allocate uec region
    psize = (size_t)(uec->buffer + hsize - head);

    if (psize > tsize) {
        uec->head_ = head + tsize;
    } else {
        uec->head_ = uec->buffer + tsize - psize;
    }
    if (uec->head_ == tail) {
        uec->ovfl = 1;
    }
    /// increment the writers' count
    uec->writer_count++;

    /// unlock UEC
    vtss_spin_unlock_irqrestore(&uec->lock, flags);

    /// do the write to the allocated uec region

    if (tail <= head) {
        if (psize > tsize) {
            memcpy(head, part0, size0);
            head += size0;
            if (size1) {
                safe_memcpy(head, part1, size1);
                head += size1;
            }
        } else {
            tmp = size0 > psize ? psize : size0;
            memcpy(head, part0, tmp);
            head += tmp;

            if (tmp == psize) {
                head = uec->buffer;
                if ((size0 - tmp) > 0) {
                    memcpy(head, ((char*)part0) + tmp, size0 - tmp);
                    head += size0 - tmp;
                }
            }
            if (size1) {
                psize -= tmp;
                if (psize) {
                    safe_memcpy(head, part1, psize);
                    head = uec->buffer;
                    if ((size1 - psize) > 0) {
                        memcpy(head, ((char*)part1) + psize, size1 - psize);
                        head += size1 - psize;
                    }
                } else {
                    safe_memcpy(head, part1, size1);
                    head += size1;
                }
            }
        }
    } else /// tail > head
    {
        memcpy(head, part0, size0);
        head += size0;
        if (size1) {
            safe_memcpy(head, part1, size1);
            head += size1;
        }
    }

    /// lock UEC
    vtss_spin_lock_irqsave(&uec->lock, flags);

    /// decrement the writers' count
    uec->writer_count--;

    uec->last_rec_ptr = last_rec_ptr;

    /// update uec variables
    if (!uec->writer_count) {
        uec->head = uec->head_;
    }
    /// unlock UEC
    vtss_spin_unlock_irqrestore(&uec->lock, flags);

    spill_uec();

    return 0;
}

int pull_uec(uec_t* uec, char __user* buffer, size_t len)
{
    int rc = 0;
    char *head;
    char *tail;
    size_t size;
    int ovfl;

    size_t copylen = 0;
    size_t partlen;

    unsigned long flags;

    /// sample the UEC state, copy the sampled contents to the specified buffer,
    /// and free the read part of the UEC buffer

    if (!uec->buffer || !buffer || !len) {
        return VTSS_ERR_BADARG;
    }
    /// sample data region
#ifdef VTSS_USE_NMI
    if(!vtss_spin_lock_irqsave_timeout(&uec->lock, flags, 10000))
        return VTSS_ERR_BUSY;
#else
    vtss_spin_lock_irqsave(&uec->lock, flags);
#endif

    if (uec->spill_active) {
        vtss_spin_unlock_irqrestore(&uec->lock, flags);
        return VTSS_ERR_BUSY;
    }
    uec->spill_active = 1;

    head = (char*)uec->head;
    tail = (char*)uec->tail;
    size = uec->tsize;
    ovfl = uec->ovfl;

    if ((head == tail && !ovfl) || (head == tail && ovfl && head != uec->head_)) {
        uec->spill_active = 0;
        vtss_spin_unlock_irqrestore(&uec->lock, flags);
        return 0; ///empty
    }

    vtss_spin_unlock_irqrestore(&uec->lock, flags);

    /// spill the sampled region
    if (head > tail) {
        copylen = (size_t)(head - tail);
        copylen = copylen > len ? len : copylen;

        rc = copy_to_user(buffer, (void*)tail, copylen);

        tail += copylen;
    } else if (head < tail || (head == tail && ovfl)) {
        copylen = partlen = (size_t)(size - (tail - uec->buffer));
        copylen = copylen > len ? len : copylen;

        rc = copy_to_user(buffer, (void*)tail, copylen);

        tail += copylen;

        if (copylen == partlen && copylen < len) {
            /// copy the second part
            partlen = (size_t)(head - uec->buffer);
            partlen = partlen > (len - copylen) ? (len - copylen) : partlen;

            rc |= copy_to_user(&((char*)buffer)[copylen], (void*)uec->buffer, partlen);

            copylen += partlen;
            /// assert(copylen <= len);

            tail = uec->buffer + partlen;
        }
    }

    vtss_spin_lock_irqsave(&uec->lock, flags);
    uec->tail = tail;
    uec->ovfl = 0;
    uec->spill_active = 0;
    vtss_spin_unlock_irqrestore(&uec->lock, flags);

    return rc ? -1 : copylen;
}
