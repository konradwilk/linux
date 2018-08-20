/*  Copyright (C) 2010-2015 Intel Corporation.  All Rights Reserved.

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
#include "collector.h"
#include "globals.h"
#include "transport.h"
#include "procfs.h"
#include "module.h"
#include "record.h"
#include "stack.h"
#include "apic.h"
#include "cpuevents.h"
#include "dsa.h"
#include "bts.h"
#include "ipt.h"
#include "lbr.h"
#include "pebs.h"
#include "time.h"
#include "nmiwd.h"
#include "memory_pool.h"

#include <linux/nmi.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/cred.h>         /* for current_uid_gid() */
#include <linux/pid.h>
#include <linux/dcache.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/preempt.h>
#include <linux/delay.h>        /* for msleep_interruptible() */
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#endif
#include <asm/kexec.h>
#include <asm/pgtable.h>
#include <asm/fixmap.h>         /* VSYSCALL_START */
#include <asm/page.h>
#include <asm/elf.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#include <xen/xen.h>
#endif

#define DEBUG_COLLECTOR TRACE

#ifndef KERNEL_IMAGE_SIZE
#define KERNEL_IMAGE_SIZE (512 * 1024 * 1024)
#endif

#ifndef MODULES_VADDR
#define MODULES_VADDR VMALLOC_START
#endif

#define SAFE       1
#define NOT_SAFE   0
#define IN_IRQ     1
#define NOT_IN_IRQ 0

#define VTSS_MIN_STACK_SPACE 1024

#ifdef VTSS_AUTOCONF_DPATH_PATH
#include <linux/path.h>
#define D_PATH(vm_file, name, maxlen) d_path(&((vm_file)->f_path), (name), (maxlen))
#else
#define D_PATH(vm_file, name, maxlen) d_path((vm_file)->f_path.dentry, (vm_file)->f_vfsmnt, (name), (maxlen))
#endif

/* Only live tasks with mm and state == TASK_RUNNING | TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE */
#define VTSS_IS_VALID_TASK(task) ((task->mm || (task->flags & PF_KTHREAD)) && (task)->state < 4 && (task)->exit_state == 0)

static const char* state_str[4] = { "STOPPED", "INITING", "RUNNING", "PAUSED" };

#define VTSS_EVENT_LOST_MODULE_ADDR 2
static const char VTSS_EVENT_LOST_MODULE_NAME[] = "Events Lost On Trace Overflow";

#define vtss_cpu_active(cpu) cpumask_test_cpu((cpu), &vtss_collector_cpumask)

#define VTSS_RET_CANCEL 1 //Cancel scheduled work

extern size_t vtss_pebs_record_size;

atomic_t vtss_collector_state = ATOMIC_INIT(VTSS_COLLECTOR_STOPPED);

static cpumask_t vtss_collector_cpumask = CPU_MASK_NONE;
static atomic_t  vtss_target_count      = ATOMIC_INIT(0);
static atomic_t  vtss_start_paused      = ATOMIC_INIT(0);
static uid_t     vtss_session_uid       = 0;
static gid_t     vtss_session_gid       = 0;

atomic_t  vtss_mmap_reg_callcnt  = ATOMIC_INIT(0);

// collector cannot work if transport uninitialized as  pointer "task->trnd" (transport)
// is not set to NULL  during tranport "fini".

static atomic_t  vtss_transport_state = ATOMIC_INIT(0);
static atomic_t  vtss_transport_busy = ATOMIC_INIT(0); //check if we can remove this
static atomic_t  vtss_events_enabling = ATOMIC_INIT(0);

static atomic_t vtss_kernel_task_in_progress = ATOMIC_INIT(0);

#if (!defined(VTSS_USE_UEC)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0))
int vtss_need_switch_off_tracing = 0;
#endif
unsigned int vtss_client_major_ver = 0;
unsigned int vtss_client_minor_ver = 0;

struct vtss_target_list_item
{
    struct list_head list;
    int pid;
    int cnt;
    int cnt_done;
};

#ifdef VTSS_CONFIG_REALTIME
static DEFINE_RAW_SPINLOCK(vtss_target_temp_list_lock);
#else
static DEFINE_SPINLOCK(vtss_target_temp_list_lock);
#endif
static LIST_HEAD(vtss_target_temp_list);



#define VTSS_ST_NEWTASK    (1<<0)
#define VTSS_ST_SOFTCFG    (1<<1)
#define VTSS_ST_SWAPIN     (1<<2)
#define VTSS_ST_SWAPOUT    (1<<3)
/*-----------------------------*/
#define VTSS_ST_SAMPLE     (1<<4)
#define VTSS_ST_STKDUMP    (1<<5)
#define VTSS_ST_STKSAVE    (1<<6)
#define VTSS_ST_PAUSE      (1<<7)
/*-----------------------------*/
#define VTSS_ST_IN_CONTEXT (1<<8)
#define VTSS_ST_IN_SYSCALL (1<<9)
#define VTSS_ST_CPUEVT     (1<<10)
#define VTSS_ST_COMPLETE   (1<<11)
/*-----------------------------*/
#define VTSS_ST_NOTIFIER   (1<<12)
#define VTSS_ST_PMU_SET    (1<<13)
#define VTSS_ST_MMAP_INIT  (1<<14)  //modules currently writing to the trace first time in different thread.
/*-----------------------------*/
//#define VTSS_ST_REC_CTX    (1<<15)  //recorded context switch for calculatiing time, even if we do not need them in result.
//#define VTSS_ST_CPU_CHANGE (1<<16)  //recorded context switch for calculatiing time, even if we do not need them in result.

static const char* task_state_str[] = {
    "-NEWTASK-",
    "-SOFTCFG-",
    "-SWAPIN-",
    "-SWAPOUT-",
    "-SAMPLE-",
    "-STACK_DUMP-",
    "-STACK_SAVE-",
    "PAUSE",
    "RUNNING",
    "IN_SYSCALL",
    "CPUEVT",
    "(COMPLETE)",
    "(NOTIFIER)",
    "(PMU_SET)",
    "(MMAP_INIT)",
};

#define VTSS_IN_CONTEXT(x)            ((x)->state & VTSS_ST_IN_CONTEXT)
#define VTSS_IN_SYSCALL(x)            ((x)->state & VTSS_ST_IN_SYSCALL)
#define VTSS_IN_NEWTASK(x)            (!((x)->state & (VTSS_ST_NEWTASK | VTSS_ST_SOFTCFG)))
#define VTSS_IS_CPUEVT(x)             ((x)->state & VTSS_ST_CPUEVT)
#define VTSS_IS_COMPLETE(x)           ((x)->state & VTSS_ST_COMPLETE)
#define VTSS_IS_NOTIFIER(x)           ((x)->state & VTSS_ST_NOTIFIER)
#define VTSS_IS_PMU_SET(x)            ((x)->state & VTSS_ST_PMU_SET)

#define VTSS_IS_STATE_SET(x,st)      ((x)->state & st)


#define VTSS_IS_MMAP_INIT(x)          ((x)->state & VTSS_ST_MMAP_INIT)
#define VTSS_SET_MMAP_INIT(x)         (x)->state |= VTSS_ST_MMAP_INIT
#define VTSS_CLEAR_MMAP_INIT(x)       (x)->state &= ~VTSS_ST_MMAP_INIT

#define VTSS_NEED_STORE_NEWTASK(x)    ((x)->state & VTSS_ST_NEWTASK)
#define VTSS_NEED_STORE_SOFTCFG(x)    (((x)->state & (VTSS_ST_NEWTASK | VTSS_ST_SOFTCFG)) == VTSS_ST_SOFTCFG)
#define VTSS_NEED_STORE_PAUSE(x)      ((((x)->state & (VTSS_ST_NEWTASK | VTSS_ST_SOFTCFG | VTSS_ST_PAUSE)) == VTSS_ST_PAUSE) && (atomic_read(&vtss_collector_state)== VTSS_COLLECTOR_PAUSED) )
#define VTSS_NEED_STACK_SAVE(x)       (((x)->state & (VTSS_ST_STKDUMP | VTSS_ST_STKSAVE)) == VTSS_ST_STKSAVE)

#define VTSS_ERROR_STORE_SAMPLE(x)    ((x)->state & VTSS_ST_SAMPLE)
#define VTSS_ERROR_STORE_SWAPIN(x)    ((x)->state & VTSS_ST_SWAPIN)
#define VTSS_ERROR_STORE_SWAPOUT(x)   ((x)->state & VTSS_ST_SWAPOUT)
#define VTSS_ERROR_STACK_DUMP(x)      ((x)->state & VTSS_ST_STKDUMP)
#define VTSS_ERROR_STACK_SAVE(x)      ((x)->state & VTSS_ST_STKSAVE)

#define VTSS_STORE_STATE(x,c,y)       ((x)->state = (c) ? (x)->state | (y) : (x)->state & ~(y))

#define VTSS_STORE_NEWTASK(x,f)       VTSS_STORE_STATE((x), vtss_record_thread_create((x)->trnd, (x)->tid, (x)->pid, (x)->cpu, (f)), VTSS_ST_NEWTASK)
#define VTSS_STORE_SOFTCFG(x,f)       VTSS_STORE_STATE((x), vtss_record_softcfg((x)->trnd, (x)->tid, (f)), VTSS_ST_SOFTCFG)
#define VTSS_STORE_PAUSE(x,cpu,i,f)   VTSS_STORE_STATE((x), vtss_record_probe((x)->trnd, (cpu), (i), (f)), VTSS_ST_PAUSE)

#define VTSS_STORE_SAMPLE(x,cpu,ip,f) VTSS_STORE_STATE((x), vtss_record_sample(VTSS_PT_FLUSH_MODE ? (x)->trnd_aux : (x)->trnd, (x)->tid, (cpu), (x)->cpuevent_chain, (ip), (f), &(x)->start_rec_id), VTSS_ST_SAMPLE)
#define VTSS_STORE_SWAPIN(x,cpu,ip,f) VTSS_STORE_STATE((x), vtss_record_switch_to(VTSS_PT_FLUSH_MODE ? (x)->trnd_aux : (x)->trnd, (x)->tid, (cpu), (ip), (f), &(x)->start_rec_id), VTSS_ST_SWAPIN)
#define VTSS_STORE_SWAPOUT(x,p,f)     VTSS_STORE_STATE((x), vtss_record_switch_from(VTSS_PT_FLUSH_MODE ? (x)->trnd_aux : (x)->trnd, (x)->cpu, (p), (f), &(x)->start_rec_id), VTSS_ST_SWAPOUT)

#ifdef VTSS_SYSCALL_TRACE
#define VTSS_STACK_DUMP(x,t,r,bp,f)   VTSS_STORE_STATE((x), vtss_stack_dump(VTSS_PT_FLUSH_MODE ? (x)->trnd_aux : (x)->trnd, &((x)->stk), (t), (r), (bp), (x)->syscall_sp, (f)), VTSS_ST_STKDUMP)
#else
#define VTSS_STACK_DUMP(x,t,r,bp,f)   VTSS_STORE_STATE((x), vtss_stack_dump(VTSS_PT_FLUSH_MODE ? (x)->trnd_aux : (x)->trnd, &((x)->stk), (t), (r), (bp), NULL, (f)), VTSS_ST_STKDUMP)
#endif
#define VTSS_STACK_SAVE(x,f)          VTSS_STORE_STATE((x), vtss_stack_record(VTSS_PT_FLUSH_MODE ? (x)->trnd_aux : (x)->trnd, &((x)->stk), (x)->tid, (x)->cpu, (f), &(x)->start_rec_id), VTSS_ST_STKSAVE)

/* Replace definition above with following to turn off functionality: */
//#define VTSS_STORE_SAMPLE(x,cpu,ip,f) VTSS_STORE_STATE((x), 0, VTSS_ST_SAMPLE)
//#define VTSS_STORE_SWAPIN(x,cpu,ip,f) VTSS_STORE_STATE((x), 0, VTSS_ST_SWAPIN)
//#define VTSS_STORE_SWAPOUT(x,p,f)     VTSS_STORE_STATE((x), 0, VTSS_ST_SWAPOUT)

//#define VTSS_STACK_DUMP(x,t,r,bp,f)   VTSS_STORE_STATE((x), 0, VTSS_ST_STKDUMP)
//#define VTSS_STACK_SAVE(x,f)          VTSS_STORE_STATE((x), 0, VTSS_ST_STKSAVE)

struct vtss_task_data
{
    stack_control_t  stk;
    lbr_control_t    lbr;
    vtss_tcb_t       tcb;
    struct vtss_transport_data* trnd;
    struct vtss_transport_data* trnd_aux;
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
    struct preempt_notifier preempt_notifier;
#endif
    unsigned int     state;
    int              m32;
    pid_t            tid;
    pid_t            pid;
    pid_t            ppid;
    unsigned int     cpu;
    void*            ip;
#ifdef VTSS_SYSCALL_TRACE
    void*            syscall_sp;
    unsigned long long syscall_enter;
#endif
#ifndef VTSS_NO_BTS
    unsigned short   bts_size;
    unsigned char    bts_buff[VTSS_BTS_MAX*sizeof(vtss_bts_t)];
#endif
    char             filename[VTSS_FILENAME_SIZE];
    char             taskname[VTSS_TASKNAME_SIZE];
    cpuevent_t       cpuevent_chain[VTSS_CFG_CHAIN_SIZE];
    void*            from_ip;
    unsigned long start_rec_id;
};

static int vtss_mmap_all(struct vtss_task_data*, struct task_struct*);
static int vtss_kmap_all(struct vtss_task_data*);

#ifndef VTSS_USE_NMI
#define VTSS_RECOVERY_LOGIC
#endif

#ifdef VTSS_RECOVERY_LOGIC
#ifdef VTSS_CONFIG_REALTIME
static DEFINE_RAW_SPINLOCK(vtss_recovery_lock);
#else
static DEFINE_SPINLOCK(vtss_recovery_lock);
#endif

static DEFINE_PER_CPU_SHARED_ALIGNED(struct vtss_task_data*, vtss_recovery_tskd);
#endif

#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
static void vtss_notifier_sched_in (struct preempt_notifier *notifier, int cpu);
static void vtss_notifier_sched_out(struct preempt_notifier *notifier, struct task_struct *next);

static struct preempt_ops vtss_preempt_ops = {
    .sched_in  = vtss_notifier_sched_in,
    .sched_out = vtss_notifier_sched_out
};
#endif

#ifdef VTSS_GET_TASK_STRUCT

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
typedef void (vtss__put_task_struct_t) (struct task_struct *tsk);
static vtss__put_task_struct_t* vtss__put_task_struct = NULL;

static struct kprobe _kp_dummy = {
    .pre_handler = NULL,
    .post_handler = NULL,
    .fault_handler = NULL,
#ifdef VTSS_AUTOCONF_KPROBE_SYMBOL_NAME
    .symbol_name = "__put_task_struct",
#endif
    .addr = (kprobe_opcode_t*)NULL
};

static inline void vtss_put_task_struct(struct task_struct *task)
{
    if (atomic_dec_and_test(&task->usage))
        vtss__put_task_struct(task);
}
#else  /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39) */
#define vtss_put_task_struct put_task_struct
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39) */

#endif /* VTSS_GET_TASK_STRUCT */

int  vtss_target_new(pid_t tid, pid_t pid, pid_t ppid, const char* filename, int fired_tid, int fired_order);
int  vtss_target_del(vtss_task_map_item_t* item);

static struct task_struct* vtss_find_task_by_tid(pid_t tid)
{
    struct task_struct *task = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
    struct pid *p_pid = NULL;
    p_pid = find_get_pid(tid);
    if (p_pid) {
        rcu_read_lock();
        task = pid_task(p_pid, PIDTYPE_PID);
        rcu_read_unlock();
        put_pid(p_pid);
    }
#else /* < 2.6.31 */
    rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    task = find_task_by_vpid(tid);
#else /* < 2.6.24 */
    task = find_task_by_pid(tid);
#endif /* 2.6.24 */
    rcu_read_unlock();
#endif /* 2.6.31 */
    return task;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static char *vtss_get_task_comm(char *taskname, struct task_struct *task)
{
    size_t size = 0;
    task_lock(task);
    size =  min((size_t)VTSS_TASKNAME_SIZE-1, (size_t)strlen(task->comm));
    strncpy(taskname, task->comm, size);
    taskname[size]='\0';
    task_unlock(task);
    return taskname;
}
#else  /* LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) */
#define vtss_get_task_comm(name, task) get_task_comm(name, task)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0) */

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_cmd_stop_work(struct work_struct *work)
#else
static void vtss_cmd_stop_work(void *work)
#endif
{
    vtss_cmd_stop();
    vtss_kfree(work);
}

int vtss_queue_work(int cpu, vtss_work_func_t* func, void* data, size_t size)
{
    struct vtss_work* my_work = 0;

    my_work = (struct vtss_work*)vtss_kmalloc(sizeof(struct vtss_work)+size, GFP_ATOMIC);

    if (my_work != NULL) {
#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
        INIT_WORK((struct work_struct*)my_work, func);
#else
        INIT_WORK((struct work_struct*)my_work, func, my_work);
#endif
        if (data != NULL && size > 0)
            memcpy(&my_work->data, data, size);

#ifdef VTSS_AUTOCONF_SYSTEM_UNBOUND_WQ

#ifdef VTSS_CONFIG_REALTIME
            queue_work(system_unbound_wq, (struct work_struct*)my_work);
#else
        if (cpu < 0) {
            queue_work(system_unbound_wq, (struct work_struct*)my_work);
        } else {
            queue_work_on(cpu, system_unbound_wq, (struct work_struct*)my_work);
        }
#endif //VTSS_CONFIG_REALTIME

#else  /* VTSS_AUTOCONF_SYSTEM_UNBOUND_WQ */
#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
        if (cpu < 0) {
            schedule_work((struct work_struct*)my_work);
        } else {
            schedule_work_on(cpu, (struct work_struct*)my_work);
        }
#else  /* VTSS_AUTOCONF_INIT_WORK_TWO_ARGS */
        /* Don't support queue work on cpu */
        schedule_work((struct work_struct*)my_work);
#endif /* VTSS_AUTOCONF_INIT_WORK_TWO_ARGS */
#endif /* VTSS_AUTOCONF_SYSTEM_UNBOUND_WQ */
    } else {
        ERROR("No memory for my_work");
        return -ENOMEM;
    }
    return 0;
}
inline int is_aux_transport_allowed(void)
{
    return (vtss_client_major_ver > 1 || (vtss_client_major_ver ==1 && vtss_client_minor_ver >=1));
}
inline int is_aux_transport_ring_buffer(void)
{
    return (is_aux_transport_allowed() && VTSS_PT_FLUSH_MODE) ? VTSS_TR_MODE_RB : VTSS_TR_MODE_REG;
}

static void vtss_target_ctrl_wakeup(struct vtss_transport_data* trnd, struct vtss_transport_data* trnd_aux)
{
    if (trnd){
        if (trnd_aux && trnd_aux != trnd) {
            char *transport_path_aux = vtss_transport_get_filename(trnd_aux);
            TRACE("wakeup for %s\n", transport_path_aux);
            vtss_procfs_ctrl_wake_up(transport_path_aux, strlen(transport_path_aux) + 1);
        } else {
            char *transport_path = vtss_transport_get_filename(trnd);
            TRACE("wakeup for %s", transport_path);
            vtss_procfs_ctrl_wake_up(transport_path, strlen(transport_path) + 1);
        }
    }
}

static void vtss_target_transport_create(struct vtss_transport_data** trnd, struct vtss_transport_data** trnd_aux, pid_t ppid, pid_t pid, uid_t cuid, gid_t cgid)
{
    if (!trnd) return;
    *trnd = vtss_transport_create(ppid, pid, cuid, cgid);
    if (!(*trnd)) return;
    if (trnd_aux){
        if (is_aux_transport_allowed()){
            *trnd_aux = vtss_transport_create_aux(*trnd, cuid, cgid, is_aux_transport_ring_buffer());
        }
        else{
            *trnd_aux = NULL;
        }
    }
    vtss_target_ctrl_wakeup(*trnd, *trnd_aux);
}

void vtss_target_del_empty_transport(struct vtss_transport_data* trnd, struct vtss_transport_data* trnd_aux)
{
    if (!trnd && !trnd_aux) return;

    atomic_inc(&vtss_transport_busy);
    if (atomic_read(&vtss_transport_state) == 1) {
        if (trnd != NULL) {
            if (trnd == trnd_aux) trnd_aux = NULL;
            if (trnd_aux && vtss_transport_delref(trnd_aux) == 0) {
                vtss_transport_complete(trnd_aux);
                TRACE("COMPLETE empty aux transport");
            }
            if (trnd && vtss_transport_delref(trnd) == 0) {
                vtss_transport_complete(trnd);
                TRACE("COMPLETE empty transport");
            }
            /* NOTE: tskd->trnd will be destroyed in vtss_transport_fini() */
        }
    }
    atomic_dec(&vtss_transport_busy);
}

struct vtss_target_list_item* vtss_target_find_in_temp_list_not_save(int pid)
{
    struct vtss_target_list_item* it = NULL;
    struct vtss_target_list_item* ret = NULL;
    struct list_head* p = NULL;
    list_for_each(p, &vtss_target_temp_list) {
        it = list_entry(p, struct vtss_target_list_item, list);
        if (it->pid == pid){
            ret = it;
            break;
        }
    }
    return ret;
}

void vtss_target_remove_from_temp_list(int pid, int failed)
{
    unsigned long flags;
    struct vtss_target_list_item* it = NULL;
    struct list_head* p = NULL;
    struct list_head* tmp = NULL;
    vtss_spin_lock_irqsave(&vtss_target_temp_list_lock, flags);
    list_for_each_safe(p, tmp, &vtss_target_temp_list) {
        it = list_entry(p, struct vtss_target_list_item, list);
        if (it->pid == pid){
            if (it->cnt == it->cnt_done){
                DEBUG_COLLECTOR("deleted completely from list, pid = %d, cnt = %d", pid, it->cnt);
                list_del(p);
                vtss_kfree(it);
            } else if (it->cnt < it->cnt_done){
                ERROR("ERROR in list!!!");
            } else {
                if (failed) it->cnt--; //queue_work failed. do it as it was before.
                else it->cnt_done++;
                DEBUG_COLLECTOR("deleted from list, pid = %d, cnt_done = %d, cnt = %d", pid, it->cnt_done, it->cnt);
            }
            break;
        }
    }
    vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);
}

int vtss_target_add_to_temp_list(int pid)
{
    unsigned long flags;
    struct vtss_target_list_item* item = NULL;
    
    vtss_spin_lock_irqsave(&vtss_target_temp_list_lock, flags);
    item = vtss_target_find_in_temp_list_not_save(pid);
    if (item){
        int cnt;
        item->cnt++;
        cnt = item->cnt;
        vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);
        DEBUG_COLLECTOR("added to list item %d, cnt %d", pid, cnt);
        return cnt;
    }
    item = (struct vtss_target_list_item*)vtss_kmalloc(sizeof(struct vtss_target_list_item), GFP_KERNEL);
    if (!item) {
        vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);
        ERROR("ERROR: No memory");
        return -1;
    }
    item->pid = pid;
    item->cnt = 0;
    item->cnt_done = 0;
    list_add_tail(&item->list, &vtss_target_temp_list);
    vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);
    DEBUG_COLLECTOR("added item pid %d, first time", pid);
    return 0;
}

int vtss_target_find_in_temp_list(int pid)
{
    unsigned long flags;
    struct vtss_target_list_item* it;
    struct list_head* p;
    int ret = -1;
    vtss_spin_lock_irqsave(&vtss_target_temp_list_lock, flags);
    list_for_each(p, &vtss_target_temp_list) {
        it = list_entry(p, struct vtss_target_list_item, list);
        if (it->pid == pid){
            ret = it->cnt_done;
            break;
        }
    }
    vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);
    return ret;
}

void vtss_target_clear_temp_list(void)
{
    unsigned long flags;
    struct vtss_target_list_item* it;
    struct list_head* p, *tmp;
    vtss_spin_lock_irqsave(&vtss_target_temp_list_lock, flags);
    list_for_each_safe(p, tmp, &vtss_target_temp_list) {
        it = list_entry(p, struct vtss_target_list_item, list);
        DEBUG_COLLECTOR("free pid = %d", it->pid);
        list_del(p);
        vtss_kfree(it);
    }
    INIT_LIST_HEAD(&vtss_target_temp_list);
    vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);
}

int vtss_target_wait_work_time(int id, int order)
{
    int cnt = 100000;
    int num = -1;
    if (order == -1){
        return 1;
    }
    while (cnt--){
        num = vtss_target_find_in_temp_list(id);
        if (num == -1){
            //finished!
            return 1;
        }
        if (num > order){
             return 1;
        }
        if (!irqs_disabled())
        {
            msleep_interruptible(1);
        }
        else
        {
            touch_nmi_watchdog();
        }
    }
    if(cnt <= 0) ERROR("Can not wait work %d with order %d, num = %d", id, order, num);
    return 0;
}

#if 0
struct vtss_target_exit_data
{
    pid_t fired_tid;
    pid_t fired_order;
};

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_target_exit_work(struct work_struct *work)
#else
static void vtss_target_exit_work(void *work)
#endif
{
    struct vtss_work* my_work = NULL;
    struct vtss_target_exit_data* data = NULL;
    vtss_task_map_item_t* item = NULL;
    struct vtss_task_data* tskd = NULL;
    if (!work){
        ERROR ("Internal error: exit have no any work to do");
        return;
    }

    DEBUG_COLLECTOR("state = %d", atomic_read(&vtss_collector_state));

    atomic_inc(&vtss_kernel_task_in_progress);
    DEBUG_COLLECTOR("after inc vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));

    if (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_STOPPED){ // It's OK to call this function in (un)initialization state
        ERROR("Internal error: exit work is called after collection was stopped");
    }
    my_work = (struct vtss_work*)work;
    data = (struct vtss_target_exit_data*)(my_work->data);
    if (data){
        DEBUG_COLLECTOR("before wait work time, tid = %d, fired order = %d", (int)data->fired_tid, data->fired_order);
        vtss_target_wait_work_time(data->fired_tid, data->fired_order);
        DEBUG_COLLECTOR("after wait work time, tid = %d, fired order = %d", (int)data->fired_tid, data->fired_order);
        item = vtss_task_map_get_item(data->fired_tid);
        if (item){
            tskd = (struct vtss_task_data*)&item->data;
            DEBUG_COLLECTOR("(%d:%d): data=0x%p, u=%d, n=%d",
                tskd->tid, tskd->pid, tskd, atomic_read(&item->usage), atomic_read(&vtss_target_count));
            /* release data */
            vtss_target_del(item);
            vtss_task_map_put_item(item);
        } else {
            ERROR("Exit work failed find item");
        }
    }

    atomic_dec(&vtss_kernel_task_in_progress);
    DEBUG_COLLECTOR("after dec vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));

    vtss_target_remove_from_temp_list(data->fired_tid, 0);
    vtss_kfree(work);
}
#endif

#if 0
struct vtss_target_exec_attach_data
{
    struct task_struct *task;
    char filename[VTSS_FILENAME_SIZE];
    char config[VTSS_FILENAME_SIZE];
    struct vtss_transport_data* new_trnd;
    struct vtss_transport_data* new_trnd_aux;
};

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_target_exec_attach_work(struct work_struct *work)
#else
static void vtss_target_exec_attach_work(void *work)
#endif
{
    int rc;
    struct vtss_work* my_work = (struct vtss_work*)work;
    struct vtss_target_exec_attach_data* data = (struct vtss_target_exec_attach_data*)(&my_work->data);
    if (!my_work){
        ERROR ("Internal error: exec have no any work to do");
        return;
    }
    if (VTSS_COLLECTOR_IS_READY_OR_INITING){
        data = (struct vtss_target_exec_attach_data*)(&my_work->data);
        rc = vtss_target_new(TASK_TID(data->task), TASK_PID(data->task), TASK_PID(TASK_PARENT(data->task)), data->filename, -1, -1);
        if (rc) {
            TRACE("(%d:%d): Error in vtss_target_new()=%d", TASK_TID(data->task), TASK_PID(data->task), rc);
            vtss_target_del_empty_transport(data->new_trnd, data->new_trnd_aux);
        }
    }
    vtss_kfree(work);
}
#endif

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_target_add_mmap_work(struct work_struct *work)
#else
static void vtss_target_add_mmap_work(void *work)
#endif
{
    //This function load module map in the case if smth was wrong during first time loading
    //This is workaround on the problem:
    //During attach the "transfer loop" is not activated till the collection started.
    //The ring buffer is overflow on module loading as nobody reads it and for huge module maps we have unknowns.
    //So, we have to schedule the new task and try again.
    struct vtss_work* my_work = (struct vtss_work*)work;
    vtss_task_map_item_t* item = NULL;
    struct vtss_task_data* tskd = NULL;
    struct task_struct* task = NULL;
    struct vtss_transport_data* trnd = NULL;

    if (my_work == NULL){
        ERROR("Internal error: vtss_target_add_map_work: work == NULL");
        atomic_dec(&vtss_kernel_task_in_progress);
        return;
    }
    item = *((vtss_task_map_item_t**)(&my_work->data));
    if (item == NULL){
        ERROR("Internal error: vtss_target_add_map_work: item == NULL");
        goto out1;
    }
    DEBUG_COLLECTOR("after inc vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));
    if (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_UNINITING){
         //No needs to add module map
         TRACE("adding mmap after stop, no need this");
         goto out;
    }
    tskd = (struct vtss_task_data*)&item->data;
    if (tskd == NULL){
        ERROR("Internal error: vtss_target_add_map_work: tskd == NULL");
        goto out;
    }

    trnd = VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux;
    if (trnd == NULL){
        ERROR("Internal error: vtss_target_add_map_work: tskd->trnd_aux == NULL");
        goto out;
    }
    if (VTSS_IS_COMPLETE(tskd)){
         //No needs to add module map
         TRACE("task is complete, no needs to load modules anymore");
         goto out;
    }
    task = vtss_find_task_by_tid(tskd->tid);
    if (task == NULL){
        ERROR("Internal error: vtss_target_add_map_work: tskd == NULL");
        goto out;
    }

    if (vtss_mmap_all(tskd, task)){
        msleep_interruptible(10); //wait again!
        ERROR("Module map was not loaded completely to the trace!");
        goto out;
    }
    if (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_UNINITING || vtss_kmap_all(tskd)){
        ERROR("Kernel map was not loaded completely to the trace!");
    }
    TRACE("(%d:%d): data=0x%p, u=%d, n=%d",
        tskd->tid, tskd->pid, tskd, atomic_read(&item->usage), atomic_read(&vtss_target_count));
out:
    /* release data */
    vtss_task_map_put_item(item);
out1:
    atomic_dec(&vtss_kernel_task_in_progress);
    DEBUG_COLLECTOR("after dec vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));
    vtss_kfree(work);
}

static inline int is_branch_overflow(struct vtss_task_data* tskd)
{
    int i;
    int f = 0;
    cpuevent_t* event;
    event = (cpuevent_t*)tskd->cpuevent_chain;
    if(!event) {
        return 0;
    }
    for(i = 0; i < VTSS_CFG_CHAIN_SIZE; i++)
    {
        if(!event[i].valid){
            break;
        }
        if((event[i].selmsk & 0xff) == 0xc4){
            f = 1;
            if(event[i].vft->overflowed(&event[i]))
            {
                return 1;
            }
        }
    }
    if(f){
      return 0;
    }
    return 1;
}

static inline int is_bts_enable(struct vtss_task_data* tskd)
{
    return ((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH) && is_branch_overflow(tskd));
}
static inline int is_callcount_enable(struct vtss_task_data* tskd)
{
    return ((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) || is_bts_enable(tskd));
}
static void vtss_callcount_disable(void)
{
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) vtss_disable_ipt();
    else vtss_bts_disable();
}
static void vtss_callcount_enable(void)
{
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) vtss_enable_ipt(reqcfg.ipt_cfg.mode, 0);
    else vtss_bts_enable();
}
static void vtss_profiling_pause(void)
{
    unsigned long flags;

    local_irq_save(flags);
    vtss_callcount_disable();
    vtss_pebs_disable();
    vtss_cpuevents_freeze();
    vtss_lbr_disable();
    local_irq_restore(flags);
}


static void vtss_profiling_resume(vtss_task_map_item_t* item, int bts_resume)
{
    int trace_flags = reqcfg.trace_cfg.trace_flags;
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
    int cpu;

    cpu = raw_smp_processor_id();

    tskd->state &= ~VTSS_ST_PMU_SET;

    atomic_inc(&vtss_transport_busy);
    if (atomic_read(&vtss_transport_state) != 1) {
        vtss_profiling_pause();
        atomic_dec(&vtss_transport_busy);
        return;
    }


    if (unlikely(!vtss_cpu_active(cpu) || VTSS_IS_COMPLETE(tskd))) {
        vtss_profiling_pause();
        atomic_dec(&vtss_transport_busy);
        return;
    }
    atomic_inc(&vtss_events_enabling);

    switch (atomic_read(&vtss_collector_state)) {
    case VTSS_COLLECTOR_RUNNING:
        // all calls of "trnd" should be under vtss_transport_initialized_rwlock.
        // this lock should be in caller function
        if (vtss_transport_is_overflowing(tskd->trnd)) {
#ifdef VTSS_OVERFLOW_PAUSE
            vtss_cmd_pause();
            vtss_profiling_pause();
            atomic_dec(&vtss_events_enabling);
            atomic_dec(&vtss_transport_busy);
            return;
#else
//            vtss_queue_work(cpu, vtss_overflow_work, &(tskd->trnd), sizeof(void*));
#endif
        }
        break;
#ifdef VTSS_OVERFLOW_PAUSE
    case VTSS_COLLECTOR_PAUSED:
        // all calls of with "trnd" should be under vtss_transport_initialized_rwlock.
        // this lock should be in caller function
        if (!vtss_transport_is_overflowing(tskd->trnd))
            vtss_cmd_resume();
#endif
    default:
        vtss_profiling_pause();
        atomic_dec(&vtss_events_enabling);
        atomic_dec(&vtss_transport_busy);
        return;
    }
    atomic_dec(&vtss_transport_busy);

    /* clear BTS/PEBS buffers */
    vtss_bts_init_dsa();
    vtss_pebs_init_dsa();
    vtss_dsa_init_cpu();
    /* always enable PEBS */
    vtss_pebs_enable();
    if (likely(VTSS_IS_CPUEVT(tskd))) {
        /* enable BTS (if requested) */
        if (is_callcount_enable(tskd) && (bts_resume  || (reqcfg.ipt_cfg.mode & vtss_iptmode_full)))
            vtss_callcount_enable();
        /* enable LBR (if requested) */
        if (trace_flags & VTSS_CFGTRACE_LASTBR)
            vtss_lbr_enable(&tskd->lbr);
        /* restart PMU events */
        VTSS_PROFILE(pmu, vtss_cpuevents_restart(tskd->cpuevent_chain, 0));
    } else {
        /* enable LBR (if requested) */
        if (trace_flags & VTSS_CFGTRACE_LASTBR)
            vtss_lbr_enable(&tskd->lbr);
        /* This need for Woodcrest and Clovertown */
        vtss_cpuevents_enable();
    }
    atomic_dec(&vtss_events_enabling);
    tskd->state |= VTSS_ST_PMU_SET;
    tskd->state &= ~VTSS_ST_CPUEVT;
}

static void vtss_target_dtr(vtss_task_map_item_t* item, void* args)
{
#ifdef VTSS_RECOVERY_LOGIC
    int cpu;
    unsigned long flags;
#endif
    struct task_struct *task = NULL;
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
    DEBUG_COLLECTOR(" (%d:%d): fini='%s'", tskd->tid, tskd->pid, tskd->filename);
    /* Set thread name in case of detach (exit has not been called) */
    if (tskd->taskname[0] == '\0')  {
        task = vtss_find_task_by_tid(tskd->tid);
        if (task != NULL) { /* task exist */
            vtss_get_task_comm(tskd->taskname, task);
            tskd->taskname[VTSS_TASKNAME_SIZE-1] = '\0';
        } else {
            ERROR(" (%d:%d): u=%d, n=%d task don't exist",
                    tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count));
        }
    } else {
        if ((strlen(tskd->taskname)==strlen("amplxe-runss")) && (!strcmp(tskd->taskname, "amplxe-runss"))){
            tskd->taskname[0]='\0';
        }
    }
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
    if (VTSS_IS_NOTIFIER(tskd)) {
        /* If forceful destruction from vtss_task_map_fini() */
        if (vtss_find_task_by_tid(tskd->tid) != NULL) { /* task exist */
            preempt_notifier_unregister(&tskd->preempt_notifier);
            tskd->state &= ~VTSS_ST_NOTIFIER;
        } else {
            ERROR(" (%d:%d): u=%d, n=%d task don't exist",
                    tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count));
        }
    }
#endif
#ifdef VTSS_RECOVERY_LOGIC
    /* Clear per_cpu recovery data for this tskd */
    vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
    for_each_possible_cpu(cpu) {
        if (per_cpu(vtss_recovery_tskd, cpu) == tskd)
            per_cpu(vtss_recovery_tskd, cpu) = NULL;
    }
    vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
#endif

    /* Finish trace transport */
    atomic_inc(&vtss_transport_busy);
    if (atomic_read(&vtss_transport_state) == 1) {
        if (tskd->trnd != NULL) {
            if (tskd->trnd == tskd->trnd_aux)tskd->trnd_aux = NULL;
            if (vtss_record_thread_name(tskd->trnd, tskd->tid, (const char*)tskd->taskname, NOT_SAFE)) {
                TRACE("vtss_record_thread_name() FAIL");
            }
            if (vtss_record_thread_stop(tskd->trnd, tskd->tid, tskd->pid, tskd->cpu, NOT_SAFE)) {
                TRACE("vtss_record_thread_stop() FAIL");
            }
            if (tskd->trnd_aux && vtss_transport_delref(tskd->trnd_aux) == 0) {
                if (vtss_record_magic(tskd->trnd_aux, NOT_SAFE)) {
                    TRACE("vtss_record_magic() FAIL");
                }
                vtss_transport_complete(tskd->trnd_aux);
                TRACE(" (%d:%d): COMPLETE", tskd->tid, tskd->pid);
            }
            if (vtss_transport_delref(tskd->trnd) == 0) {
                if (vtss_record_process_exit(tskd->trnd, tskd->tid, tskd->pid, tskd->cpu, (const char*)tskd->filename, NOT_SAFE)) {
                    TRACE("vtss_record_process_exit() FAIL");
                }
                if (vtss_record_magic(tskd->trnd, NOT_SAFE)) {
                    TRACE("vtss_record_magic() FAIL");
                }
                vtss_transport_complete(tskd->trnd);
                TRACE(" (%d:%d): COMPLETE", tskd->tid, tskd->pid);
            }
            tskd->trnd = NULL;
            tskd->trnd_aux = NULL;
            /* NOTE: tskd->trnd will be destroyed in vtss_transport_fini() */
        }
    }
    atomic_dec(&vtss_transport_busy);

    tskd->stk.destroy(&tskd->stk);
}

struct vtss_target_new_data
{
    pid_t tid;
    pid_t pid;
    pid_t ppid;
    
    int fired_tid;
    int fired_order;

    vtss_task_map_item_t *item;
};

#ifdef VTSS_RECOVERY_LOGIC
static void vtss_clear_recovery(struct vtss_task_data *tskd)
{
    if (tskd && tskd->cpu >= 0){
        unsigned long flags;
        vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
        DEBUG_COLLECTOR("clear recovery, cpu = %d", tskd->cpu);
        per_cpu(vtss_recovery_tskd, tskd->cpu) = NULL;
        vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
    }
}
#endif

int vtss_target_new_part1(pid_t tid, pid_t pid, pid_t ppid, vtss_task_map_item_t *item)
{
    struct task_struct *task;
    struct vtss_task_data *tskd;
    
    struct vtss_transport_data* trnd = NULL;
    struct vtss_transport_data* trnd_aux = NULL;
    
    if (!VTSS_COLLECTOR_IS_READY){ //If adding the task is not actual anymore
        DEBUG_COLLECTOR("The task tid = %d will not be added as collection already stopped", tid);
        return 0;
    }
    tskd = (struct vtss_task_data*)&item->data;
    trnd = tskd->trnd;
    trnd_aux = tskd->trnd_aux;

    /* Transport initialization */
    if (tskd->tid == tskd->pid) { /* New process */
        if (!trnd){
            vtss_target_transport_create(&trnd, &trnd_aux, tskd->ppid, tskd->pid, vtss_session_uid, vtss_session_gid);
        }
        if (trnd == NULL) {
            ERROR(" (%d:%d): Unable to create transport", tid, pid);
            return -ENOMEM;
        }
        tskd->trnd = trnd; 
        if (tskd->trnd != NULL) {
            //if aux transport was not created early, then use the same transport as for samples.
            tskd->trnd_aux = trnd_aux ? trnd_aux : tskd->trnd;
        }
        if (tskd->trnd != NULL && tskd->trnd_aux != NULL) {
            if (vtss_record_configs(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, SAFE)) {
                TRACE("vtss_record_configs() FAIL");
            }
            if (vtss_record_process_exec(tskd->trnd, tskd->tid, tskd->pid, tskd->cpu, (const char*)tskd->filename, SAFE)) {
                TRACE("vtss_record_process_exec() FAIL");
            }
        }
    } else { /* New thread */
        struct vtss_task_data *tskd0;
        vtss_task_map_item_t *item0 = vtss_task_map_get_item(tskd->pid);
        if (item0 == NULL) {
            ERROR(" (%d:%d): Unable to find main thread", tskd->tid, tskd->pid);
            return -ENOENT;
        }
        tskd0 = (struct vtss_task_data*)&item0->data;
        tskd->trnd = tskd0->trnd;
        tskd->trnd_aux = tskd0->trnd_aux;
        if (tskd->trnd != NULL) {
            vtss_transport_addref(tskd->trnd);
        }
        if (tskd->trnd!=tskd->trnd_aux && tskd->trnd_aux != NULL) {
            vtss_transport_addref(tskd->trnd_aux);
        }
        vtss_task_map_put_item(item0);
    }
    if (tskd->trnd == NULL) {
        ERROR(" (%d:%d): Unable to create transport", tskd->tid, tskd->pid);
        return -ENOMEM;
    }
    /* Create cpuevent chain */
    memset(tskd->cpuevent_chain, 0, VTSS_CFG_CHAIN_SIZE*sizeof(cpuevent_t));
    vtss_cpuevents_upload(tskd->cpuevent_chain, &reqcfg.cpuevent_cfg_v1[0], reqcfg.cpuevent_count_v1);
    /* Store first records */
    if (likely(VTSS_NEED_STORE_NEWTASK(tskd)))
        VTSS_STORE_NEWTASK(tskd, SAFE);
    if (likely(VTSS_NEED_STORE_SOFTCFG(tskd)))
        VTSS_STORE_SOFTCFG(tskd, SAFE);
    if (likely(VTSS_NEED_STORE_PAUSE(tskd)))
        VTSS_STORE_PAUSE(tskd, tskd->cpu, 0x66 /* tpss_pi___itt_pause from TPSS ini-file */, SAFE);
    /* ========================================================= */
    /* Add new item in task map. Tracing starts after this call. */
    /* ========================================================= */
    if (!vtss_task_map_add_item(item))
        atomic_inc(&vtss_target_count);
    DEBUG_COLLECTOR("(%d:%d): u=%d, n=%d, init='%s'",
        tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count), tskd->filename);
    task = vtss_find_task_by_tid(tskd->tid);
    DEBUG_COLLECTOR("Found task = %p", task);
    if (task != NULL && !(task->state & TASK_DEAD)) { /* task exist */
#ifdef VTSS_GET_TASK_STRUCT
        get_task_struct(task);
#endif
        /* Setting up correct arch (32-bit/64-bit) of user application */
        tskd->m32 = test_tsk_thread_flag(task, TIF_IA32) ? 1 : 0;
        tskd->stk.lock(&tskd->stk);
        tskd->stk.wow64 = tskd->m32;
        tskd->stk.clear(&tskd->stk);
        tskd->stk.unlock(&tskd->stk);
#ifdef VTSS_SYSCALL_TRACE
        /* NOTE: Need this for BP save and FIXUP_TOP_OF_STACK into pt_regs
         * when is called from the SYSCALL. Actual only for 64-bit kernel! */
        set_tsk_thread_flag(task, TIF_SYSCALL_TRACE);
#endif
        if (tskd->tid == tskd->pid) { /* New process */
            unsigned long addr = VTSS_EVENT_LOST_MODULE_ADDR;
            unsigned long size = 1;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
            unsigned long dyn_addr = 0;
#endif

            long long cputsc, realtsc;
            vtss_time_get_sync(&cputsc, &realtsc);
            if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, addr, size, VTSS_EVENT_LOST_MODULE_NAME, 0, cputsc, realtsc, SAFE)) {
                TRACE("vtss_record_module() FAIL");
            }
            addr = VTSS_KSTART;
            /* TODO: reduce the size to real instead of maximum */
            size = VTSS_KSIZE;
#ifdef CONFIG_RANDOMIZE_BASE
#ifdef CONFIG_KALLSYMS
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
            /* fixup kernel start address for newest kernels */
            dyn_addr = kallsyms_lookup_name("_text") & ~(PAGE_SIZE - 1);
            if(dyn_addr > addr) {
                TRACE("vmlinux addr=0x%lx, dyn_addr=0x%lx", addr, dyn_addr);
                size -= (dyn_addr - addr);
                addr = dyn_addr;
            }
            else if(!dyn_addr) {
                dyn_addr = kallsyms_lookup_name("_stext") & ~(PAGE_SIZE - 1);
                if(dyn_addr > addr) {
                    TRACE("vmlinux addr=0x%lx, stext dyn_addr=0x%lx", addr, dyn_addr);
                    size -= (dyn_addr - addr);
                    addr = dyn_addr;
                }
            }
#endif
#endif
#endif
            if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, 0, addr, size, "vmlinux", 0, cputsc, realtsc, SAFE)) {
                TRACE("vtss_record_module() FAIL");
            }
#ifdef CONFIG_X86_64
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
            addr = (unsigned long)VSYSCALL_START;
            size = (unsigned long)(VSYSCALL_MAPPED_PAGES * PAGE_SIZE);
#else
            addr = (unsigned long)VSYSCALL_ADDR;
            size = (unsigned long)PAGE_SIZE;
#endif
            if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, 0, addr, size, "[vsyscall]", 0, cputsc, realtsc, SAFE)) {
                TRACE("vtss_record_module() FAIL");
            }
#endif
            if (irqs_disabled() || vtss_mmap_all(tskd, task) || vtss_kmap_all(tskd)){
                 // we have to try load map again!
                 vtss_task_map_item_t* item_temp = vtss_task_map_get_item(tskd->tid);
                 if (item == item_temp) {
                    DEBUG_COLLECTOR("Map file was not loaded completely. Arranged the task to finish this");
                    atomic_inc(&vtss_kernel_task_in_progress);
                    if (vtss_queue_work(-1, vtss_target_add_mmap_work, &item, sizeof(item))) {
                        ERROR("Internal error: add mmap task was not arranged");
                        atomic_dec(&vtss_kernel_task_in_progress);
                        vtss_task_map_put_item(item_temp);
                    } else {
                        set_tsk_need_resched(current);
                    }
                } else {
                    vtss_task_map_put_item(item_temp);
                    ERROR("Internal error: task map error");
                }
            } else {
                TRACE("Modules are added");
            }
        }
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
        /**
         * TODO: add to task, not to current !!!
         * This API will be added in future version of kernel:
         * preempt_notifier_register_task(&tskd->preempt_notifier, task);
         * So far I should use following:
         */
        hlist_add_head(&tskd->preempt_notifier.link, &task->preempt_notifiers);
        tskd->state |= VTSS_ST_NOTIFIER;
#endif
#ifdef VTSS_GET_TASK_STRUCT
        vtss_put_task_struct(task);
#endif
    } else {
        char dbgmsg[128];
        int rc = snprintf(dbgmsg, sizeof(dbgmsg)-1, "vtss_target_new(%d,%d,%d,'%s'): u=%d, n=%d task(%ld) don't exist or not valid.",
                tskd->tid, tskd->pid, tskd->ppid, tskd->filename, atomic_read(&item->usage), atomic_read(&vtss_target_count), task ? task->state : 0);
        if (rc > 0 && rc < sizeof(dbgmsg)-1) {
            dbgmsg[rc] = '\0';
            vtss_record_debug_info(tskd->trnd, dbgmsg, 0);
        }
        DEBUG_COLLECTOR("The new task is not valid. The task is not added to profile (%d:%d): u=%d, n=%d, done='%s'",
                tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count), tskd->filename);
        vtss_target_del(item);
        return 0;
    }

    DEBUG_COLLECTOR("end: (%d:%d): u=%d, n=%d, done='%s'",
            tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count), tskd->filename);
    return 0;
}

#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_target_new_part2(struct work_struct *work)
#else
static void vtss_target_new_part2(void *work)
#endif
{
    struct vtss_work* my_work = (struct vtss_work*)work;
    struct vtss_target_new_data* data = NULL;

    DEBUG_COLLECTOR("vtss_target_new");

    if (!my_work){
        ERROR ("Internal error: target_new have no any work to do");
        atomic_dec(&vtss_kernel_task_in_progress);
        return;
    }

    DEBUG_COLLECTOR("after inc vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));
    if (VTSS_COLLECTOR_IS_READY){
        data = (struct vtss_target_new_data*)(&my_work->data);
        if (!data){
            ERROR ("Internal error: no data in work");
            goto out;
        }
        if (data->fired_tid != -1){
          DEBUG_COLLECTOR("awaiting fired order = %d for tid = %d", data->fired_order, data->fired_tid);
          if (!vtss_target_wait_work_time(data->fired_tid, data->fired_order))
              DEBUG_COLLECTOR("wait task failed");
          DEBUG_COLLECTOR("stop awaiting");
        }
        if (VTSS_COLLECTOR_IS_READY) //If adding the task still actual after wait
        /**data->rc =*/ vtss_target_new_part1(data->tid, data->pid, data->ppid, data->item);

    } else {
        DEBUG_COLLECTOR("newask after collection is done");
    }

    vtss_target_remove_from_temp_list(data->tid, 0);

    DEBUG_COLLECTOR("after removing from the list");
out:
    vtss_task_map_put_item(data->item);
    vtss_kfree(work);
    DEBUG_COLLECTOR("after free work");
    atomic_dec(&vtss_kernel_task_in_progress);
    DEBUG_COLLECTOR("after dec vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));

    return;
}

static void vtss_sched_switch_to(vtss_task_map_item_t* item, struct task_struct* task, void* ip);
int vtss_target_new(pid_t tid, pid_t pid, pid_t ppid, const char* filename, int fired_tid, int fired_order)
{
    int rc = 0;
    size_t size = 0;

    vtss_task_map_item_t *item = NULL;
    struct vtss_task_data *tskd = NULL;
    struct task_struct *task = NULL;

    DEBUG_COLLECTOR("vtss_target_new(%d,%d,%d) \n",tid, pid, ppid);

    if (atomic_read(&vtss_transport_state) != 1){
        ERROR(" (%d:%d): Transport not initialized", tid, pid);
        return VTSS_ERR_INTERNAL;
    }

    atomic_inc(&vtss_kernel_task_in_progress);

    if (!VTSS_COLLECTOR_IS_READY){ //If adding the task is not actual anymore
        DEBUG_COLLECTOR("The task tid = %d will not be added as collection already stopped", tid);
        atomic_dec(&vtss_kernel_task_in_progress);
        return 0;
    }

    item = vtss_task_map_alloc(tid, sizeof(struct vtss_task_data), vtss_target_dtr, GFP_KERNEL);

    if (item == NULL) {
        ERROR(" (%d:%d): Unable to allocate, size = %d", tid, pid, (int)sizeof(struct vtss_task_data));
        atomic_dec(&vtss_kernel_task_in_progress);
        return -ENOMEM;
    }

    tskd = (struct vtss_task_data*)&item->data;
    tskd->tid        = tid;
    tskd->pid        = pid;
    tskd->trnd       = NULL;
    tskd->trnd_aux   = NULL;
    tskd->ppid       = ppid;

    tskd->m32        = 0; /* unknown so far, assume native */
    tskd->ip         = NULL;
    tskd->cpu = raw_smp_processor_id();
    tskd->from_ip    = NULL;
#ifndef VTSS_NO_BTS
    tskd->bts_size   = 0;
#endif
    tskd->state      = (VTSS_ST_NEWTASK | VTSS_ST_SOFTCFG | VTSS_ST_STKDUMP);
    if (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_PAUSED)
        tskd->state |= VTSS_ST_PAUSE;
#ifdef VTSS_SYSCALL_TRACE
    tskd->syscall_sp = NULL;
    tskd->syscall_enter = 0ULL;
#endif
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
    preempt_notifier_init(&tskd->preempt_notifier, &vtss_preempt_ops);
#endif
    rc = vtss_init_stack(&tskd->stk);
    if (rc) {
        ERROR(" (%d:%d): Unable to init STK: %d", tid, pid, rc);
        atomic_dec(&vtss_kernel_task_in_progress);
        return rc;
    }
    task = vtss_find_task_by_tid(tskd->tid);
    if (task != NULL && !(task->state & TASK_DEAD)&&task->comm != NULL) { /* task exist */
        size = min((size_t)VTSS_FILENAME_SIZE-1, (size_t)strnlen(task->comm, TASK_COMM_LEN));
        memcpy(tskd->filename, task->comm, size);
    } else if (filename != NULL) {
        size = min((size_t)VTSS_FILENAME_SIZE-1, (size_t)strlen(filename));
        memcpy(tskd->filename, filename, size);
    }
    tskd->filename[size] = '\0';
    tskd->taskname[0] = '\0';

    if (tid == pid){
        vtss_target_transport_create(&tskd->trnd, &tskd->trnd_aux, ppid, pid, vtss_session_uid, vtss_session_gid);
    }
    if((!irqs_disabled() || (tskd->trnd && tskd->trnd_aux))){
        if (fired_tid!=-1){
            DEBUG_COLLECTOR("awaiting fired order = %d for tid = %d", fired_order, fired_tid);
            vtss_target_wait_work_time(fired_tid, fired_order);
            DEBUG_COLLECTOR("stop awaiting");
        }

        rc = vtss_target_new_part1(tid, pid, ppid, item);

        if (task == current /*|| tskd->tid == TASK_TID(current)*/)
        {
            DEBUG_COLLECTOR("mark swap in");
            tskd->from_ip = (void*)_THIS_IP_;
            vtss_sched_switch_to(item, task, NULL);
        }
        vtss_task_map_put_item(item);

        atomic_dec(&vtss_kernel_task_in_progress);
    } else {
        struct vtss_target_new_data data;

        data.tid = tid;
        data.pid = pid;
        data.ppid = ppid;

        data.fired_tid = fired_tid;
        data.fired_order = fired_order;
        data.item = item;

        vtss_target_add_to_temp_list(data.tid);

        if ((rc = vtss_queue_work(-1, vtss_target_new_part2, &data, sizeof(data)))) {
              vtss_task_map_put_item(item);
              atomic_dec(&vtss_kernel_task_in_progress);
              vtss_target_remove_from_temp_list(data.tid, 1);
        } else {
            set_tsk_need_resched(current);
        }
    }
    DEBUG_COLLECTOR("Target added: rc = %d", rc);
    return rc;
}

int vtss_target_del(vtss_task_map_item_t* item)
{
    vtss_task_map_del_item(item);
    if (atomic_dec_and_test(&vtss_target_count)) {
        //This function should be called after transport deinitialization
        //vtss_procfs_ctrl_wake_up(NULL, 0);
    }
    return 0;
}

void vtss_target_fork(struct task_struct *task, struct task_struct *child)
{
    if(!VTSS_COLLECTOR_IS_READY){
         //vtss collector is unitialized
         return;
    }
     if (task != NULL && child != NULL) {
        int fired_order = -1;
        vtss_task_map_item_t* item = NULL;

        fired_order = vtss_target_find_in_temp_list(TASK_TID(task));
        if (fired_order !=-1){
            DEBUG_COLLECTOR("fired_order = %d", fired_order);
            vtss_target_new(TASK_TID(child), TASK_PID(child), TASK_TID(task), task->comm, TASK_TID(task), fired_order);
        } else {
            item = vtss_task_map_get_item(TASK_TID(task));
        }
        if (item) {
            struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

            DEBUG_COLLECTOR("(%d:%d)=>(%d:%d): u=%d, n=%d, file='%s', irqs=%d",
                  TASK_TID(task), TASK_PID(task), TASK_TID(child), TASK_PID(child),
                  atomic_read(&item->usage), atomic_read(&vtss_target_count), tskd->filename, !irqs_disabled());
            preempt_disable();
            tskd->cpu = smp_processor_id();
            preempt_enable_no_resched();
            {
                int rc = 0;
                rc = vtss_target_new(TASK_TID(child), TASK_PID(child), TASK_PID(task), tskd->filename, -1, -1);
                if (unlikely(rc)) ERROR("(%d:%d): Error in vtss_target_new()=%d. Fork failed!", TASK_TID(task), TASK_PID(task), rc);
            } 
            vtss_task_map_put_item(item);
        }
    }
}

void vtss_target_exec_enter(struct task_struct *task, const char *filename, const char *config)
{
    vtss_task_map_item_t* item;
    int fired_order = -1;

    vtss_profiling_pause();
    if(!VTSS_COLLECTOR_IS_READY){
         //vtss collector is unitialized
         TRACE("Not ready");
         return;
    }
    if (atomic_read(&vtss_transport_state)!=1) return;
    fired_order = vtss_target_find_in_temp_list(TASK_TID(task));
    if (fired_order !=-1)
        vtss_target_wait_work_time(TASK_TID(task), fired_order);
    item = vtss_task_map_get_item(TASK_TID(task));
    if (item != NULL) {
        struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

        DEBUG_COLLECTOR("(%d:%d): u=%d, n=%d, file='%s'",
                tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count), filename);
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
        if (VTSS_IS_NOTIFIER(tskd)) {
            preempt_notifier_unregister(&tskd->preempt_notifier);
            tskd->state &= ~VTSS_ST_NOTIFIER;
        }
#endif
        if (task != NULL){
            //tskd->taskname[0]='\0';
            //the lines below leads a bug when thread name is shown as amplxe_runss. We need fix it in GUI part before.
            size_t size =  min((size_t)VTSS_TASKNAME_SIZE-1, (size_t)strlen(task->comm));
            strncpy(tskd->taskname, task->comm, size);
            tskd->taskname[size]='\0';
        }
        tskd->taskname[VTSS_TASKNAME_SIZE-1] = '\0';

        tskd->state |= VTSS_ST_COMPLETE;
        vtss_task_map_put_item(item);
    }
}
           
void vtss_target_exec_leave(struct task_struct *task, const char *filename, const char *config, int rc, int fired_tid)
{
    vtss_task_map_item_t* item = NULL;
    int fired_order = -1;
    
    if(!VTSS_COLLECTOR_IS_READY) {
        //vtss collector is unitialized
        TRACE("collector is not initialized");
        return;
    }
    fired_order = vtss_target_find_in_temp_list(fired_tid);
    if (fired_order !=-1){
        if (rc == 0) vtss_target_new(TASK_TID(task), TASK_PID(task), TASK_PID(TASK_PARENT(task)), filename, fired_tid, fired_order);
    } else {
        item = vtss_task_map_get_item(fired_tid);
    }
    if (item) {
        struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

        DEBUG_COLLECTOR("(%d:%d); file='%s', rc=%d, item = %p, u:%d",TASK_PID(TASK_PARENT(task)), TASK_PID(task), filename, rc, item, atomic_read(&item->usage));
        if (rc == 0) { /* Execution success, so start tracing new process */

            preempt_disable();
            tskd->cpu = smp_processor_id();
            preempt_enable_no_resched();
            vtss_target_new(TASK_TID(task), TASK_PID(task), TASK_PID(TASK_PARENT(task)), filename, -1, -1);

        } else { /* Execution failed, so restore tracing current process */
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
            /**
             * TODO: add to task, not to current !!!
             * This API will be added in future version of kernel:
             * preempt_notifier_register_task(&tskd->preempt_notifier, task);
             * So far I should use following:
             */
            hlist_add_head(&tskd->preempt_notifier.link, &task->preempt_notifiers);
            tskd->state |= VTSS_ST_NOTIFIER;
#endif
            tskd->state &= ~VTSS_ST_COMPLETE;
            tskd->state |= VTSS_ST_PMU_SET;
        }
        DEBUG_COLLECTOR("old item usage = %d", atomic_read(&item->usage));

        vtss_task_map_put_item(item);
        
    } else{
       if (*config != '\0' && rc == 0) { /* attach to current process */


         vtss_target_new(TASK_TID(task), TASK_PID(task), TASK_PID(TASK_PARENT(task)), filename, -1, -1);
      }
    }
}

static void vtss_dump_save_events(struct vtss_task_data* tskd)
{
unsigned long flags;
local_irq_save(flags);
preempt_disable();
if (VTSS_IN_CONTEXT(tskd)){
    if (unlikely((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) && (reqcfg.ipt_cfg.mode & vtss_iptmode_full))){
        VTSS_PROFILE(bts, vtss_dump_ipt(VTSS_PT_FLUSH_MODE ? tskd->trnd_aux : tskd->trnd, tskd->tid, tskd->cpu, 0));
    }
}
preempt_enable_no_resched();
local_irq_restore(flags);

}

void vtss_target_exit(struct task_struct *task)
{
    vtss_task_map_item_t* item = NULL;
    int fired_order = -1;

    vtss_profiling_pause();

    fired_order = vtss_target_find_in_temp_list(TASK_TID(task));
    if (fired_order !=-1)
        vtss_target_wait_work_time(TASK_TID(task), fired_order);
    item = vtss_task_map_get_item(TASK_TID(task));
    
    if (item != NULL) {
        struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
#ifdef VTSS_RECOVERY_LOGIC
        int cpu = -1;
        unsigned long flags;
#endif
        if (!tskd){
            ERROR("!tskd");
        }else DEBUG_COLLECTOR("tskd=%p", tskd);
        DEBUG_COLLECTOR("(%d:%d): u=%d, n=%d, file='%s', irqs=%d",
              tskd->tid, tskd->pid, atomic_read(&item->usage), atomic_read(&vtss_target_count), tskd->filename, !irqs_disabled());
#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)
        if (VTSS_IS_NOTIFIER(tskd)) {
            preempt_notifier_unregister(&tskd->preempt_notifier);
            tskd->state &= ~VTSS_ST_NOTIFIER;
        }
#endif
        vtss_dump_save_events(tskd);
#ifdef VTSS_RECOVERY_LOGIC
        vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
        for_each_possible_cpu(cpu) {
            if (per_cpu(vtss_recovery_tskd, cpu) == tskd)
                per_cpu(vtss_recovery_tskd, cpu) = NULL;
        }
        vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
#endif
        
        tskd->cpu = raw_smp_processor_id();

        tskd->state |= VTSS_ST_COMPLETE;
        vtss_dump_save_events(tskd);
        if (task != NULL){
            size_t size =  min((size_t)VTSS_TASKNAME_SIZE-1, (size_t)strlen(task->comm));
            strncpy(tskd->taskname, task->comm, size);
            tskd->taskname[size]='\0';
        }
        tskd->taskname[VTSS_TASKNAME_SIZE-1] = '\0';
        DEBUG_COLLECTOR("before del");
        vtss_target_del(item);
        DEBUG_COLLECTOR("after del");
        vtss_task_map_put_item(item);
        DEBUG_COLLECTOR("after put");
    }
}

#ifdef VTSS_SYSCALL_TRACE

static struct vtss_task_data* vtss_wait_for_completion(vtss_task_map_item_t** pitem)
{
    unsigned long i;
    struct vtss_task_data* tskd = (struct vtss_task_data*)&((*pitem)->data);

    /* It's task after exec(), so waiting for re-initialization */
    DEBUG_COLLECTOR("Waiting task: 0x%p ....", current);
    for (i = 0; i < 1000000UL && *pitem != NULL && atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_RUNNING; i++) {
        vtss_task_map_put_item(*pitem);
        /* TODO: waiting... */
        *pitem = vtss_task_map_get_item(TASK_TID(current));
        if (*pitem != NULL) {
            tskd = (struct vtss_task_data*)&((*pitem)->data);
            if (!VTSS_IS_COMPLETE(tskd))
                break;
        }
    }
    DEBUG_COLLECTOR("Waiting task: 0x%p done(%lu)", current, i);
    if (*pitem == NULL) {
        ERROR("Tracing task 0x%p error", current);
        return NULL;
    } else if (VTSS_IS_COMPLETE(tskd)) {
        DEBUG_COLLECTOR("Task 0x%p wait timeout", current);
        vtss_task_map_put_item(*pitem);
        return NULL;
    }
    return tskd;
}

void vtss_syscall_enter(struct pt_regs* regs)
{
    vtss_task_map_item_t* item = vtss_task_map_get_item(TASK_TID(current));

    if (item != NULL) {
        struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

        TRACE("task=0x%p, syscall=%.3ld, ip=0x%lx, sp=0x%lx, bp=0x%lx",
            current, REG(orig_ax, regs), REG(ip, regs), REG(sp, regs), REG(bp, regs));
        if (unlikely(VTSS_IS_COMPLETE(tskd)))
            tskd = vtss_wait_for_completion(&item);
        if (tskd != NULL) {
            /* Just store BP register for following unwinding */
            tskd->syscall_sp = (void*)REG(sp, regs);
            tskd->syscall_enter = (atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_RUNNING) ? vtss_time_cpu() : 0ULL;
            tskd->state |= VTSS_ST_IN_SYSCALL;
            vtss_task_map_put_item(item);
        }
    }
}

void vtss_syscall_leave(struct pt_regs* regs)
{
    vtss_task_map_item_t* item = vtss_task_map_get_item(TASK_TID(current));

    if (item != NULL) {
        struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

        TRACE("task=0x%p, syscall=%.3ld, ip=0x%lx, sp=0x%lx, bp=0x%lx, ax=0x%lx",
            current, REG(orig_ax, regs), REG(ip, regs), REG(sp, regs), REG(bp, regs), REG(ax, regs));
        if (VTSS_IN_SYSCALL(tskd) && tskd->syscall_enter && atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_RUNNING) {
            tskd->tcb.syscall_count++;
            tskd->tcb.syscall_duration += vtss_time_cpu() - tskd->syscall_enter;
        }
        tskd->state &= ~VTSS_ST_IN_SYSCALL;
        tskd->syscall_sp = NULL;
        vtss_task_map_put_item(item);
    }
}

#endif /* VTSS_SYSCALL_TRACE */

static int vtss_kmap_all(struct vtss_task_data* tskd)
{
    struct module* mod;
    struct list_head* modules;
    long long cputsc, realtsc;
    int repeat = 0;

    if (VTSS_IS_MMAP_INIT(tskd)){
        ERROR("Kernel map was not loaded because currently the map is in initialized state");
        return 1;
    }
#ifdef VTSS_AUTOCONF_MODULE_MUTEX
    mutex_lock(&module_mutex);
#endif
    VTSS_SET_MMAP_INIT(tskd);
    vtss_time_get_sync(&cputsc, &realtsc);
    for(modules = THIS_MODULE->list.prev; (unsigned long)modules > MODULES_VADDR; modules = modules->prev);
    list_for_each_entry(mod, modules, list){
        const char *name   = mod->name;
#ifdef VTSS_AUTOCONF_MODULE_CORE_LAYOUT
        unsigned long addr = (unsigned long)mod->core_layout.base;
        unsigned long size = mod->core_layout.size;
#else
        unsigned long addr = (unsigned long)mod->module_core;
        unsigned long size = mod->core_size;
#endif
        if (module_is_live(mod)) {
            TRACE("module: addr=0x%lx, size=%lu, name='%s'", addr, size, name);
            if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, 0, addr, size, name, 0, cputsc, realtsc, SAFE)) {
                TRACE("vtss_record_module() FAIL");
                repeat = 1;
            }
        }
    }
    VTSS_CLEAR_MMAP_INIT(tskd);
#ifdef VTSS_AUTOCONF_MODULE_MUTEX
    mutex_unlock(&module_mutex);
#endif
    return repeat;
}

void vtss_kmap(struct task_struct* task, const char* name, unsigned long addr, unsigned long pgoff, unsigned long size)
{
    vtss_task_map_item_t* item = NULL;

    if (!task) return;

    item = vtss_task_map_get_item(TASK_TID(task));
    atomic_inc(&vtss_transport_busy);
    if (atomic_read(&vtss_transport_state) == 1) {
        if (item != NULL) {
            struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
            long long cputsc, realtsc;

            if (!VTSS_IS_MMAP_INIT(tskd)){
                vtss_time_get_sync(&cputsc, &realtsc);
                TRACE("addr=0x%lx, size=%lu, name='%s', pgoff=%lu", addr, size, name, pgoff);
                if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, 0, addr, size, name, pgoff, cputsc, realtsc, SAFE)) {
                     ERROR("vtss_record_module() FAIL");
                }
            }
        }
    }
    atomic_dec(&vtss_transport_busy);
    if (item != NULL) vtss_task_map_put_item(item);
}

static int vtss_mmap_all(struct vtss_task_data* tskd, struct task_struct* task)
{
    struct mm_struct *mm;
    char *pname, *tmp = (char*)vtss_get_free_page(GFP_KERNEL);
    int repeat = 0;

    if (!tmp){
        ERROR("No memory");
        return 1;
    }
    if (VTSS_IS_MMAP_INIT(tskd)){
        ERROR("Module map was not loaded because currently the map is in initialized state");
        return 1;
    }
    if ((mm = get_task_mm(task)) != NULL) {
        int is_vdso_found = 0;
        struct vm_area_struct* vma;
        long long cputsc, realtsc;
        VTSS_SET_MMAP_INIT(tskd);
        vtss_time_get_sync(&cputsc, &realtsc);
        down_read(&mm->mmap_sem);
        for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
            TRACE("vma=[0x%lx - 0x%lx], flags=0x%lx", vma->vm_start, vma->vm_end, vma->vm_flags);
            if (((vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_MAYEXEC)) && !(vma->vm_flags & VM_WRITE) &&
                vma->vm_file && vma->vm_file->f_path.dentry)
            {
                pname = D_PATH(vma->vm_file, tmp, PAGE_SIZE);
                if (!IS_ERR(pname)) {
                    TRACE("addr=0x%lx, size=%lu, file='%s', pgoff=%lu", vma->vm_start, (vma->vm_end - vma->vm_start), pname, vma->vm_pgoff);
                    if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, vma->vm_start, (vma->vm_end - vma->vm_start), pname, vma->vm_pgoff, cputsc, realtsc, SAFE)) {
                        TRACE("vtss_record_module() FAIL");
                        repeat = 1;
                    }
                }
#ifdef VM_HUGEPAGE
            /**
             * Try to recover the mappings of some hugepages
             * by looking at segments immediately precede and
             * succeed them 
             */
            } else if ((vma->vm_flags & VM_HUGEPAGE) &&
                ((vma->vm_flags & VM_EXEC) || (vma->vm_flags & VM_MAYEXEC)) && !(vma->vm_flags & VM_WRITE) &&
                !vma->vm_file)
            {
                struct vm_area_struct *vma_pred = find_vma(mm, vma->vm_start - 1);
                struct vm_area_struct *vma_succ = find_vma(mm, vma->vm_end);
                if (vma_pred && vma_succ) {
                    if (((vma_pred->vm_flags & VM_EXEC) || (vma_pred->vm_flags & VM_MAYEXEC)) && !(vma_pred->vm_flags & VM_WRITE) &&
                        vma_pred->vm_file && vma_pred->vm_file->f_path.dentry) {
                        char *pname_pred = D_PATH(vma_pred->vm_file, tmp, PAGE_SIZE);
                        if (!IS_ERR(pname_pred)) {
                            if (vma_succ->vm_file && vma_succ->vm_file->f_path.dentry) {
                                char *pname_succ = D_PATH(vma_succ->vm_file, tmp, PAGE_SIZE);
                                if (!IS_ERR(pname_succ)) {
                                    if (strcmp(pname_pred, pname_succ) == 0) {
                                        TRACE("recover vma=[0x%lx - 0x%lx] flags=0x%lx, pgoff=0x%lx, file='%s'", vma->vm_start, vma->vm_end, vma->vm_flags, vma_pred->vm_pgoff + ((vma_pred->vm_end - vma_pred->vm_start) >> PAGE_SHIFT), pname_pred);
                                        if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, vma->vm_start, (vma->vm_end - vma->vm_start), pname_pred, vma_pred->vm_pgoff + ((vma_pred->vm_end - vma_pred->vm_start) >> PAGE_SHIFT), cputsc, realtsc, SAFE)) {
                                            TRACE("vtss_record_module() FAIL");
                                            repeat = 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
#endif
            } else if (vma->vm_mm && vma->vm_start == (long)vma->vm_mm->context.vdso) {
                is_vdso_found = 1;
                TRACE("addr=0x%lx, size=%lu, name='%s', pgoff=%lu", vma->vm_start, (vma->vm_end - vma->vm_start), "[vdso]", 0UL);
                if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, vma->vm_start, (vma->vm_end - vma->vm_start), "[vdso]", 0, cputsc, realtsc, SAFE)) {
                    TRACE("vtss_record_module() FAIL");
                    repeat = 1;
                }
            }
        }
        if (!is_vdso_found && mm->context.vdso) {
            TRACE("addr=0x%p, size=%lu, name='%s', pgoff=%lu", mm->context.vdso, PAGE_SIZE, "[vdso]", 0UL);
            if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, (unsigned long)((size_t)mm->context.vdso), PAGE_SIZE, "[vdso]", 0, cputsc, realtsc, SAFE)) {
                TRACE("vtss_record_module() FAIL");
                repeat = 1;
            }
        }
        up_read(&mm->mmap_sem);
        VTSS_CLEAR_MMAP_INIT(tskd);
        mmput(mm);
    }
    if (tmp)
        vtss_free_page((unsigned long)tmp);
    return repeat;
}

void vtss_mmap(struct file *file, unsigned long addr, unsigned long pgoff, unsigned long size)
{
    vtss_task_map_item_t* item = NULL;

    if (!VTSS_COLLECTOR_IS_READY_OR_INITING){
        return;
    }
    atomic_inc(&vtss_kernel_task_in_progress);
    if ((atomic_read(&vtss_transport_state) == 1) && VTSS_COLLECTOR_IS_READY_OR_INITING) {
        item = vtss_task_map_get_item(TASK_TID(current));
        if (item != NULL) {
            struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
            atomic_inc(&vtss_mmap_reg_callcnt);
            if ((!VTSS_IS_COMPLETE(tskd)) && (!VTSS_IS_MMAP_INIT(tskd))) {
#ifdef VTSS_USE_NMI
                // we cannot allocate memory in irqs_disabled mode
                char tmp[960];
#else
                char *tmp = (char*)vtss_get_free_page(GFP_NOWAIT);
#endif
                long long cputsc, realtsc;
                vtss_time_get_sync(&cputsc, &realtsc);

                if (tmp != NULL) {
#ifdef VTSS_USE_NMI
                    char* pname = D_PATH(file, tmp, 960);
#else
                    char* pname = D_PATH(file, tmp, PAGE_SIZE);
#endif
                    if (!IS_ERR(pname)) {
                        TRACE("vma=[0x%lx - 0x%lx], file='%s', pgoff=%lu", addr, addr+size, pname, pgoff);
                        if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, addr, size, pname, pgoff, cputsc, realtsc, SAFE)) {
                            TRACE("vtss_record_module() FAIL");
                        }
                    }
#ifndef VTSS_USE_NMI
                    vtss_free_page((unsigned long)tmp);
#endif
                }
            }
            vtss_task_map_put_item(item);
        }
    }
    atomic_dec(&vtss_kernel_task_in_progress);
}

#if 0
void vtss_mmap_reload(struct file *file, unsigned long addr)
{
    vtss_task_map_item_t* item = vtss_task_map_get_item(TASK_TID(current));

    atomic_inc(&vtss_transport_busy);
    if (atomic_read(&vtss_transport_initialized) == 1)  {
        if (item != NULL) {
            struct mm_struct *mm =  current->mm;
            if (mm != NULL) {
                struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
                if (unlikely(VTSS_IS_COMPLETE(tskd)))
                    tskd = vtss_wait_for_completion(&item);
                if (tskd != NULL) {
                    char *pname, *tmp = (char*)vtss_get_free_page(GFP_NOWAIT);
                    if (tmp != NULL)
                    {
                        long long cputsc, realtsc;
                        struct vm_area_struct* vma = NULL;
                        down_read(&mm->mmap_sem);
                        vma = find_vma(mm, addr);
                        vtss_time_get_sync(&cputsc, &realtsc);
                        if (vma!=0 && tmp!=0 && (vma->vm_flags & VM_EXEC) && !(vma->vm_flags & VM_WRITE) &&
                                                                vma->vm_file && vma->vm_file->f_path.dentry)
                        {
                            pname = D_PATH(vma->vm_file, tmp, PAGE_SIZE);
                            if (!IS_ERR(pname)) {
                               TRACE("addr=0x%lx, size=%lu, file='%s', pgoff=%lu", vma->vm_start, (vma->vm_end - vma->vm_start), pname, vma->vm_pgoff);
                               if (vtss_record_module(VTSS_PT_FLUSH_MODE ? tskd->trnd : tskd->trnd_aux, tskd->m32, vma->vm_start, (vma->vm_end - vma->vm_start), pname, vma->vm_pgoff, cputsc, realtsc, SAFE)) {
                                   TRACE("vtss_record_module() FAIL");
                               }
                            }
                        }
                        up_read(&mm->mmap_sem);
                        vtss_free_page((unsigned long)tmp);
                    }
                }
            }
            vtss_task_map_put_item(item);
        }
    }
    atomic_dec(&vtss_transport_busy);
}
#endif

static void vtss_dump_stack(struct vtss_task_data* tskd, struct task_struct* task, struct pt_regs* regs, void* bp, int clear)
{
    if (task != current) {
        return;
    }
    if (likely(!VTSS_IS_COMPLETE(tskd) &&
        (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS) &&
        VTSS_IS_VALID_TASK(task) &&
        tskd->stk.trylock(&tskd->stk)))
    {
        void* reg_bp;
        reg_bp = regs ? (void*)REG(bp, regs) : bp;
        if (!reg_bp && task == current){
            unsigned long bp_val;
            vtss_get_current_bp(bp_val);
            reg_bp = (void*)bp_val;
        }
        /* Clear stack history if stack was not stored in trace */
        if (unlikely(VTSS_NEED_STACK_SAVE(tskd)) || clear)
            tskd->stk.clear(&tskd->stk);
        VTSS_PROFILE(stk, VTSS_STACK_DUMP(tskd, task, regs, reg_bp, IN_IRQ));

        if (likely(!VTSS_ERROR_STACK_DUMP(tskd))) {
            VTSS_STORE_STATE(tskd, 1, VTSS_ST_STKSAVE);
        } else {
            tskd->stk.clear(&tskd->stk);
        }
        tskd->stk.unlock(&tskd->stk);
    }
}

static void vtss_sched_switch_from(vtss_task_map_item_t* item, struct task_struct* task, void* bp, void* ip)
{
    unsigned long flags;
    int state = atomic_read(&vtss_collector_state);
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
    int is_preempt = (task->state == TASK_RUNNING) ? 1 : 0;
    int cpu;
    unsigned long start_rec_id = tskd->start_rec_id;
    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();

#ifdef VTSS_DEBUG_STACOAK
    unsigned long stack_size = ((unsigned long)(&stack_size)) & (THREAD_SIZE-1);
    if (unlikely(stack_size < (VTSS_MIN_STACK_SPACE + sizeof(struct thread_info)))) {
        ERROR("(%d:%d): LOW STACK %lu", TASK_PID(current), TASK_TID(current), stack_size);
        vtss_profiling_pause();
        tskd->state &= ~VTSS_ST_PMU_SET;
        return;
    }
#endif
    if (unlikely(!vtss_cpu_active(cpu) || VTSS_IS_COMPLETE(tskd))) {
        vtss_profiling_pause();
        tskd->state &= ~VTSS_ST_PMU_SET;
        return;
    }

    local_irq_save(flags);
    preempt_disable();
    vtss_lbr_disable_save(&tskd->lbr);
    /* read and freeze cpu counters if ... */
    if (likely((state == VTSS_COLLECTOR_RUNNING || VTSS_IN_CONTEXT(tskd)) &&
                VTSS_IS_PMU_SET(tskd))){
        VTSS_PROFILE(pmu, vtss_cpuevents_sample(tskd->cpuevent_chain));
        if ((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) && (reqcfg.ipt_cfg.mode & vtss_iptmode_full)){
            VTSS_PROFILE(bts, vtss_dump_ipt(VTSS_PT_FLUSH_MODE ? tskd->trnd_aux : tskd->trnd, tskd->tid, tskd->cpu, 0));
        }
    }
    tskd->state &= ~VTSS_ST_PMU_SET;
    { /* update and restart system counters always but with proper flag */
        int flag = (state == VTSS_COLLECTOR_RUNNING || VTSS_IN_CONTEXT(tskd)) ?
                (is_preempt ? 2 : 3) : (is_preempt ? -2 : -3);
        /* set correct TCB for following vtss_cpuevents_quantum_border() */
        pcb_cpu.tcb_ptr = &tskd->tcb;
        /* update system counters */
        VTSS_PROFILE(sys, vtss_cpuevents_quantum_border(tskd->cpuevent_chain, flag));
        pcb_cpu.tcb_ptr = NULL;
    }
    /* store swap-out record */
    if (ip) tskd->from_ip = ip;
    if (likely(VTSS_IN_CONTEXT(tskd))) {
        if (1/*(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX) || (VTSS_IS_STATE_SET(tskd, VTSS_ST_REC_CTX))*/){
            VTSS_STORE_SWAPOUT(tskd, is_preempt, NOT_SAFE);}
        else
            VTSS_STORE_STATE(tskd, 0, VTSS_ST_SWAPOUT);
#ifdef VTSS_RECOVERY_LOGIC
        if (likely(!VTSS_ERROR_STORE_SWAPOUT(tskd))) {
            vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
            per_cpu(vtss_recovery_tskd, tskd->cpu) = NULL;
            vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
            tskd->state &= ~VTSS_ST_IN_CONTEXT;
        }
#else
        tskd->state &= ~VTSS_ST_IN_CONTEXT;
#endif
    }
    if (likely(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX)) {
        vtss_dump_stack(tskd, task, NULL, bp, start_rec_id < tskd->start_rec_id);
    }
    preempt_enable_no_resched();
    local_irq_restore(flags);
}

static void vtss_sched_switch_to(vtss_task_map_item_t* item, struct task_struct* task, void* ip)
{
    int cpu;
    unsigned long flags;
    int state = atomic_read(&vtss_collector_state);
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();

#ifdef VTSS_DEBUG_STACK
    unsigned long stack_size = ((unsigned long)(&stack_size)) & (THREAD_SIZE-1);
    if (unlikely(stack_size < (VTSS_MIN_STACK_SPACE + sizeof(struct thread_info)))) {
        ERROR("(%d:%d): LOW STACK %lu", TASK_PID(current), TASK_TID(current), stack_size);
        vtss_profiling_pause();
        tskd->state &= ~VTSS_ST_PMU_SET;
        return;
    }
#endif

    if (unlikely(!vtss_cpu_active(cpu) || VTSS_IS_COMPLETE(tskd))) {
        vtss_profiling_pause();
        tskd->state &= ~VTSS_ST_PMU_SET;
#ifdef VTSS_RECOVERY_LOGIC
        vtss_clear_recovery(tskd);
#endif
        return;
    }
    local_irq_save(flags);
    preempt_disable();
    { /* update and restart system counters always but with proper flag */
        int flag = (state == VTSS_COLLECTOR_RUNNING) ? 1 : -1;
        /* set correct TCB for following vtss_cpuevents_quantum_border() */
        pcb_cpu.tcb_ptr = &tskd->tcb;
        VTSS_PROFILE(sys, vtss_cpuevents_quantum_border(tskd->cpuevent_chain, flag));
        pcb_cpu.tcb_ptr = NULL;
    }
    /* recover logic */
    if (unlikely(VTSS_NEED_STORE_NEWTASK(tskd)))
        VTSS_STORE_NEWTASK(tskd, NOT_SAFE);
    if (unlikely(VTSS_NEED_STORE_SOFTCFG(tskd)))
        VTSS_STORE_SOFTCFG(tskd, NOT_SAFE);
    if (unlikely(VTSS_NEED_STORE_PAUSE(tskd)))
        VTSS_STORE_PAUSE(tskd, tskd->cpu, 0x66 /* tpss_pi___itt_pause from TPSS ini-file */, SAFE);
    if (likely(VTSS_IN_NEWTASK(tskd))) {
        /* Exit from context on CPU if error was */
        struct vtss_task_data* cpu_tskd = NULL;
#ifdef VTSS_RECOVERY_LOGIC
        unsigned long flags;
        vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
        cpu_tskd = per_cpu(vtss_recovery_tskd, cpu);
        if (unlikely(1/*(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX)*/ &&
            cpu_tskd != NULL &&
            VTSS_IN_CONTEXT(cpu_tskd) &&
            VTSS_ERROR_STORE_SWAPOUT(cpu_tskd)))
        {
            unsigned long start_rec_id = cpu_tskd->start_rec_id;
            VTSS_STORE_SWAPOUT(cpu_tskd, 1, NOT_SAFE);
            if (start_rec_id < cpu_tskd->start_rec_id){
              //Put clear stack one more time after switch to
              VTSS_STORE_STATE(cpu_tskd, 1, VTSS_ST_STKSAVE);
            }
            if (likely(!VTSS_ERROR_STORE_SWAPOUT(cpu_tskd))) {
                per_cpu(vtss_recovery_tskd, cpu) = NULL;
                cpu_tskd->state &= ~VTSS_ST_IN_CONTEXT;
                cpu_tskd = NULL;
            }
        }
        vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
        /* Exit from context for the task if error was */
        if (unlikely(VTSS_IN_CONTEXT(tskd) && VTSS_ERROR_STORE_SWAPOUT(tskd))) {
            if (1/*reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX*/){
                unsigned long start_rec_id = tskd->start_rec_id;
                VTSS_STORE_SWAPOUT(tskd, 1, NOT_SAFE);
                if (start_rec_id < tskd->start_rec_id){
                  //Put clear stack one more time after switch to
                  VTSS_STORE_STATE(tskd, 1, VTSS_ST_STKSAVE);
                }
            }else VTSS_STORE_STATE(tskd, 0, VTSS_ST_SWAPOUT);
            if (likely(!VTSS_ERROR_STORE_SWAPOUT(tskd))) {
                vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
                per_cpu(vtss_recovery_tskd, tskd->cpu) = NULL;
                vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
                tskd->state &= ~VTSS_ST_IN_CONTEXT;
                if (unlikely(cpu == tskd->cpu))
                    cpu_tskd = NULL;
            }
        }
#endif
        /* Enter in context for the task if: */
        if (likely(cpu_tskd == NULL && /* CPU is free      */
            !VTSS_IN_CONTEXT(tskd)  && /* in correct state */
            state == VTSS_COLLECTOR_RUNNING))
        {
            unsigned long start_rec_id = tskd->start_rec_id;
#ifdef VTSS_KERNEL_CONTEXT_SWITCH
            if ( !ip )
            {
                ip = tskd->from_ip;
            }
            /* Use user IP if no stacks on context switches */
            if (!ip || !(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX))
#endif
                ip = (void*)KSTK_EIP(task);
            if (1/*reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX || (cpu != tskd->cpu) || (tskd->state&VTSS_ST_CPU_CHANGE)*/) {
                if (reqcfg.cpuevent_count_v1 !=0) VTSS_STORE_SAMPLE(tskd, tskd->cpu, NULL, NOT_SAFE);
                VTSS_STORE_SWAPIN(tskd, cpu, ip, NOT_SAFE/*, (cpu == tskd->cpu ? 0 : VTSS_ST_REC_CTX)*/);
            } else {
                if (reqcfg.cpuevent_count_v1 !=0) VTSS_STORE_SAMPLE(tskd, tskd->cpu, ip, NOT_SAFE);
                VTSS_STORE_STATE(tskd, 0, VTSS_ST_SWAPIN);
            }

#ifdef VTSS_RECOVERY_LOGIC
            if (likely(!VTSS_ERROR_STORE_SWAPIN(tskd))) {
                vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
                per_cpu(vtss_recovery_tskd, cpu) = tskd;
                vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
#else
            {
#endif
                tskd->state |= VTSS_ST_IN_CONTEXT;
                tskd->cpu = cpu;
                if (unlikely(!VTSS_NEED_STACK_SAVE(tskd))) {
                    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX) {
                        vtss_dump_stack(tskd, task, NULL, NULL, start_rec_id < tskd->start_rec_id);
                    }
                }
                if (likely(VTSS_NEED_STACK_SAVE(tskd) &&
                    (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS) &&
                    !vtss_transport_is_overflowing(tskd->trnd) &&
                    tskd->stk.trylock(&tskd->stk)))
                {
                    VTSS_STACK_SAVE(tskd, NOT_SAFE);
                    tskd->stk.unlock(&tskd->stk);
                }
            }
        }
    } else {
        tskd->state |= VTSS_ST_SWAPIN;
    }
    VTSS_STORE_STATE(tskd, 1, VTSS_ST_CPUEVT);
    vtss_profiling_resume(item, 0);
    preempt_enable_no_resched();
    local_irq_restore(flags);
}

#if defined(CONFIG_PREEMPT_NOTIFIERS) && defined(VTSS_USE_PREEMPT_NOTIFIERS)

static void vtss_notifier_sched_out(struct preempt_notifier *notifier, struct task_struct *next)
{
    vtss_task_map_item_t* item;

    vtss_profiling_pause();
    item = vtss_task_map_get_item(TASK_TID(current));
    if (item != NULL) {
        unsigned long bp;
        vtss_get_current_bp(bp);
        VTSS_PROFILE(ctx, vtss_sched_switch_from(item, current, (void*)bp, 0));
        vtss_task_map_put_item(item);
    }
}

static void vtss_notifier_sched_in(struct preempt_notifier *notifier, int cpu)
{
    vtss_task_map_item_t* item = vtss_task_map_get_item(TASK_TID(current));

    if (item != NULL) {
        void* bp;
        vtss_get_current_bp(bp);
        VTSS_PROFILE(ctx, vtss_sched_switch_to(item, current, (void*)_THIS_IP_));
        vtss_task_map_put_item(item);
    } else {
        vtss_profiling_pause();
    }
}

#endif


void vtss_sched_switch(struct task_struct* prev, struct task_struct* next, void* prev_bp, void* prev_ip)
{
    vtss_task_map_item_t *item;

    vtss_profiling_pause();
    item = vtss_task_map_get_item(TASK_TID(prev));
    if (item != NULL) {
        VTSS_PROFILE(ctx, vtss_sched_switch_from(item, prev, prev_bp, prev_ip));
        vtss_task_map_put_item(item);
    }
    item = vtss_task_map_get_item(TASK_TID(next));
    if (item != NULL) {
        VTSS_PROFILE(ctx, vtss_sched_switch_to(item, next, 0));
        vtss_task_map_put_item(item);
    }
}

static void vtss_pmi_dump(struct pt_regs* regs, vtss_task_map_item_t* item, int is_bts_overflowed)
{
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
    int cpu;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();

    VTSS_STORE_STATE(tskd, !is_bts_overflowed, VTSS_ST_CPUEVT);
    if (likely(VTSS_IS_CPUEVT(tskd))) {
        /* fetch PEBS.IP, if available, or continue as usual */
        vtss_pebs_t* pebs = vtss_pebs_get(cpu);
        if (pebs != NULL) {
            TRACE("ip = %p, pebs_ip = %llx, eventing_ip = %llx", tskd->ip, pebs->v1.ip, pebs->v3.eventing_ip );
            if (0) { //vtss_pebs_is_trap()){
                /* correct the trap-IP - disabled to be consistent with SEP   */
                /* tskd->ip = vtss_lbr_correct_ip((void*)((size_t)pebs->v1.ip)); */
                if (vtss_pebs_record_size == sizeof(pebs->v3)){
                    tskd->ip = (void*)((size_t)pebs->v3.eventing_ip);
                } else {
                    tskd->ip = (void*)((size_t)pebs->v1.ip);
                }
                TRACE("in trap");
            }
            else {
                /* fault-IP is already correct */
                if (vtss_pebs_record_size == sizeof(pebs->v3)){
                    tskd->ip = (void*)((size_t)pebs->v3.eventing_ip);
                } else {
                    tskd->ip = (void*)((size_t)pebs->v1.ip);
                }
                TRACE("fault-IP is already correct");
            }
        } else
            tskd->ip = vtss_lbr_correct_ip((void*)instruction_pointer(regs));
        if (likely(VTSS_IS_PMU_SET(tskd))) {
            VTSS_PROFILE(pmu, vtss_cpuevents_sample(tskd->cpuevent_chain));
            tskd->state &= ~VTSS_ST_PMU_SET;
        }
    }
#ifndef VTSS_NO_BTS
    /* dump trailing BTS buffers */
    if (unlikely(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH)) {
        VTSS_PROFILE(bts, tskd->bts_size = vtss_bts_dump(tskd->bts_buff));
        vtss_bts_disable();
    }else if (unlikely(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT)) {
        vtss_disable_ipt();
    }
#endif
}

static void vtss_pmi_record(struct pt_regs* regs, vtss_task_map_item_t* item, int is_bts_overflowed)
{
    int cpu;
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
   
    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();
#ifdef VTSS_DEBUG_STACK
    unsigned long stack_size = ((unsigned long)(&stack_size)) & (THREAD_SIZE-1);
    if (unlikely(stack_size < (VTSS_MIN_STACK_SPACE + sizeof(struct thread_info)))) {
        ERROR("(%d:%d): LOW STACK %lu", TASK_PID(current), TASK_TID(current), stack_size);
        return;
    }
#endif
    if (unlikely(VTSS_NEED_STORE_NEWTASK(tskd)))
        VTSS_STORE_NEWTASK(tskd, NOT_SAFE);
    if (unlikely(VTSS_NEED_STORE_SOFTCFG(tskd)))
        VTSS_STORE_SOFTCFG(tskd, NOT_SAFE);
    if (unlikely(VTSS_NEED_STORE_PAUSE(tskd)))
        VTSS_STORE_PAUSE(tskd, tskd->cpu, 0x66 /* tpss_pi___itt_pause from TPSS ini-file */, SAFE);
    if (likely(VTSS_IN_NEWTASK(tskd))) {
#ifdef VTSS_RECOVERY_LOGIC
        /* Exit from context on CPU if error was */
        unsigned long flags;
        struct vtss_task_data* cpu_tskd = NULL;

        vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
        cpu_tskd = per_cpu(vtss_recovery_tskd, cpu);
        if (unlikely(1/*(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX)*/ &&
            cpu_tskd != NULL && cpu_tskd != tskd &&
            VTSS_IN_CONTEXT(cpu_tskd) &&
            VTSS_ERROR_STORE_SWAPOUT(cpu_tskd)))
        {
            unsigned long start_rec_id = cpu_tskd->start_rec_id;
            VTSS_STORE_SWAPOUT(cpu_tskd, 1, NOT_SAFE);
            if ( start_rec_id < cpu_tskd->start_rec_id){
                VTSS_STORE_STATE(cpu_tskd, 1, VTSS_ST_STKSAVE);
            }
            if (likely(!VTSS_ERROR_STORE_SWAPOUT(cpu_tskd))) {
                per_cpu(vtss_recovery_tskd, cpu) = NULL;
                cpu_tskd->state &= ~VTSS_ST_IN_CONTEXT;
                cpu_tskd = NULL;
            }
        }
        vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
        /* Enter in context for the task if CPU is free and no error */
        if (unlikely(cpu_tskd == NULL &&
            !VTSS_IN_CONTEXT(tskd) &&
            VTSS_ERROR_STORE_SWAPIN(tskd) &&
            atomic_read(&vtss_collector_state) == VTSS_COLLECTOR_RUNNING))
        {
            unsigned long  start_rec_id = tskd->start_rec_id;
            if (1/*(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX) || (cpu != tskd->cpu)||(tskd->state&VTSS_ST_CPU_CHANGE)*/){
                VTSS_STORE_SWAPIN(tskd, cpu, (void*)instruction_pointer(regs), NOT_SAFE/*, (cpu == tskd->cpu ? 0 : VTSS_ST_REC_CTX)*/);
            }
            else
                VTSS_STORE_STATE(tskd, 0, VTSS_ST_SWAPIN);
            if (start_rec_id < tskd->start_rec_id){
                VTSS_STORE_STATE(tskd, 1, VTSS_ST_STKSAVE);
            }

            if (likely(!VTSS_ERROR_STORE_SWAPIN(tskd))) {
                vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
                per_cpu(vtss_recovery_tskd, cpu) = tskd;
                vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
                tskd->state |= VTSS_ST_IN_CONTEXT;
                tskd->cpu = cpu;
                if (unlikely(VTSS_NEED_STACK_SAVE(tskd) && 
                    (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_CTX) &&
                    (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS) &&
                    !vtss_transport_is_overflowing(tskd->trnd) &&
                    tskd->stk.trylock(&tskd->stk)))
                {
                    VTSS_STACK_SAVE(tskd, NOT_SAFE);
                    tskd->stk.unlock(&tskd->stk);
                }
            }
            if (start_rec_id < tskd->start_rec_id){
                VTSS_STORE_STATE(tskd, 1, VTSS_ST_STKSAVE);
            }
        }
#endif
    } else {
        tskd->state |= VTSS_ST_SWAPIN;
    }
    if (likely(VTSS_IN_CONTEXT(tskd))) {
#ifndef VTSS_NO_BTS
        if (!is_bts_overflowed) 
        {
            if (unlikely (tskd->bts_size)){
                VTSS_PROFILE(bts, vtss_record_bts(tskd->trnd, tskd->tid, tskd->cpu, tskd->bts_buff, tskd->bts_size, 0));
                tskd->bts_size = 0;
            }
        }
#endif
        
        if (unlikely((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) &&
            !VTSS_ERROR_STORE_SAMPLE(tskd) &&
            !(VTSS_ERROR_STACK_DUMP(tskd)&&(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS)) &&
            !VTSS_ERROR_STACK_SAVE(tskd)))
        {
            VTSS_PROFILE(bts, vtss_dump_ipt(VTSS_PT_FLUSH_MODE ? tskd->trnd_aux : tskd->trnd, tskd->tid, tskd->cpu, 0));
        }

        if (likely(VTSS_IS_CPUEVT(tskd))) {
            void* ip = VTSS_ERROR_STORE_SAMPLE(tskd) ? (void*)VTSS_EVENT_LOST_MODULE_ADDR : tskd->ip;
            unsigned long  start_rec_id = tskd->start_rec_id;
            VTSS_STORE_SAMPLE(tskd, tskd->cpu, ip, NOT_SAFE);
            
            if (likely(!VTSS_ERROR_STORE_SAMPLE(tskd)))
            {
                vtss_dump_stack(tskd, current, regs, NULL, start_rec_id < tskd->start_rec_id);
                if (likely(VTSS_NEED_STACK_SAVE(tskd) &&
                    (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS) &&
                    !vtss_transport_is_overflowing(tskd->trnd) &&
                    tskd->stk.trylock(&tskd->stk)))
                {
                    VTSS_STACK_SAVE(tskd, NOT_SAFE);
                    tskd->stk.unlock(&tskd->stk);
                }
            }
        }
        if (unlikely((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) &&
            !VTSS_ERROR_STORE_SAMPLE(tskd) &&
            !(VTSS_ERROR_STACK_DUMP(tskd)&&(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS)) &&
            !VTSS_ERROR_STACK_SAVE(tskd)))
        {
            ;
            //INFO("dump PT");
            //VTSS_PROFILE(bts, vtss_dump_ipt(VTSS_PT_FLUSH_MODE ? tskd->trnd_aux : tskd->trnd, tskd->tid, tskd->cpu, 0));
        }
#ifndef VTSS_NO_BTS
        else if (unlikely(is_bts_overflowed && tskd->bts_size &&
            (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH) &&
            !VTSS_ERROR_STORE_SAMPLE(tskd) &&
            !(VTSS_ERROR_STACK_DUMP(tskd)&&(reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_STACKS)) &&
            !VTSS_ERROR_STACK_SAVE(tskd)))
        {
            VTSS_PROFILE(bts, vtss_record_bts(tskd->trnd, tskd->tid, tskd->cpu, tskd->bts_buff, tskd->bts_size, 0));
            tskd->bts_size = 0;
        }
#endif
    }

}

static int is_callcount_overflowed(void)
{
    int cpu;

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();

    if (reqcfg.trace_cfg.trace_flags & (VTSS_CFGTRACE_IPT)) return vtss_has_ipt_overflowed();
    return vtss_bts_overflowed(cpu);
}
/**
 * CPU event counter overflow handler and BTS/PEBS buffer overflow handler
 * sample counter values, form the trace record
 * select a new mux group (if applicable)
 * program event counters
 * NOTE: LBR/BTS/PEBS is already disabled in vtss_perfvec_handler()
 */
asmlinkage void vtss_pmi_handler(struct pt_regs *regs)
{
    unsigned long flags = 0;
    int is_bts_overflowed = 0;
    int bts_enable = 0;
    vtss_task_map_item_t* item = NULL;

#ifndef VTSS_USE_NMI
    if (unlikely(!vtss_apic_read_priority())) {
        ERROR("INT 0xFE was called");
        return;
    }
#endif
    local_irq_save(flags);
    preempt_disable();
#ifndef VTSS_NO_BTS
    is_bts_overflowed = is_callcount_overflowed();
#endif
    if (likely(!is_bts_overflowed))
        vtss_cpuevents_freeze();
    if (likely(VTSS_IS_VALID_TASK(current)))
        item = vtss_task_map_get_item(TASK_TID(current));
    if (likely(item != NULL)) {
        struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
        bts_enable = is_callcount_enable(tskd);
        VTSS_PROFILE(pmi, vtss_pmi_dump(regs, item, is_bts_overflowed));
    } else {
        vtss_profiling_pause();
    }
#ifndef VTSS_USE_NMI
    vtss_apic_ack_eoi();
#endif
    vtss_pmi_enable();
    if (likely(item != NULL)) {
        VTSS_PROFILE(pmi, vtss_pmi_record(regs, item, is_bts_overflowed));
        vtss_profiling_resume(item, bts_enable);
        vtss_task_map_put_item(item);
    }
    preempt_enable_no_resched();
    local_irq_restore(flags);
}

/* ------------------------------------------------------------------------- */

#ifdef VTSS_DEBUG_PROFILE
cycles_t vtss_profile_cnt_stk  = 0;
cycles_t vtss_profile_clk_stk  = 0;
cycles_t vtss_profile_cnt_ctx  = 0;
cycles_t vtss_profile_clk_ctx  = 0;
cycles_t vtss_profile_cnt_pmi  = 0;
cycles_t vtss_profile_clk_pmi  = 0;
cycles_t vtss_profile_cnt_pmu  = 0;
cycles_t vtss_profile_clk_pmu  = 0;
cycles_t vtss_profile_cnt_sys  = 0;
cycles_t vtss_profile_clk_sys  = 0;
cycles_t vtss_profile_cnt_bts  = 0;
cycles_t vtss_profile_clk_bts  = 0;
cycles_t vtss_profile_cnt_vma  = 0;
cycles_t vtss_profile_clk_vma  = 0;
cycles_t vtss_profile_cnt_pgp  = 0;
cycles_t vtss_profile_clk_pgp  = 0;
cycles_t vtss_profile_cnt_cpy  = 0;
cycles_t vtss_profile_clk_cpy  = 0;
cycles_t vtss_profile_cnt_vld  = 0;
cycles_t vtss_profile_clk_vld  = 0;
cycles_t vtss_profile_cnt_unw  = 0;
cycles_t vtss_profile_clk_unw  = 0;
#endif

int vtss_cmd_open(void)
{
    return 0;
}

int vtss_cmd_close(void)
{
    return 0;
}


static int vtss_cmd_set_target_task(struct task_struct *task);

static int vtss_cmd_set_target_task(struct task_struct *task)
{
    int rc = -EINVAL;
    int state = atomic_read(&vtss_collector_state);

    if (state == VTSS_COLLECTOR_RUNNING || state == VTSS_COLLECTOR_PAUSED) {
        struct task_struct *p;
        if (task != NULL) {
            char *tmp = NULL;
            char *pathname = NULL;
            struct mm_struct *mm;
            struct pid *pgrp;

            pgrp = get_pid(task->pids[PIDTYPE_PID].pid);
            if ((mm = get_task_mm(task)) != NULL) {
                struct file *exe_file = mm->exe_file;
                mmput(mm);
                if (exe_file) {
                    get_file(exe_file);
                    tmp = (char*)vtss_get_free_page(GFP_KERNEL);
                    if (tmp) {
                        pathname = d_path(&exe_file->f_path, tmp, PAGE_SIZE);
                        if (!IS_ERR(pathname)) {
                            char *p = strrchr(pathname, '/');
                            pathname = p ? p+1 : pathname;
                        } else {
                            pathname = NULL;
                        }
                    }
                    fput(exe_file);
                }
            }
            rc = -ENOENT;
            do_each_pid_thread(pgrp, PIDTYPE_PID, p) {
                DEBUG_COLLECTOR("profile the process <%d>: tid=%d, pid=%d, ppid = %d, pathname='%s'", TASK_PID(task), TASK_TID(task), TASK_PID(task), TASK_PID(TASK_PARENT(p)),pathname);
                if (!vtss_target_new(TASK_TID(p), TASK_PID(p), TASK_PID(TASK_PARENT(p)), pathname, -1, -1)) {
                    rc = 0;
                }
            } while_each_pid_thread(pgrp, /*PIDTYPE_MAX*/PIDTYPE_PID, p);

            if (rc != 0) {
                ERROR("Error: cannot profile the process <%d>: tid=%d, pid=%d,  pathname='%s'", TASK_PID(task), TASK_TID(task), TASK_PID(task), pathname);
            }
            put_pid(pgrp);
            if (tmp)
                vtss_free_page((unsigned long)tmp);
        } else
            rc = -ENOENT;
    }
    return rc;
}

int vtss_cmd_set_target(pid_t pid)
{
    int rc = -EINVAL;
    struct task_struct *task = vtss_find_task_by_tid(pid);
    rc = vtss_cmd_set_target_task(task);
    return rc;
}
static void vtss_collector_pmi_disable_on_cpu(void *ctx)
{
    vtss_pmi_disable();
}


#ifdef VTSS_AUTOCONF_INIT_WORK_TWO_ARGS
static void vtss_transport_fini_work(struct work_struct *work)
#else
static void vtss_transport_fini_work(void *work)
#endif
{
    DEBUG_COLLECTOR("start");
    vtss_transport_fini();
    atomic_set(&vtss_transport_state, 0);
    vtss_procfs_ctrl_wake_up(NULL, 0);
    if (work) vtss_kfree(work);
    DEBUG_COLLECTOR("end");
}
static void wait_transport_fini(void)
{
    int cnt = 0;
    DEBUG_COLLECTOR("1, transport state = %d", atomic_read(&vtss_transport_state));
    while (atomic_read(&vtss_transport_state) != 0){
        cnt++;
    }
    DEBUG_COLLECTOR("2, cnt = %d", cnt);
    return;
}


static int vtss_callcount_init(void)
{
    int rc = 0;
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) rc = vtss_ipt_init();
    else  rc = vtss_bts_init(reqcfg.bts_cfg.brcount);
    return rc;
}

static void vtss_callcount_fini(void)
{
    if (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) vtss_ipt_fini();
    else vtss_bts_fini();
}

static void vtss_target_complete_item(vtss_task_map_item_t* item, void* args)
{
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;
    if (tskd) tskd->state |= VTSS_ST_COMPLETE;
}

#ifndef VTSS_USE_NMI

#define VTSS_CLR_PEBS_OVF 0x4000000000000000ULL
#define VTSS_CLR_STATUS_PEBS_OVF 0x4000000000000000ULL
#define MSR_PERF_GLOBAL_OVF_CTRL 0x390
#define IA32_PERF_GLOBAL_STATUS 0x38e

static void vtss_collector_check_status(void *ctx)
{
// workaround for RHEL 6 update 5 for HSW/BDW EP machines
// kernel panic happens without calling this function
    unsigned long long val = 0;

    if (hardcfg.family == 0x06 && hardcfg.model >= 0x0f){
        rdmsrl(IA32_PERF_GLOBAL_STATUS, val);
        if (val & VTSS_CLR_STATUS_PEBS_OVF){
            wrmsrl(MSR_PERF_GLOBAL_OVF_CTRL,VTSS_CLR_PEBS_OVF);
            if (ctx)(*((int*)ctx))++;
            vtss_pmi_enable();
        }
    }
}

static void vtss_collector_freeze_events(void *ctx)
{
    unsigned long flags, flags_rec;
    int cpu;
    struct vtss_task_data* tskd;
    local_irq_save(flags);
    preempt_disable();
    
//    vtss_bts_init_dsa();
    vtss_profiling_pause();
    
    vtss_collector_check_status(NULL);

#ifdef VTSS_RECOVERY_LOGIC
    cpu = smp_processor_id();
    vtss_spin_lock_irqsave(&vtss_recovery_lock, flags_rec);
    if ((tskd = per_cpu(vtss_recovery_tskd, cpu)) != NULL){
        VTSS_PROFILE(pmu, vtss_cpuevents_sample(tskd->cpuevent_chain));
        if ((reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_IPT) && (reqcfg.ipt_cfg.mode & vtss_iptmode_full)) {
            VTSS_PROFILE(bts, vtss_dump_ipt(VTSS_PT_FLUSH_MODE ? tskd->trnd_aux : tskd->trnd, tskd->tid, tskd->cpu, 0));
        }
    }
    vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags_rec);
//        INFO("end recovering...");
#endif
    vtss_pmi_disable();
    vtss_bts_init_dsa();

    preempt_enable_no_resched();
    local_irq_restore(flags);
}
#endif /* VTSS_USE_NMI */

int vtss_collection_fini(void)
{
    int i = 0;

    while (atomic_read(&vtss_kernel_task_in_progress) != 0){
        i++;
        if (i==1000) ERROR("Kernel task is not finished! vtss_kernel_task_in_progress = %d", atomic_read(&vtss_kernel_task_in_progress));
    }
    DEBUG_COLLECTOR("All kernel tasks finished i = %d, no new items can be added from now", i);

    if (atomic_read(&vtss_target_count)!=0){
        //detach case
        vtss_task_map_foreach(vtss_target_complete_item, NULL);
#ifndef VTSS_USE_NMI
        on_each_cpu(vtss_collector_freeze_events, NULL, SMP_CALL_FUNCTION_ARGS);
#endif
    }

#ifndef VTSS_USE_NMI
     {
        int br_ovl_status = 0;
        for (i = 0; i < 20; i++){
            br_ovl_status=0;
            on_each_cpu(vtss_collector_check_status, &br_ovl_status, SMP_CALL_FUNCTION_ARGS);
            if (br_ovl_status == 0) break;
        }
#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32))
        if (br_ovl_status){
            ERROR("Kernel panic may happen in several minutes if your OS is RHEL 6.5. Please, upgrade you system till RHEL 6.7");
        }
#endif
    }
#endif

    while (atomic_read(&vtss_events_enabling) != 0) i++;
    DEBUG_COLLECTOR("No enabled events i = %d", i);
    
    //workaround on the problem when pmi enabling while the collection is stopping, but some threads is still collecting data
    //on_each_cpu(vtss_collector_pmi_disable_on_cpu, NULL, SMP_CALL_FUNCTION_ARGS);
 
    vtss_probe_fini();
    vtss_cpuevents_fini_pmu();
    vtss_pebs_fini();
    vtss_callcount_fini();
    vtss_lbr_fini();
    vtss_dsa_fini();
#ifndef VTSS_USE_NMI
    vtss_apic_pmi_fini();
#endif
    /* NOTE: !!! vtss_transport_fini() should be after vtss_task_map_fini() !!! */
    vtss_task_map_fini();
    atomic_set(&vtss_transport_state, 2);
    while (atomic_read(&vtss_transport_busy) != 0) i++;
    DEBUG_COLLECTOR("No transport usage i = %d", i);
    if (vtss_queue_work(-1, vtss_transport_fini_work, NULL, 0)){
        vtss_transport_fini();
        atomic_set(&vtss_transport_state, 0);
        vtss_procfs_ctrl_wake_up(NULL, 0);
    } else {
       set_tsk_need_resched(current);
    }
    vtss_session_uid = 0;
    vtss_session_gid = 0;
    vtss_time_limit  = 0ULL; /* set default value */
#if 0
    on_each_cpu(errata_fix, NULL, SMP_CALL_FUNCTION_ARGS);
#endif
    DEBUG_COLLECTOR("repare nmi watchdog");
    vtss_nmi_watchdog_enable(0);
    atomic_set(&vtss_start_paused, 0);
    atomic_set(&vtss_collector_state, VTSS_COLLECTOR_STOPPED);
    vtss_target_clear_temp_list();
#if (!defined(VTSS_USE_UEC)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0))
    if (vtss_need_switch_off_tracing){
        tracing_off();
        vtss_need_switch_off_tracing = 0;
    }
#endif
    INFO("vtss++ collection stopped");
    VTSS_PROFILE_PRINT(printk);
    return 0;
}

void vtss_collection_cfg_init(void)
{
    int i = 0;
    memset(&reqcfg, 0, sizeof(process_cfg_t));
    for (i = 0; i < vtss_stk_last; i++){
        reqcfg.stk_sz[i] = (unsigned long)-1;
        reqcfg.stk_pg_sz[i] = 0;
    }
}

static int vtss_verify_settings(void)
{
    if (reqcfg.cpuevent_count_v1==0 && (reqcfg.trace_cfg.trace_flags & VTSS_CFGTRACE_BRANCH))
        return -1;
    return 0;
}

int vtss_cmd_start(void)
{
    int rc = 0;
    unsigned long flags;
    int old_state = atomic_cmpxchg(&vtss_collector_state, VTSS_COLLECTOR_STOPPED, VTSS_COLLECTOR_INITING);
    if (old_state != VTSS_COLLECTOR_STOPPED) {
        TRACE("Already running");
        return VTSS_ERR_START_IN_RUN;
    }

    if (vtss_verify_settings())
    {
        TRACE("Incoming settings is incorrect\n");
        return VTSS_ERR_BADARG;
    }
    //workaround on the problem when pmi enabling while the collection is stopping, but some threads is still collecting data
    on_each_cpu(vtss_collector_pmi_disable_on_cpu, NULL, SMP_CALL_FUNCTION_ARGS);
    vtss_nmi_watchdog_disable(0);
    wait_transport_fini();
#ifdef VTSS_CONFIG_INTERNAL_MEMORY_POOL
    vtss_memory_pool_clear();
#endif

#ifdef VTSS_DEBUG_PROFILE
    vtss_profile_cnt_stk  = 0;
    vtss_profile_clk_stk  = 0;
    vtss_profile_cnt_ctx  = 0;
    vtss_profile_clk_ctx  = 0;
    vtss_profile_cnt_pmi  = 0;
    vtss_profile_clk_pmi  = 0;
    vtss_profile_cnt_pmu  = 0;
    vtss_profile_clk_pmu  = 0;
    vtss_profile_cnt_sys  = 0;
    vtss_profile_clk_sys  = 0;
    vtss_profile_cnt_bts  = 0;
    vtss_profile_clk_bts  = 0;
    vtss_profile_cnt_vma  = 0;
    vtss_profile_clk_vma  = 0;
    vtss_profile_cnt_pgp  = 0;
    vtss_profile_clk_pgp  = 0;
    vtss_profile_cnt_cpy  = 0;
    vtss_profile_clk_cpy  = 0;
    vtss_profile_cnt_vld  = 0;
    vtss_profile_clk_vld  = 0;
    vtss_profile_cnt_unw  = 0;
    vtss_profile_clk_unw  = 0;
#endif
#if (!defined(VTSS_USE_UEC)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0))
   // We need switch on tracing as for 2.x.x version of kernel it's necessary for ring_buffer functionality
   // that is used in transport.c
   DEBUG_COLLECTOR("in define");
   vtss_need_switch_off_tracing = 0;
   if (!tracing_is_on()){
       DEBUG_COLLECTOR("in tracing off");
       vtss_need_switch_off_tracing = 1;
       tracing_on();
   }
   if (!tracing_is_on()){
       ERROR("tracing is off, please, build VTSS in \"uec\" mode");
       return VTSS_ERR_RING_BUFFER_DENIED;
   }
#endif
    INFO("Starting vtss++ collection");
    INFO("HARDCFG: family: 0x%02x, model: 0x%02x", hardcfg.family, hardcfg.model);
    INFO("SYSCFG: kernel: %d.%d.%d", (LINUX_VERSION_CODE>>16) & 0xff, (LINUX_VERSION_CODE>>8) & 0xff, (LINUX_VERSION_CODE) & 0xff);

    atomic_set(&vtss_target_count, 0);
    atomic_set(&vtss_mmap_reg_callcnt, 1);
    cpumask_copy(&vtss_collector_cpumask, vtss_procfs_cpumask());

    vtss_spin_lock_irqsave(&vtss_target_temp_list_lock, flags);
    INIT_LIST_HEAD(&vtss_target_temp_list);
    vtss_spin_unlock_irqrestore(&vtss_target_temp_list_lock, flags);

#if defined CONFIG_UIDGID_STRICT_TYPE_CHECKS || (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
    {
    kuid_t uid;
    kgid_t gid;
    current_uid_gid(&uid, &gid);
    vtss_session_uid = uid.val;
    vtss_session_gid = gid.val;
    }
#else
    current_uid_gid(&vtss_session_uid, &vtss_session_gid);
#endif
    vtss_procfs_ctrl_flush();
    rc |= vtss_transport_init(is_aux_transport_ring_buffer());
    atomic_set(&vtss_transport_state, 1);
    rc |= vtss_task_map_init();
#ifdef VTSS_CONFIG_KPTI
    rc |= vtss_cea_init();
#elif defined(VTSS_CONFIG_KAISER)
    rc |= vtss_kaiser_init();
#endif
    rc |= vtss_dsa_init();
    rc |= vtss_lbr_init();
    rc |= vtss_callcount_init();
    rc |= vtss_pebs_init();
    rc |= vtss_cpuevents_init_pmu(vtss_procfs_defsav());
    rc |= vtss_probe_init();
#ifndef VTSS_USE_NMI
    vtss_apic_pmi_init();
#endif
    if (!rc) {
        atomic_set(&vtss_collector_state, VTSS_COLLECTOR_RUNNING);
        TRACE("state: %s => RUNNING", state_str[old_state]);
        if (atomic_read(&vtss_start_paused)) {
            atomic_set(&vtss_start_paused, 0);
            vtss_cmd_pause();
        }
    } else {
        ERROR("Collection was not started because of initialization error.");
        vtss_collection_fini();
    }
    return rc;
}

int vtss_cmd_stop(void)
{
    int old_state = atomic_cmpxchg(&vtss_collector_state, VTSS_COLLECTOR_RUNNING, VTSS_COLLECTOR_UNINITING);

    if (old_state == VTSS_COLLECTOR_STOPPED) {
        DEBUG_COLLECTOR("Already stopped");
        return 0;
    }
    if (old_state == VTSS_COLLECTOR_INITING) {
        DEBUG_COLLECTOR("STOP in INITING state");
        return 0;
    }
    if (old_state == VTSS_COLLECTOR_UNINITING) {
        DEBUG_COLLECTOR("STOP in UNINITING state");
        return 0;
    }
    if (old_state == VTSS_COLLECTOR_PAUSED) {
        old_state = atomic_cmpxchg(&vtss_collector_state, VTSS_COLLECTOR_PAUSED, VTSS_COLLECTOR_UNINITING);
    }
    DEBUG_COLLECTOR("state: %s => STOPPING", state_str[old_state]);
    return vtss_collection_fini();
}

int vtss_cmd_stop_async(void)
{
    int rc = 0;
    if (atomic_read(&vtss_collector_state) != VTSS_COLLECTOR_STOPPED){
        rc = vtss_queue_work(-1, vtss_cmd_stop_work, NULL, 0);
        DEBUG_COLLECTOR("Async STOP (%d)", rc);
    }
    return rc;
}

int vtss_cmd_stop_ring_buffer(void)
{
    int rc = 0;
    vtss_transport_stop_ring_bufer();
    return rc;
}

int vtss_cmd_pause(void)
{
    int rc = -EINVAL;
    int cpu;
    int old_state = atomic_cmpxchg(&vtss_collector_state, VTSS_COLLECTOR_RUNNING, VTSS_COLLECTOR_PAUSED);

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();

    if (old_state == VTSS_COLLECTOR_RUNNING) {
        if (!vtss_record_probe_all(cpu, 0x66 /* tpss_pi___itt_pause from TPSS ini-file */, SAFE)) {
            rc = 0;
        } else {
            TRACE("vtss_record_probe_all() FAIL");
        }
    } else if (old_state == VTSS_COLLECTOR_PAUSED) {
        TRACE("Already paused");
        rc = 0;
    } else if (old_state == VTSS_COLLECTOR_STOPPED) {
        atomic_inc(&vtss_start_paused);
        TRACE("It's STOPPED. Start paused = %d", atomic_read(&vtss_start_paused));
        rc = 0;
    } else {
        /* Pause can be done in RUNNING state only */
        TRACE("PAUSE in wrong state %d", old_state);
    }
    TRACE("state: %s => PAUSED (%d)", state_str[old_state], rc);
    return rc;
}

int vtss_cmd_resume(void)
{
    int rc = -EINVAL;
    int cpu;
    int old_state = atomic_cmpxchg(&vtss_collector_state, VTSS_COLLECTOR_PAUSED, VTSS_COLLECTOR_RUNNING);

    preempt_disable();
    cpu = smp_processor_id();
    preempt_enable_no_resched();

    if (old_state == VTSS_COLLECTOR_PAUSED) {
        if (!vtss_record_probe_all(cpu, 0x67 /* tpss_pi___itt_resume from TPSS ini-file */, SAFE)) {
            rc = 0;
        } else {
            TRACE("vtss_record_probe_all() FAIL");
        }
    } else if (old_state == VTSS_COLLECTOR_RUNNING) {
        TRACE("Already resumed");
        rc = 0;
    } else if (old_state == VTSS_COLLECTOR_STOPPED) {
        atomic_dec(&vtss_start_paused);
        TRACE("It's STOPPED. Start paused = %d", atomic_read(&vtss_start_paused));
        rc = 0;
    } else {
        /* Resume can be done in PAUSED state only */
        TRACE("RESUME in wrong state %d", old_state);
    }
    TRACE("state: %s => RUNNING (%d)", state_str[old_state], rc);
    return rc;
}

static void vtss_debug_info_target(vtss_task_map_item_t* item, void* args)
{
    int i;
    struct seq_file *s = (struct seq_file*)args;
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

    seq_printf(s, "\n[task %d:%d]\nname='%s'\nstate=0x%04x (",
                tskd->tid, tskd->pid, tskd->filename, tskd->state);
    for (i = 0; i < sizeof(task_state_str)/sizeof(char*); i++) {
        if (tskd->state & (1<<i))
            seq_printf(s, " %s", task_state_str[i]);
    }
    seq_printf(s, " )\n");
}

int vtss_debug_info(struct seq_file *s)
{
    int rc = 0;

    seq_printf(s, "[collector]\nstate=%s\ntargets=%d\ncpu_mask=",
                state_str[atomic_read(&vtss_collector_state)],
                atomic_read(&vtss_target_count));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    seq_cpumask_list(s, &vtss_collector_cpumask);
#else
    seq_printf(s, "%*pbl", cpumask_pr_args(&vtss_collector_cpumask));
#endif
    seq_putc(s, '\n');

#ifdef VTSS_DEBUG_PROFILE
    seq_puts(s, "\n[profile]\n");
    VTSS_PROFILE_PRINT(seq_printf, s,);
#endif
    rc |= vtss_transport_debug_info(s);
    rc |= vtss_task_map_foreach(vtss_debug_info_target, s);
    return rc;
}

static void vtss_target_pids_item(vtss_task_map_item_t* item, void* args)
{
    struct seq_file *s = (struct seq_file*)args;
    struct vtss_task_data* tskd = (struct vtss_task_data*)&item->data;

    if (tskd->tid == tskd->pid) /* Show only processes */
        seq_printf(s, "%d\n", tskd->pid);
}

int vtss_target_pids(struct seq_file *s)
{
    return vtss_task_map_foreach(vtss_target_pids_item, s);
}

void vtss_fini(void)
{
    DEBUG_COLLECTOR("Unloading vtss...");
    vtss_cmd_stop();
    wait_transport_fini();
    vtss_procfs_fini();
    vtss_user_vm_fini();
    vtss_cpuevents_fini();
    vtss_globals_fini();
#ifdef VTSS_CONFIG_INTERNAL_MEMORY_POOL
    vtss_memory_pool_fini();
#endif
    DEBUG_COLLECTOR("vtss stopped.");
}

int vtss_init(void)
{
    int rc = 0;
#ifdef VTSS_RECOVERY_LOGIC
    int cpu;
    unsigned long flags;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
    if (xen_initial_domain()) {
        ERROR("XEN dom0 is not supported by VTSS++");
        return -1;
    }
#endif

#ifdef VTSS_GET_TASK_STRUCT
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
    if (vtss__put_task_struct == NULL) {
#ifndef VTSS_AUTOCONF_KPROBE_SYMBOL_NAME
        vtss__put_task_struct = (vtss__put_task_struct_t*)kallsyms_lookup_name("__put_task_struct");
#else  /* VTSS_AUTOCONF_KPROBE_SYMBOL_NAME */
        if (!register_kprobe(&_kp_dummy)) {
            vtss__put_task_struct = (vtss__put_task_struct_t*)_kp_dummy.addr;
            TRACE("__put_task_struct=0x%p", vtss__put_task_struct);
            unregister_kprobe(&_kp_dummy);
        }
#endif /* VTSS_AUTOCONF_KPROBE_SYMBOL_NAME */
        if (vtss__put_task_struct == NULL) {
            ERROR("Cannot find '__put_task_struct' symbol");
            return -1;
        }
    }
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39) */
#endif /* VTSS_GET_TASK_STRUCT */

#ifdef VTSS_RECOVERY_LOGIC
    vtss_spin_lock_irqsave(&vtss_recovery_lock, flags);
    for_each_possible_cpu(cpu) {
        per_cpu(vtss_recovery_tskd, cpu) = NULL;
    }
    vtss_spin_unlock_irqrestore(&vtss_recovery_lock, flags);
#endif
    cpumask_copy(&vtss_collector_cpumask, cpu_present_mask);

#ifdef VTSS_CONFIG_INTERNAL_MEMORY_POOL
    rc |= vtss_memory_pool_init();
#endif
    rc |= vtss_globals_init();
    rc |= vtss_cpuevents_init();
    rc |= vtss_user_vm_init();
    rc |= vtss_procfs_init();
    return rc;
}
