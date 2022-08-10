from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
// 用于包含raw_spinlock_t的定义
#include <linux/spinlock_types.h>

// rq的简单定义
struct rq_partial {
    raw_spinlock_t      lock;
    unsigned int        nr_running;
};

// 进程key的信息[cpu, pid]
struct key {
    u32     cpu;
    u32     pid;
};

// 调度过程中value的信息
struct value {
    u32     cpu;
    u32     into_pid;
    u32     into_tgid;
    u32     into_policy;    // 调度策略
    u32     into_user;      // 根据mm字段确认是否是内核线程
    char    into_comm[TASK_COMM_LEN];
    u32     preempt;        // 参数preempt
    u64     into_state;     // 进入时的state
    u64     exit_state;     // 退出时的state
    u64     into_nivcsw;    // 进入时的非自愿切换计数
    u64     exit_nivcsw;    // 退出时的非自愿切换计数
    u64     into_nvcsw;     // 进入时的自愿切换计数
    u64     exit_nvcsw;     // 退出时的自愿切换计数
    u32     deactivate;     // 调度过程中是否从队列删除
    u32     pickcount_sp;   // 调度过程中sp_class的调用次数
    u32     pickcount_dl;   // 调度过程中dl_class的调用次数
    u32     pickcount_rt;   // 调度过程中rt_class的调用次数
    u32     pickcount_cf;   // 调度过程中cfs_class的调用次数
    u32     pickcount_id;   // 调度过程中idle_class的调用次数
    u32     nr_running;     // rq现在的进程个数
    u32     exit_pid;
    u32     exit_tgid;
    u32     exit_policy;
    u32     exit_user;
    char    exit_comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

BPF_HASH(sched_detail, struct key, struct value);

// 进入__schedule，更新prev的信息
int do_enter_schedule(struct pt_regs *ctx, bool preempt){
    struct task_struct *prev = NULL;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct key key = {};
    struct value value = {};

    prev = (struct task_struct *)bpf_get_current_task();

    key.cpu = value.cpu = bpf_get_smp_processor_id();
    key.pid = value.into_pid = pid_tgid;
    
    value.into_tgid = pid_tgid >> 32;
    bpf_get_current_comm(&(value.into_comm), sizeof(value.into_comm));

    value.preempt = 0;
    if (preempt) {
        value.preempt = 1;
    }

    value.into_user = 0;
    if (prev->mm) {
        value.into_user = 1;
    }

    // 默认为0
    value.deactivate = 0;
    value.pickcount_sp = 0;
    value.pickcount_dl = 0;
    value.pickcount_rt = 0;
    value.pickcount_cf = 0;
    value.pickcount_id = 0;

    value.into_policy = prev->policy;
    value.into_state = prev->state;
    value.into_nivcsw = prev->nivcsw;
    value.into_nvcsw = prev->nvcsw;

    sched_detail.update(&key, &value);

    return 0;
}

// 队列删除，更新deactivate字段
int do_deactivate(struct pt_regs *ctx) {
    struct key key = {};
    struct value *valuep;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        valuep->deactivate = 1;
    }

    return 0;
}

// pick_next_task_stop
int do_pick_next_stop(struct pt_regs *ctx, struct rq *rq) {
    struct key key = {};
    struct value *valuep;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        struct rq_partial *rq_now = (struct rq_partial *)rq;

        valuep->nr_running = rq_now->nr_running;
        valuep->pickcount_sp++;
    }

    return 0;
}

// pick_next_task_dl
int do_pick_next_deadline(struct pt_regs *ctx, struct rq *rq) {
    struct key key = {};
    struct value *valuep;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        struct rq_partial *rq_now = (struct rq_partial *)rq;

        valuep->nr_running = rq_now->nr_running;
        valuep->pickcount_dl++;
    }

    return 0;
}

// pick_next_task_rt
int do_pick_next_rt(struct pt_regs *ctx, struct rq *rq) {
    struct key key = {};
    struct value *valuep;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        struct rq_partial *rq_now = (struct rq_partial *)rq;

        valuep->nr_running = rq_now->nr_running;
        valuep->pickcount_rt++;
    }

    return 0;
}

// pick_next_task_fair
int do_pick_next_cfs(struct pt_regs *ctx, struct rq *rq) {
    struct key key = {};
    struct value *valuep;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        struct rq_partial *rq_now = (struct rq_partial *)rq;

        valuep->nr_running = rq_now->nr_running;
        valuep->pickcount_cf++;
    }

    return 0;
}

// pick_next_task_idle
int do_pick_next_idle(struct pt_regs *ctx, struct rq *rq) {
    struct key key = {};
    struct value *valuep;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        struct rq_partial *rq_now = (struct rq_partial *)rq;

        valuep->nr_running = rq_now->nr_running;
        valuep->pickcount_id++;
    }

    return 0;
}

// finish_task_switch
int do_exit_schedule(struct pt_regs *ctx, struct task_struct *prev) {
    struct key key = {};
    struct value *valuep, data = {};

    key.cpu = bpf_get_smp_processor_id();
    key.pid = prev->pid;

    valuep = sched_detail.lookup(&key);
    if (valuep) {
        struct task_struct *next = (struct task_struct *)bpf_get_current_task();

        valuep->exit_state = prev->state;
        valuep->exit_nivcsw = prev->nivcsw;
        valuep->exit_nvcsw = prev->nvcsw;

        valuep->exit_pid = next->pid;
        valuep->exit_tgid = next->tgid;
        valuep->exit_policy = next->policy;
        bpf_get_current_comm(&(valuep->exit_comm), sizeof(valuep->exit_comm));

        valuep->exit_user = 0;
        if (next->mm) {
            valuep->exit_user = 1;
        }

        data = *valuep;

        events.perf_submit(ctx, &data, sizeof(data));

        sched_detail.delete(&key);
    }

    return 0;
}
"""

b = BPF(text=bpf_text)

b.attach_kprobe(event="rcu_note_context_switch", fn_name="do_enter_schedule")
b.attach_kprobe(event="deactivate_task", fn_name="do_deactivate")
b.attach_kprobe(event="pick_next_task_stop", fn_name="do_pick_next_stop")
b.attach_kprobe(event="pick_next_task_dl", fn_name="do_pick_next_deadline")
b.attach_kprobe(event="pick_next_task_rt", fn_name="do_pick_next_rt")
b.attach_kprobe(event="pick_next_task_fair", fn_name="do_pick_next_cfs")
b.attach_kprobe(event="pick_next_task_idle", fn_name="do_pick_next_idle")
b.attach_kprobe(event="finish_task_switch", fn_name="do_exit_schedule")

dict_mm = {
    0 : "kthread",
    1 : "uthread"
}

dict_preempt = {
    0 : "false",
    1 : "true"
}

dict_deactivate = {
    0 : "false",
    1 : "true"
}

dict_policy = {
    0 : "SCHED_NORMAL",
    1 : "SCHED_FIFO",
    2 : "SCHED_RR",
    3 : "SCHED_BATCH",
    5 : "SCHED_IDLE",
    6 : "SCHED_DEADLINE"
}

dict_state = {
    0 : "TASK_RUNNING",
    1 : "TASK_INTRRUPTIBLE",
    2 : "TASK_UNINTERRUPTIBLE",
    4 : "__TASK_STOPPED",
    8 : "__TASK_TRACED",
    16 : "EXIT_DEAD",
    32 : "EXIT_ZOMBIE",
    48 : "EXIT_TRACE",
    64 : "TASK_PARKED",
    128 : "TASK_DEAD",
    256 : "TASK_WAKEKILL",
    512 : "TASK_WAKING",
    1024 : "TASK_NOLOAD",
    2048 : "TASK_NEW",
    4096 : "TASK_STATE_MAX",
    258 : "TASK_KILLABLE",
    260 : "TASK_STOPPED",
    264 : "TASK_TRACED",
    1026 : "TASK_IDLE",
    3 : "TASK_NORAML",
    127 : "TASK_REPORT"
}

# cpu pid tgid k/uthread policy state comm
# preempt deactivate stop dl rt cfs idle
# rq niv1 nv1 niv2 nv2
# state pid tgid k/uthread policy comm


def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("cpu:",event.cpu, event.into_pid, event.into_tgid, dict_mm[event.into_user], dict_policy[event.into_policy] , dict_state[event.into_state] ,event.into_comm,
    dict_preempt[event.preempt], dict_deactivate[event.deactivate], event.pickcount_sp, event.pickcount_dl, event.pickcount_rt, event.pickcount_cf, event.pickcount_id,
    event.nr_running, event.into_nivcsw, event.into_nvcsw, event.exit_nivcsw, event.exit_nvcsw,dict_state[event.exit_state],
    event.exit_pid, event.exit_tgid, dict_mm[event.exit_user], dict_policy[event.exit_policy], event.exit_comm,)

b["events"].open_perf_buffer(print_event)

sleep(1)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
# "%-2d %-6d %-6d %-16s %-16s %-16s %-16s %-16s %-16s %-6d %-6d %-6d %-6d %-6d %-6d %-6d %-16d %-16d %-16d %-16d %-6d %-6d %-16s %-16s %-16s %-16s\n" %
