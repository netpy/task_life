#!/usr/bin.python
# coding-utf-8
# author: Jiqing Zhang

# exit.py Trace processs exit via do_exit.

from bcc import BPF
import argparse

parser= argparse.ArgumentParser(
        description="trace process exit")

args=parser.parse_args()

#define BPF program
bpf_text="""
    #include <linux/sched.h>
    #include <linux/init_task.h>
    #include <linux/kernel.h>

    struct data_t{
        u32 pid;
        u32 tgid;
        u32 uid;
        u32 cpu;
        u64 ts;
        char comm[TASK_COMM_LEN];
        };
    
    BPF_PERF_OUTPUT(events);

    int exiting(struct pt_regs *ctx,long code){
        struct data_t data={};
        struct task_struct *task=(struct task_struct *)bpf_get_current_task();
        
        data.pid=task->pid;
        data.tgid=task->tgid;
        data.uid=bpf_get_current_uid_gid()&0xffffffff;
        data.cpu=bpf_get_smp_processor_id();
        data.ts=bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm,sizeof(data.comm));

        events.perf_submit(ctx,&data,sizeof(data));

        return 0;

    }
"""


# initialize BPF
b=BPF(text=bpf_text)
b.attach_kprobe(event="do_exit",fn_name="exiting")

def print_event(cpu,data,size):
    event=b["events"].event(data)
    print(" pid: %-5d\t comm:%-15s\t cpu: %-3d\t tgid: %-5d\t uid: %-5d\t timestamp: %-15d\t "%(event.pid,event.comm,event.cpu,event.tgid,event.uid,event.ts))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()





