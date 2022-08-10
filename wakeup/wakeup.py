#!/usr/bin/python

from bcc import BPF
from time import sleep, strftime
import argparse
from bcc.syscall import syscall_name, syscalls

parser = argparse.ArgumentParser()

args = parser.parse_args()


bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
	u32 pid;
	u32 tgid;
	char comm[TASK_COMM_LEN];
    u64 start_time;
    u32 cpu;
    u64 prev_state;
    u64 state;
    u64 wake_flags;
};


BPF_PERF_OUTPUT(events);

int try_to_wake_up_fun(struct pt_regs *ctx,struct task_struct *p, unsigned int state, int wake_flags){
    u64 delta,*tsp,ts;
    ts=bpf_ktime_get_ns();
    struct data_t data={};
    
    data.pid=p->pid;
    data.tgid=p->tgid;
    bpf_probe_read_kernel_str(data.comm, sizeof(data.comm), p->comm);
    data.start_time=ts;
    data.cpu=bpf_get_smp_processor_id();
    data.prev_state=p->state;
    data.state=state;
    data.wake_flags=wake_flags;
    
    events.perf_submit(ctx,&data,sizeof(data));

    return 0;
}

"""


# initialize BPF
b=BPF(text=bpf_text)
#b.attach_kprobe(event="__switch_to_asm",fn_name="sched_start")
b.attach_kprobe(event="try_to_wake_up",fn_name="try_to_wake_up_fun")

def print_event(cpu,data,size):
    event=b["events"].event(data)
    print(r"cpu: %-3d pid: %-5d  tgid:%-12d comm:%-15s start_time: %-15d prev_state:%-15d state:%-15d wake_flags:%-15d "%(event.cpu,event.pid,event.tgid,bytes.decode(event.comm),event.start_time,event.prev_state,event.state,event.wake_flags))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
