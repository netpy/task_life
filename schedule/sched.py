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
	u32 prev_pid;
	u32 current_pid;
	u32 prev_tgid;
	char flags;
	u32 current_tgid;
	char prev_comm[TASK_COMM_LEN];
    char current_comm[TASK_COMM_LEN];
    u64 start_time;
    u64 end_time;
    u64 continue_time;
    u32 cpu;
    u64 prev_state;
};

struct comp_t {
    u32 sched_start_pid;
    u32 cpu;
};

struct time_t {
	u64 start_time;
	u64 end_time;	
};

struct time_flag_t {
	u64 start_time;
	char flags;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(start,struct comp_t,struct time_flag_t);
BPF_HASH(times,u32,u64);


int exit_sched_start(){

	u64 ts=bpf_ktime_get_ns();
    struct comp_t comp_start;
	struct task_struct *task=(struct task_struct *)bpf_get_current_task();
	struct time_flag_t start_flag={};

	start_flag.start_time=ts;
	start_flag.flags='E';


	u32 task_pid=task->pid;
	u32 cpu=bpf_get_smp_processor_id();
    comp_start.sched_start_pid=task_pid;
    comp_start.cpu=cpu;

   // if(task_pid==0)
    	//times.update(&cpu,&ts);

    start.update(&comp_start,&start_flag);
    return 0;
}


int idle_exit_sched_start(){

	u64 ts=bpf_ktime_get_ns();
    struct comp_t comp_start;
	struct task_struct *task=(struct task_struct *)bpf_get_current_task();
	struct time_flag_t start_flag={};

	start_flag.start_time=ts;
	start_flag.flags='I';


	u32 task_pid=task->pid;
	u32 cpu=bpf_get_smp_processor_id();
    comp_start.sched_start_pid=task_pid;
    comp_start.cpu=cpu;

   // if(task_pid==0)
    	//times.update(&cpu,&ts);

    start.update(&comp_start,&start_flag);
    return 0;
}



int normal_sched_start(){

	u64 ts=bpf_ktime_get_ns();
    struct comp_t comp_start;
	struct task_struct *task=(struct task_struct *)bpf_get_current_task();
	struct time_flag_t start_flag={};

	start_flag.start_time=ts;
	start_flag.flags='A';


	u32 task_pid=task->pid;
	u32 cpu=bpf_get_smp_processor_id();
    comp_start.sched_start_pid=task_pid;
    comp_start.cpu=cpu;

   // if(task_pid==0)
    //times.update(&cpu,&ts);

    start.update(&comp_start,&start_flag);
    return 0;
}

int sched_end(struct pt_regs *ctx,struct task_struct *prev){
    u64 a=0;
    u64 delta,*tsp,ts;
    ts=bpf_ktime_get_ns();
    struct data_t data={};
    struct comp_t comp_end;
    struct time_t prev_time={};

    u32 prev_pid=prev->pid;
    u32 current_pid=bpf_get_current_pid_tgid();
    u32 cpu=bpf_get_smp_processor_id();
 

    comp_end.sched_start_pid=prev_pid;
    comp_end.cpu=cpu;

    //delta=ts-*tsp;

    //tsp=start.lookup(&comp_end);
    struct time_flag_t *start_flag=start.lookup(&comp_end);
    //if(tsp==0){
        //tsp=&a;
        //return 0;
        //tsp=times.lookup(&cpu);
        //if(tsp==0)
        //	tsp=&a;
        //times.delete(&cpu);
        //}

    if(!start_flag || start_flag->start_time==0)
    {
    	return 0;
    	//start_flag.start_time=0;
    	//start_flag.flags='U';
    }

    delta=ts-start_flag->start_time;
    
    data.prev_pid=prev_pid;
    data.current_pid=current_pid;
    data.prev_tgid=prev->tgid;
    data.flags=start_flag->flags;
    data.current_tgid=bpf_get_current_pid_tgid()>>32;
    bpf_probe_read_kernel_str(data.prev_comm, sizeof(data.prev_comm), prev->comm);
    bpf_get_current_comm(&data.current_comm,sizeof(data.current_comm));
    data.start_time=start_flag->start_time;
    data.end_time=ts;
    data.continue_time=delta;
    data.cpu=cpu;
    data.prev_state=prev->state;
    


    start.delete(&comp_end);
    events.perf_submit(ctx,&data,sizeof(data));

    return 0;
}

"""


# initialize BPF
b=BPF(text=bpf_text)
#b.attach_kprobe(event="__switch_to_asm",fn_name="sched_start")
b.attach_kprobe(event="do_task_dead",fn_name="exit_sched_start")
b.attach_kprobe(event="schedule_idle",fn_name="idle_exit_sched_start")
b.attach_kprobe(event="schedule",fn_name="normal_sched_start")
b.attach_kprobe(event="finish_task_switch",fn_name="sched_end")

def print_event(cpu,data,size):
    event=b["events"].event(data)
    print("cpu: %-3d flag: %-1s start_pid: %-5d (%-12d %-5d %-15s)--->end_pid: %-5d ( %-5d %-15s)  s_time: %-15d~e_time: %-15d  delta: %-7d "%(event.cpu,event.flags,event.prev_pid,event.prev_state,event.prev_tgid,event.prev_comm,event.current_pid,event.current_tgid,event.current_comm,event.start_time,event.end_time,event.continue_time))

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()