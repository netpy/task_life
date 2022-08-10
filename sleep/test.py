from bcc import BPF

# define BPF program
prog="""
int hello(void *ctx){
    bpf_trace_printk("Hello,World!\\n");
    return 0;
    }

int byebye(void *ctx){
    bpf_trace_printk("Good bye!\\n");
    return 0;
    }
"""

#load BPF program
b=BPF(text=prog)
#fnname=b.get_syscall_fnname("execve")
#print(fnname)
#b.attach_kprobe(event="ext4_file_write_iter", fn_name="hello")
b.attach_kprobe(event="schedule_timeout_uninterruptible", fn_name="hello")
#b.attach_kretprobe(event="__send_signal",fn_name="byebye")
#b.attach_kprobe(event="do_group_exit",fn_name="byebye")
#b.attach_kprobe(event="do_task_dead",fn_name="byebye")
#header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

#format output
while 1:
    try:
        (task,pid,cpu,flags,ts,msg)=b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

