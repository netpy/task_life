from bcc import BPF
#BPF(text='int kprobe__finish_wait(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
#BPF(text='int kretprobe__bprm_execve(void *ctx) { bpf_trace_printk("This is exit!\\n"); return 0; }').trace_print()
BPF(text='int kprobe__try_to_wake_up(void *ctx) { bpf_trace_printk("This is enter!\\n"); return 0; }').trace_print()
