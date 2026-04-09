#!/usr/bin/env python3
from bcc import BPF
import ctypes as ct

program = r"""
BPF_PROG_ARRAY(syscall, 500);  // BCC提供了一个BPF_PROG_ARRAY宏，用于轻松定义BPF_MAP_TYPE_PROG_ARRAY类型的映射。我将该映射命名为syscall并允许300个条目，这对于本例来说已经足够了。

int hello(struct bpf_raw_tracepoint_args *ctx) {  // 其他简单例子里都是void *类型的参数
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);  // 这里， 我们向程序数组中键与操作码匹配的条目发起一个尾调用。这行代码在被 BCC 传递给编译器之前，会被重写为对 bpf_tail_call() 辅助函数的调用。
    
    bpf_trace_printk("Another syscall: %d", opcode);  // 如果尾调用成功，这行用于跟踪操作码值的代码将永远不会被执行。我利用这一点为映射中没有对应程序条目的操作码提供了一个默认的跟踪行。
    return 0;
}

int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)  # 这些对b.load_func()的调用会为每个尾调用程序返回一个文件描述符。请注意，尾调用需要与其父程序具有相同的程序类型——BPF.RAW_TRACEPOINT在本例中即是如此。另外需要指出的是，每个尾调用程序本身就是一个eBPF程序。
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")  # 用户空间代码在syscall映射中创建条目。映射不必为每个可能的操作码都完全填充；如果某个特定操作码没有条目，则仅意味着不会执行尾调用。此外，多个条目指向同一个eBPF程序是完全可行的。在本例中，我希望针对一组定时器相关系统调用中的任何一个执行hello_timer()尾调用。

# Ignore all syscalls initially
for i in range(len(prog_array)):
    prog_array[ct.c_int(i)] = ct.c_int(ignore_fn.fd)  # 有些系统调用被系统运行得如此频繁，以至于每个调用的跟踪行都会使跟踪输出混乱到无法阅读的程度。我已经对多个系统调用使用了ignore_opcode()尾调用。

# Only enable few syscalls which are of interest
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")  # 与之前附加到 kprobe 不同，这次用户空间代码将主 eBPF 程序附加到 sys_enter 跟踪点。之前调用的是attach_kprobe

b.trace_print()
