#!/usr/bin/env python3
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);  // BCC 定义了宏 BPF_PERF_OUTPUT ，用于创建一个将用于从内核向用户空间传递消息的映射。
 
struct data_t {     // 每次运行hello()时，代码都会写入一个结构体大小的数据。这是该结构体的定义，它包含进程ID、当前正在运行的命令名称以及一条文本消息的字段。
   int pid;
   int uid;
   char command[16];
   char message[12];
};
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello PanPan";  // 这是要传递给用户空间的消息。它被定义为一个局部变量，并在调用bpf_probe_read_kernel()之前填充到数据结构中。
 
   data.pid = bpf_get_current_pid_tgid() >> 32;  // 它返回一个64位值，其中进程ID位于高32位。低32位是线程组ID。对于单线程进程，这与进程ID相同，但该进程的附加线程将被分配不同的ID。 GNU C库的文档很好地描述了进程ID与线程组ID之间的区别。
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   
   bpf_get_current_comm(data.command, sizeof(data.command));
   bpf_probe_read_kernel(data.message, sizeof(data.message), message); 
 
   output.perf_submit(ctx, &data, sizeof(data));   // 此时，数据结构中已填充了进程ID、命令名称和消息。对output.perf_submit()的调用将这些数据放入map中。
 
   return 0;
}
"""

b = BPF(text=program)  # 编译C代码、将其加载到内核中并将其附加到系统调用事件
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
 
def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
 
b["output"].open_perf_buffer(print_event)  # opens the perf ring buffer.
while True:   
   b.perf_buffer_poll()
