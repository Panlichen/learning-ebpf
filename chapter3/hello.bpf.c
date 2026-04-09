#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

SEC("xdp")  // 宏SEC() 定义了一个名为xdp 的节，你可以在已编译的目标文件中看到它。 我将在第5章(CO-RE)中再讨论如何使用这个节名，但现在你可以简单地将其理解为 定义这是一个快速数据路径 (XDP) 类型的eBPF程序。
int hello(struct xdp_md *ctx) {
    bpf_printk("Hello World %d", counter);
    counter++; 
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
