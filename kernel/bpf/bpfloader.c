#include <linux/bpf.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/slab.h>

SYSCALL_DEFINE3(bpfloader, int, fd, const char __user *, path, int, flags)
{
    struct bpf_prog *prog;
    int err;

    // 从文件描述符获取BPF程序
    prog = bpf_prog_get(fd);
    if (IS_ERR(prog)) {
        pr_err("bpfloader: failed to get BPF program\n");
        return PTR_ERR(prog);
    }

    // 加载BPF程序
    err = bpf_prog_load(prog, path, flags);
    if (err < 0) {
        pr_err("bpfloader: failed to load BPF program\n");
        bpf_prog_put(prog);
        return err;
    }

    pr_info("bpfloader: BPF program loaded successfully\n");
    return 0;
}
