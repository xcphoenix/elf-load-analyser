#ifndef XC_COMMON_H
#define XC_COMMON_H

#include <linux/elf.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/binfmts.h>

#include "_dev.h"

#define _XC_DEBUG 
#define TEMPTY

struct _common {
    u64 ts;
};

#define TDATA(struct_name, args) \
    typedef struct struct_name { \
        u64 ts;                  \
        args;                    \
    } __attribute__((packed)) struct_name;

// get param from stack(>7)
#define PARM_ON_STACK(num) \
    (kernel_stack_pointer(ctx) + (num - 6) * sizeof(void *))

// init tdata with ns
static void *init_tdata(void *data) {
    u64 ns = bpf_ktime_get_ns();
    struct _common *tmp = (struct _common *)data;
    bpf_probe_read_kernel(&tmp->ts, sizeof(u64), (void *)(&ns));
    return data;
}

#endif