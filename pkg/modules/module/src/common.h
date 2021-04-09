#ifndef XC_COMMON_H
#define XC_COMMON_H

#include <linux/elf.h>
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/binfmts.h>

#include "_dev.h"

#define _X_DEBUG_
#define TEMPTY

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN PAGE_SIZE
#endif

#ifndef ELF_CORE_EFLAGS
#define ELF_CORE_EFLAGS 0
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN - 1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN - 1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

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