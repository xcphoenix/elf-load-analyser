#include <linux/fdtable.h>
#include <linux/types.h>

#include "common.h"

// pre define
#ifdef __x86_64__
#define __ELF_NATIVE_CLASS 64
#else
#define __ELF_NATIVE_CLASS 32
#endif
#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

struct link_map {
    ElfW(Addr) l_addr;
    char *l_name;
    ElfW(Dyn) * l_ld;
    struct link_map *l_next, *l_prev;
    ElfW(Addr) l_relro_addr;
    size_t l_relro_size;
};

#define BOOTSTRAP_FINISHED 1
#define START_USER_PROG_STEP 4

// 阶段事件
// 1. 动态链接器自举
// 2. 装载共享对象
// 3. 重定位和初始化
// 4. 控制权交给用户程序
TDATA(step_event, TEMPTY);
BPF_PERF_OUTPUT(bootstrap_finished_events);
BPF_PERF_OUTPUT(start_user_prog_events);
BPF_PERCPU_ARRAY(step_array, u32, 1);

// RELO 相关
TDATA(protect_relro_event,  // _dl_protect_relro
      u64 l_addr;           // 加载地址
      char name[256];       // l_name
      u64 start;            // mprotect start
      int64_t prot;         // just read prot
      u32 len;              // mprotect len
      _Bool do_protect;     // is exec __mprotect
      int16_t valid;        // is valid
);
BPF_PERF_OUTPUT(protect_relro_events);
BPF_PERCPU_ARRAY(relro_array, struct protect_relro_event, 1);

// 共享对象映射
// 以映射的入口和出口为区间边界, 时间在此区间内的 mmap 操作都作用与当前的 fd
// 如果 fd 无法获取到, 获取当前进程结构体, 通过 files 尝试获取文件名或 inode
TDATA(map_object_event,    // map_object_event
      char realname[256];  // 名字
      int32_t fd;          // 对应的文件 fd
);

TDATA(mmap_event,     // mmap event
      u64 addr;       // addr
      u32 len;        // len
      int64_t prot;   // prot
      int64_t flags;  // flags
      int64_t fd;     // fd
      u64 offset;     // offset

      char name[256];  // mapped file name
);

typedef struct fd_name_store {
    int64_t fd;
    char name[256];
    int8_t valid;
} fd_name_store;

BPF_PERCPU_ARRAY(fd_name_array, fd_name_store, 1);
BPF_PERF_OUTPUT(map_object_events);
BPF_PERF_OUTPUT(mmap_events);

TDATA(mprotect_event,  // simple mprotect event
      u64 start;       // mprotect start
      int64_t prot;    // just read prot
      u32 len;         // mprotect len
);

// 普通的取消映射事件
TDATA(munmap_event,  // unmmap_event
      u64 addr;      // unmap add
      u32 len;       // len
);

BPF_PERF_OUTPUT(mprotect_events);
BPF_PERF_OUTPUT(munmap_events);

/**
 * 当动态链接自举成功后调用 `__rtld_malloc_init_stubs`
 *
 * The rtld startup code calls __rtld_malloc_init_stubs after the
 * first self-relocation to adjust the pointers to the minimal
 * implementation below.
 */
int bootstrap_finished(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct step_event e = {};
    init_tdata(&e);

    bootstrap_finished_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    int zero = 0;
    u32 step = BOOTSTRAP_FINISHED;
    step_array.update(&zero, &step);
    return 0;
}

/**
 * 控制权交给用户程序
 */
int start_user_prog(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct step_event e = {};
    init_tdata(&e);

    start_user_prog_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    int zero = 0;
    u32 step = START_USER_PROG_STEP;
    step_array.update(&zero, &step);

    bpf_trace_printk("START USER PROG");

    return 0;
}

/**
 * RELRO 保护
 */
int dl_protect_relro(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    struct link_map *l = (struct link_map *)PT_REGS_PARM1(ctx);
    if (!l) {
        return 0;
    }

    int zero                     = 0;
    struct protect_relro_event e = {.valid = 1};
    init_tdata(&e);

    e.l_addr = (u64)l->l_addr;
    bpf_probe_read_user_str(&e.name, sizeof(e.name), (void *)l->l_name);

    relro_array.update(&zero, &e);
    return 0;
}

int mprotect(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx)) {
        return 0;
    }

    int zero                      = 0;
    struct protect_relro_event *e = relro_array.lookup(&zero);
    if (e == NULL || e->valid == 0) {
        // 为 0 代表不是在处理 RELRO 时处理的操作
        struct mprotect_event me = {};
        init_tdata(&me);

        me.start = (u64)PT_REGS_PARM1(ctx);
        me.len   = (u32)PT_REGS_PARM2(ctx);
        me.prot  = (u64)PT_REGS_PARM3(ctx);

        mprotect_events.perf_submit((void *)ctx, (void *)&me, sizeof(me));
        return 0;
    }

    e->start      = (u64)PT_REGS_PARM1(ctx);
    e->len        = (u32)PT_REGS_PARM2(ctx);
    e->prot       = (u64)PT_REGS_PARM3(ctx);
    e->do_protect = 1;

    relro_array.update(&zero, e);

    return 0;
}

int ret_dl_protect_relro(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    int zero                      = 0;
    struct protect_relro_event *e = relro_array.lookup(&zero);
    if (!e || !e->valid) {
        return 0;
    }

    protect_relro_events.perf_submit((void *)ctx, (void *)e, sizeof(*e));
    e->valid = 0;

    relro_array.update(&zero, e);
    return 0;
}

// TODO
int munmap(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx)) {
        return 0;
    }

    struct munmap_event e = {};
    init_tdata(&e);

    e.addr = (u64)PT_REGS_PARM1(ctx);
    e.len  = (u32)PT_REGS_PARM2(ctx);

    munmap_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}

int dl_map_object_from_fd(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    bpf_trace_printk("MAP OBJECT EVENT");

    if (!PT_REGS_PARM3(ctx) || !PT_REGS_PARM5(ctx)) {
        bpf_trace_printk("MAP OBJECT EVENT: PARM INVALID");
        return 0;
    }

    int zero = 0;

    u32 *step = step_array.lookup(&zero);
    if (step && *step == START_USER_PROG_STEP) {
        bpf_trace_printk("MAP OBJECT EVENT: START USER PROG ALERDY??");
        return 0;
    }

    struct map_object_event e = {};
    init_tdata(&e);

    e.fd = (int32_t)PT_REGS_PARM3(ctx);
    bpf_probe_read_user_str(&e.realname, sizeof(e.realname),
                            (void *)PT_REGS_PARM5(ctx));

    struct fd_name_store *store = fd_name_array.lookup(&zero);
    if (store) {
        store->fd    = e.fd;
        store->valid = 1;
        bpf_probe_read_user_str(&store->name, sizeof(store->name),
                                (void *)PT_REGS_PARM5(ctx));
        fd_name_array.update(&zero, store);
    }

    bpf_trace_printk("MAP OBJECT EVENT ==> SUBMIT");

    map_object_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}

int ret_dl_map_object_from_fd(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    // set status invalid
    int zero                    = 0;
    struct fd_name_store *store = fd_name_array.lookup(&zero);
    if (store) {
        store->valid == 0;
        fd_name_array.update(&zero, store);
    }

    return 0;
}

int mmap(struct pt_regs *ctx, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags,
         unsigned long fd, unsigned long off) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    bpf_trace_printk("MMAP EVENT");

    int zero  = 0;
    u32 *step = step_array.lookup(&zero);
    if (step == NULL || *step == 0) {
        return 0;
    }
    if (step && *step == START_USER_PROG_STEP) {
        return 0;
    }

    struct mmap_event e = {};
    init_tdata(&e);

    e.addr   = (u64)addr;
    e.len    = (u32)len;
    e.prot   = (int64_t)prot;
    e.flags  = (int64_t)flags;
    e.fd     = (int64_t)fd;
    e.offset = (u64)off;

    struct fd_name_store *store = fd_name_array.lookup(&zero);
    if (store && store->valid) {
        bpf_probe_read_str(&e.name, sizeof(e.name), (void *)&store->name);
    } else {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task != NULL && e.fd >= 0) {
            struct file *target = task->files->fdt->fd[e.fd];
            if (target) {
                bpf_probe_read_str(&e.name, sizeof(e.name),
                                   (void *)&(target->f_path.dentry->d_iname));
            }
        }
    }

    mmap_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    return 0;
}