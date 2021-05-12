/**
 * @file resolve.c
 * @author xcphoenix (root@xcphoenix.top)
 * @brief ld 动态链接延迟绑定
 * @version 0.1
 * @date 2021-05-12
 *
 * @copyright Copyright (c) 2021
 */

#include <linux/elf.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <uapi/linux/ptrace.h>

// 获取栈上的入参  (>=7)
#define PARM_ON_STACK(num) \
    (kernel_stack_pointer(ctx) + (num - 6) * sizeof(void *))

#ifdef __x86_64__
#define __ELF_NATIVE_CLASS 64
#else
#define __ELF_NATIVE_CLASS 32
#endif

#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

#if (!ELF_MACHINE_NO_RELA && !defined ELF_MACHINE_PLT_REL) || ELF_MACHINE_NO_REL
#define PLTREL ElfW(Rela)
#else
#define PLTREL ElfW(Rel)
#endif

// defined in /usr/include/elf.h
#define DT_NUM 35
#define DT_VERSIONTAGNUM 16
#define DT_EXTRANUM 3
#define DT_VALNUM 12
#define DT_ADDRNUM 11
#define DT_THISPROCNUM 0  // 这个定义似乎依赖于平台，暂且设置为0

struct r_found_version {
    char *name;
    ElfW(Word) hash;

    int hidden;
    char *filename;
};

struct libname_list {
    const char *name;          /* Name requested (before search).  */
    struct libname_list *next; /* Link to next name for this object.  */
    int dont_free;             /* Flag whether this element should be freed
                          if the object is not entirely unloaded.  */
};

typedef long int Lmid_t;

struct link_map {
    ElfW(Addr) l_addr;
    char *l_name;     /* Absolute file name object was found in.  */
    ElfW(Dyn) * l_ld; /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */

    struct link_map *l_real;
    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;
    struct libname_list *l_libname;

    ElfW(Dyn) * l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM +
                       DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
};
typedef struct link_map *lookup_t;

/*
 * _dl_runtime_resolve_xxx
 *         ...
 *          |_______ _dl_fixup
 *                       |_______ _dl_lookup_symbol_x
 */

#define SYMBOL_MAX_LENGTH 256
#define VERSION_MAX_LENGTH 80

typedef struct symbol_resolve_event {
    u32 pid;            // 进程 pid
    u64 l_addr;         // 程序的加载地址
    u64 reloc_idx;      // 要重定位的符号在 .rel(a) 中的索引
    u64 reloc_addr;     // 要重定位的地址
    u64 original_addr;  // 重定位前的地址
    u64 symbol_addr;    // 符号的真实地址
    u64 load_addr;      // 符号的加载地址
    char symbol[SYMBOL_MAX_LENGTH];    // 符号名
    char version[VERSION_MAX_LENGTH];  // 版本名
    u64 flags;                         // 标志
} __attribute__((packed)) symbol_resolve_event;

// key 为 pid, 值为1表示当前进程处于 _dl_fixup 调用流程中
BPF_HASH(fixup_token, u32, u32);
BPF_HASH(resolve_event, u32, symbol_resolve_event);

BPF_PERF_OUTPUT(resolve_event_output);

static void issue_fixup_token();
static void cancel_fixup_token();
static int is_hold_token();
static symbol_resolve_event *get_event();
static void save_event(symbol_resolve_event *event);

static u32 get_cur_pid() { return bpf_get_current_pid_tgid() >> 32; }

// 获取符号在 .rel(a).plt 中的下标，要重定位的地址
int uprobe__x_dl_fixup(struct pt_regs *ctx) {
    bpf_trace_printk("RUN DL FIXUP");

    issue_fixup_token();

    // 获取参数
    struct link_map *l   = (struct link_map *)PT_REGS_PARM1(ctx);
    ElfW(Word) reloc_arg = (ElfW(Word))PT_REGS_PARM2(ctx);

    symbol_resolve_event e = {
        .pid       = get_cur_pid(),
        .reloc_idx = (u64)reloc_arg,
        .l_addr    = (u64)l->l_addr,
    };

    // NOTE: only for x86_64__
    ElfW(Dyn) * dynp;
    bpf_probe_read_user(&dynp, sizeof(dynp), &l->l_info[DT_JMPREL]);
    ElfW(Dyn) dyn = {};
    bpf_probe_read_user(&dyn, sizeof(dyn), (void *)dynp);
    // 在 .rela.plt 中的位置
    u64 reloc = (u64)(dyn.d_un.d_ptr + sizeof(ElfW(Rela)) * e.reloc_idx);

    PLTREL pltrel = {};
    bpf_probe_read_user(&pltrel, sizeof(pltrel), (void *)reloc);
    // 加完之后，是 .got.plt 当中的某一项
    e.reloc_addr = (u64)(pltrel.r_offset + l->l_addr);

    void *addr;
    bpf_probe_read_user(&addr, sizeof(addr), (void *)e.reloc_addr);
    e.original_addr = (u64)addr;

    save_event(&e);
    return 0;
}

// 获取符号地址
int uretprobe__x_dl_fixup(struct pt_regs *ctx) {
    symbol_resolve_event *e = get_event();
    if (!e) {
        return 0;
    }

    e->symbol_addr = (u64)PT_REGS_RC(ctx);
    resolve_event_output.perf_submit((void *)ctx, (void *)e, sizeof(*e));

    cancel_fixup_token();  // 在最后取消
    return 0;
}

// 获取符号名称、符号版本、flags
int uprobe__x_dl_lookup_symbol_x(struct pt_regs *ctx) {
    bpf_trace_printk("RUN LOOKUP SYMBOL");

    symbol_resolve_event *e = get_event();
    if (!e) {
        return 0;
    }

    // symbol
    if (PT_REGS_PARM1(ctx)) {
        bpf_probe_read_user_str(&e->symbol, sizeof(char) * SYMBOL_MAX_LENGTH,
                                (void *)PT_REGS_PARM1(ctx));
    }

    // version
    if (PT_REGS_PARM5(ctx)) {
        struct r_found_version rfv = {};
        bpf_probe_read_user(&rfv, sizeof(rfv), (void *)PT_REGS_PARM5(ctx));
        bpf_probe_read_user_str(&e->version, sizeof(char) * VERSION_MAX_LENGTH,
                                (void *)rfv.name);
    }

    // flags
    int f = 0;
    bpf_probe_read_user(&f, sizeof(f), (void *)(PARM_ON_STACK(7)));
    e->flags = (u64)f;

    save_event(e);
    return 0;
}

// 获取符号的加载地址
int uretprobe__x_dl_lookup_symbol_x(struct pt_regs *ctx) {
    symbol_resolve_event *e = get_event();
    if (!e) {
        return 0;
    }

    lookup_t l   = (lookup_t)PT_REGS_RC(ctx);
    e->load_addr = l->l_addr;

    save_event(e);
    return 0;
}

static void issue_fixup_token() {
    u32 pid = get_cur_pid(), token_val = 1;
    fixup_token.update(&pid, &token_val);
}

static void cancel_fixup_token() {
    u32 pid = get_cur_pid(), token_val = 0;
    fixup_token.update(&pid, &token_val);
    // clear
    save_event(NULL);
}

static int is_hold_token() {
    u32 pid    = get_cur_pid();
    u32 *token = fixup_token.lookup(&pid);
    if (token != NULL && *token != 0) {
        return 1;
    }
    return 0;
}

static symbol_resolve_event *get_event() {
    if (!is_hold_token()) {
        return NULL;
    }
    u32 pid = get_cur_pid();
    return resolve_event.lookup(&pid);
}

static void save_event(symbol_resolve_event *event) {
    if (!is_hold_token()) {
        return;
    }

    u32 pid = get_cur_pid();
    if (event) {
        resolve_event.update(&pid, event);
    } else {
        resolve_event.delete(&pid);
    }
}