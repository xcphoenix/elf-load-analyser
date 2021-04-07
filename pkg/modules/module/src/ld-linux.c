#include "common.h"

/*
 * Copy from glibc/elf
 */
#ifdef __x86_64__
#define __ELF_NATIVE_CLASS 64
#else
#define __ELF_NATIVE_CLASS 32
#endif
#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

#define DL_FIXUP_MAKE_VALUE(map, addr) (addr)
#define LOOKUP_VALUE_ADDRESS(map, set) ((set) || (map) ? (map)->l_addr : 0)
#define SYMBOL_ADDRESS(map, ref, map_set)                         \
    ((ref) == NULL ? 0                                            \
                   : (((ref)->st_shndx == SHN_ABS)                \
                          ? 0                                     \
                          : LOOKUP_VALUE_ADDRESS(map, map_set)) + \
                         (ref)->st_value)
/* 
 * END 
 */

struct link_map {
    ElfW(Addr) l_addr;
    char *l_name;
    ElfW(Dyn) * l_ld;
    struct link_map *l_next, *l_prev;
};

struct r_found_version {
    char *name;
    ElfW(Word) hash;

    int hidden;
    char *filename;
};

TDATA(lookup_symbol_event_t, // lookup_symbol_event_type
    u32 type;
    u32 pid;
    char str[128];
    char ver[80];
    u64 flag;
    u64 addr;

    ElfW(Sym) sym;
    int has_sym;
);

BPF_PERF_OUTPUT(loopup_symbol_events);
BPF_HASH(sym_hash, u32, struct lookup_symbol_event_t);

int bootstrap_finish(struct pt_regs *ctx) {
    struct lookup_symbol_event_t e = {};
    u32 pid = bpf_get_current_pid_tgid();
    e.pid = pid;
    loopup_symbol_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int lookup_symbol(struct pt_regs *ctx) {
    struct lookup_symbol_event_t event = {.type = 1};

    // PID
    u32 pid = bpf_get_current_pid_tgid();
    event.pid = pid;

    // SYMBOL
    if (PT_REGS_PARM1(ctx)) {
        bpf_probe_read_user_str(&event.str, sizeof(event.str),
                                (void *)PT_REGS_PARM1(ctx));
    }

    // SYM
    if (PT_REGS_PARM3(ctx)) {
        bpf_probe_read_user(&event.sym, sizeof(event.sym),
                            (void *)PT_REGS_PARM3(ctx));
        event.has_sym = 1;
    }

    // FLAG
    int f = 0;
    bpf_probe_read_user(&f, sizeof(f), (void *)(PARM_ON_STACK(7)));
    event.flag = (u64)f;

    // VERSION
    if (PT_REGS_PARM5(ctx)) {
        struct r_found_version rfv = {};
        bpf_probe_read_user_str(&rfv, sizeof(rfv), (void *)PT_REGS_PARM5(ctx));
        bpf_probe_read_user_str(&event.ver, sizeof(event.ver),
                                (void *)rfv.name);
    }

    sym_hash.update(&pid, &event);

    return 0;
}

int get_symbol_addr(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    struct lookup_symbol_event_t *event = sym_hash.lookup(&pid);
    if (!event) {
        return 0;
    }

    struct link_map result, *result_p = NULL;
    if (PT_REGS_RC(ctx)) {
        bpf_probe_read_user(&result, sizeof(result), (void *)PT_REGS_RC(ctx));
        result_p = &result;
#ifdef _XC_DEBUG
        bpf_trace_printk("laddr: %x\n", result_p->l_addr);
#endif
    }

    ElfW(Sym) *sym = event->has_sym ? &event->sym : NULL;
#ifdef _XC_DEBUG
    if (sym) {
        bpf_trace_printk("shndx: %x\n", sym->st_shndx);
        bpf_trace_printk("value: %x\n", sym->st_value);
    }
#endif
    event->addr =
        DL_FIXUP_MAKE_VALUE(result_p, SYMBOL_ADDRESS(result_p, sym, false));

    // clear
    ElfW(Sym) emptySym = {};
    event->sym = emptySym;

    // submit
    loopup_symbol_events.perf_submit(ctx, event,
                                     sizeof(struct lookup_symbol_event_t));
    sym_hash.delete(&pid);
    return 0;
}