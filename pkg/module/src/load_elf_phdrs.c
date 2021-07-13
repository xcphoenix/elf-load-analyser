// https://elixir.bootlin.com/linux/v5.10.7/source/fs/exec.c#L1775

#include "common.h"

TDATA(load_elf_pgdrs_event, TEMPTY);
BPF_PERF_OUTPUT(load_elf_phdrs_events);

int kprobe__load_elf_phdrs(struct pt_regs* ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct load_elf_pgdrs_event event = {};
    init_tdata(&event);
    load_elf_phdrs_events.perf_submit((void*)ctx, &event, sizeof(event));
    return 0;
}