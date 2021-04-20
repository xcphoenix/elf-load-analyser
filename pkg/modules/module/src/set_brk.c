#include "common.h"

// PROC MACRO
#define PROT_EXEC	0x4		/* page can be executed */

TDATA(set_brk_event_type, // set_brk_event_type
    u64 start;
    u64 end;
    u64 start_align;
    u64 end_align;
    int64_t prot;   // bss prot
    u32 nbyte;      // number of bytes needed by clear
    u32 exec_prot;     // is map the last of the bss segment
);

BPF_PERF_OUTPUT(set_brk_events);

int kprobe__set_brk(struct pt_regs *ctx, unsigned long start, unsigned long end,
                    int prot) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    struct set_brk_event_type event = {};
    init_tdata(&event);
    event.start = (u64)start;
    event.end = (u64)end;
    event.prot = (int64_t)prot;

    event.start_align = ELF_PAGEALIGN(start);
    event.end_align = ELF_PAGEALIGN(end);

    // map last segment
    if (event.end_align > event.start_align) {
        event.exec_prot = event.prot & PROT_EXEC ? 1 : 0;
        // Map the last of the bss segment
        // vm_brk_flags(event.start_align, event.end_align - event.start_align, event.prot & PROT_EXEC ? VM_EXEC : 0);
    }

    // set current->mm->start_brk and current->mm->brk = event.end_align

    // clear user data
    unsigned long nbyte = ELF_PAGEOFFSET(event.start);
    if (nbyte) {
        nbyte = ELF_MIN_ALIGN - nbyte;
        if (nbyte > event.end - event.start) {
            nbyte = event.end - event.start;
        }
    }
    event.nbyte = nbyte;

    set_brk_events.perf_submit((void *)ctx, (void *)&event, sizeof(event));
    return 0;
}