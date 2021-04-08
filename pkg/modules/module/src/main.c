#include "common.h"

TDATA(main_event_type,  // main event type
      TEMPTY);
BPF_PERF_OUTPUT(main_events);

int uprobe__main(struct pt_regs* ctx) {
    struct main_event_type e = {};
    init_tdata(&e);
    main_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}