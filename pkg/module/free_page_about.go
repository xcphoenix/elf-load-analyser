package module

import (
	_ "embed" // embed for free_page_about.c
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/free_page_about.c.k
var tlbAboutSource string

type tlbAboutEvent struct {
	enhance.TimeEventResult
	Type uint32
}

func (t tlbAboutEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown(
		helper.IfElse(t.Type == 1, "为了页表的清除初始化 mmu_gather 结构体", "结束 mmu_gather 结构体").(string)),
	)
}

type freePgdRangeEventType struct {
	enhance.TimeEventResult
	Addr    uint64
	End     uint64
	Floor   uint64
	Ceiling uint64
}

func (f freePgdRangeEventType) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewMarkdown("释放可以清除的页表"),
		form.NewFmtList(form.Fmt{
			{"addr: %x, end: %x", f.Addr, f.End},
			{"floor: %x, ceiling: %x", f.Floor, f.Ceiling},
		}),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "mmu_gather",
		Source: tlbAboutSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__tlb_gather_mmu", "tlb_gather_mmu", -1),
			ebpf.NewKprobeEvent("kprobe__tlb_finish_mmu", "tlb_finish_mmu", -1),
			ebpf.NewKprobeEvent("kprobe__shift_arg_pages", "shift_arg_pages", -1),
			ebpf.NewKprobeEvent("kprobe__free_pgd_range", "free_pgd_range", -1),
		},
	})
	m.RegisterOnceTable("tlb_gather_mmu_events", monitor.RenderHandler(tlbAboutEvent{}, nil))
	m.RegisterOnceTable("tlb_finish_mmu_events", monitor.RenderHandler(tlbAboutEvent{}, nil))
	m.RegisterOnceTable("free_pgd_range_events", monitor.RenderHandler(freePgdRangeEventType{}, nil))
	//factory.Register(m)
}
