package module

import (
	_ "embed" // embed for __vma_adjust
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/x__vma_adjust.c.k
var xVmaAdjustSource string

type xVmaAdjustEvent struct {
	enhance.TimeEventResult

	VmaStart uint64
	VmaEnd   uint64
	Start    uint64
	End      uint64
	Seq      uint32
}

func (x xVmaAdjustEvent) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewMarkdown("调整 vma 区间"),
		form.NewList(fmt.Sprintf("[%x, %x] => [%x, %x]", x.VmaStart, x.VmaEnd, x.Start, x.End)),
	)
	return data.NewAnalyseData(res).
		PutExtra(virtualm.VmaFlag, virtualm.AdjustVmaEvent{
			VmaStart:    x.VmaStart,
			VmaEnd:      x.VmaEnd,
			AdjustStart: x.Start,
			AdjustEnd:   x.End,
		})
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "__vma_adjust",
		Source: xVmaAdjustSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__shift_arg_pages", "shift_arg_pages", -1),
			ebpf.NewKprobeEvent("kprobe__x__vma_adjust", "__vma_adjust", -1),
		},
	})
	m.RegisterTable("x__vma_adjust_events", true, monitor.RenderHandler(xVmaAdjustEvent{}, nil))
	factory.Register(m)
}
