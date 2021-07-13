package module

import (
	_ "embed" // embed for arch_randomize_brk
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/arch_randomize_brk.c.k
var archRandomizeBrkSource string

type archRandomizeBrkEvent struct {
	enhance.TimeEventResult
	Type     uint32
	StartBrk uint64
	Brk      uint64
}

func (a archRandomizeBrkEvent) Render() *data.AnalyseData {
	result := data.NewSet()
	if a.Type != 0 {
		result.Combine(form.NewMarkdown("随机化堆的位置："))
	}
	result.Combine(form.NewFmtList(form.Fmt{
		{"start_brk: 0x%x", a.StartBrk},
		{"brk: 0x%x", a.Brk},
	}))
	d := data.NewAnalyseData(result)
	if a.Type != 0 {
		d.PutExtra(virtualm.VmaFlag, virtualm.NewVMIndicatricesEvent(map[string]uint64{
			"StartBrk": a.StartBrk,
			"Brk":      a.Brk,
		}))
	}
	return d
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "heap-scope",
		Source: archRandomizeBrkSource,
		Events: []*ebpf.Event{
			ebpf.NewKretprobeEvent("kretprobe__arch_randomize_brk", "arch_randomize_brk", -1),
			ebpf.NewKretprobeEvent("kretprobe__arch_setup_additional_pages", "arch_setup_additional_pages", -1),
		},
		CanMerge: true,
	})
	m.RegisterTable("arch_randomize_brk_events", true, monitor.RenderHandler(archRandomizeBrkEvent{}, nil))
	factory.Register(m)
}
