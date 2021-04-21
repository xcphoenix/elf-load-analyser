package module

import (
	_ "embed" // embed for arch_randomize_brk
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/handler/virtualm"
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
	result.Combine(form.NewList(
		fmt.Sprintf("start_brk: 0x%x", a.StartBrk),
		fmt.Sprintf("brk: 0x%x", a.Brk),
	))
	d := data.NewAnalyseData(result)
	if a.Type != 0 {
		d.PutExtra(virtualm.VmaFlag, virtualm.BrkVMEvent{
			StartBrk: a.StartBrk,
			Brk:      a.Brk,
		})
	}
	return d
}

func init() {
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "heap-scope",
		Source:  archRandomizeBrkSource,
		Events: []*bcc.Event{
			bcc.NewKretprobeEvent("kretprobe__arch_randomize_brk", "arch_randomize_brk", -1),
			bcc.NewKretprobeEvent("kretprobe__arch_setup_additional_pages", "arch_setup_additional_pages", -1),
		},
	})
	m.RegisterTable("arch_randomize_brk_events", true, modules.RenderHandler(&archRandomizeBrkEvent{}))
	factory.Register(m.Mm())
}
