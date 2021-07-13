package module

import (
	_ "embed" // embed for arch_pick_mmap_layout
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/arch_pick_mmap_layout.c.k
var archPickMmapLayoutSource string

type archPickMmapLayoutEvent struct {
	enhance.TimeEventResult
	MmapBase uint64
}

func (a archPickMmapLayoutEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown(fmt.Sprintf("mmap 基地址：0x%x", a.MmapBase))).
		PutExtra(virtualm.VmaFlag, virtualm.NewVMIndicatrixEvent("Mmap_base", a.MmapBase))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "arch_pick_mmap_layout",
		Source: archPickMmapLayoutSource,
		Events: []*ebpf.Event{
			ebpf.NewKretprobeEvent("kretprobe__arch_pick_mmap_layout", "arch_pick_mmap_layout", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("arch_pick_mmap_layout_events", monitor.RenderHandler(archPickMmapLayoutEvent{}, nil))
	factory.Register(m)
}
