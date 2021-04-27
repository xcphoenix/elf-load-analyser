package module

import (
	_ "embed" // embed for arch_pick_mmap_layout
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/handler/virtualm"
)

//go:embed src/arch_pick_mmap_layout.c.k
var archPickMmapLayoutSource string

type archPickMmapLayoutEvent struct {
	enhance.TimeEventResult
	MmapBase uint64
}

func (a archPickMmapLayoutEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown(fmt.Sprintf("mmap 基地址：0x%x", a.MmapBase))).
		PutExtra(virtualm.VmaFlag, virtualm.MMapVMEvent{MmapBase: a.MmapBase})
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "arch_pick_mmap_layout",
		Source:  archPickMmapLayoutSource,
		Events: []*bcc.Event{
			bcc.NewKretprobeEvent("kretprobe__arch_pick_mmap_layout", "arch_pick_mmap_layout", -1),
		},
	})
	m.RegisterOnceTable("arch_pick_mmap_layout_events", modules.RenderHandler(&archPickMmapLayoutEvent{}))
	factory.Register(m.Mm())
}
