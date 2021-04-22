package module

import (
	_ "embed" // for embed bcc source
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/enhance"
)

//go:embed src/interp_elf_map.c.k
var interpElfMapSource string

type interpElfMapEventType struct {
	enhance.TimeEventResult
	commonElfMapEventType
}

type interpElfMapPropEventType struct {
	enhance.TimeEventResult
}

func (e interpElfMapPropEventType) Render() *data.AnalyseData {
	result := form.NewMarkdown("开始映射ELF解释器")
	return data.NewAnalyseData(result)
}

func init() {
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "interp_elf_map",
		Source:  interpElfMapSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__elf_map", "elf_map", -1),
			bcc.NewKretprobeEvent("kretprobe__elf_map", "elf_map", -1),
			bcc.NewKprobeEvent("kprobe__total_mapping_size", "total_mapping_size", -1),
			bcc.NewKprobeEvent("kprobe__vma_link", "vma_link", -1),
		},
		LazyInit: func(_ *modules.MonitorModule, param bcc.PreParam) bool {
			return !param.IsDyn
		},
	})
	m.RegisterTable("interp_elf_map_events", true, modules.RenderHandler(&interpElfMapEventType{}))
	m.RegisterOnceTable("interp_elf_map_prop_events", modules.RenderHandler(&interpElfMapPropEventType{}))
	factory.Register(m.Mm())
}
