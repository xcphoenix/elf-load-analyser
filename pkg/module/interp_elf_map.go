package module

import (
	_ "embed" // for embed ebpf source
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/interp_elf_map.c.k
var interpElfMapSource string

var interpPath string

type interpElfMapEventType struct {
	enhance.TimeEventResult
	commonElfMapEventType
}

func (e interpElfMapEventType) Render() *data.AnalyseData {
	var result = e.commonElfMapEventType.Render()
	var event = virtualm.MapVmaEvent{
		// ps: 第一次 elf_map 会先映射整体，所以不能直接用 v.VmaEnd
		NewVma: virtualm.BuildVma(e.VmaStart, e.VmaStart+e.Size, e.VmaFlags, e.Off, interpPath),
	}
	return result.PutExtra(virtualm.VmaFlag, event)
}

type interpElfMapPropEventType struct {
	enhance.TimeEventResult
}

func (e interpElfMapPropEventType) Render() *data.AnalyseData {
	result := form.NewMarkdown("开始映射ELF解释器")
	return data.NewAnalyseData(result)
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "interp_elf_map",
		Source: interpElfMapSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__elf_map", "elf_map", -1),
			ebpf.NewKretprobeEvent("kretprobe__elf_map", "elf_map", -1),
			ebpf.NewKprobeEvent("kprobe__total_mapping_size", "total_mapping_size", -1),
			ebpf.NewKprobeEvent("kprobe__vma_link", "vma_link", -1),
		},
		LazyInit: func(_ *monitor.Monitor, param ebpf.PreParam) bool {
			interpPath = param.Interp
			return !param.IsDyn
		},
	})
	m.RegisterTable("interp_elf_map_events", true, monitor.RenderHandler(interpElfMapEventType{}, nil))
	m.RegisterOnceTable("interp_elf_map_prop_events", monitor.RenderHandler(interpElfMapPropEventType{}, nil))
	factory.Register(m)
}
