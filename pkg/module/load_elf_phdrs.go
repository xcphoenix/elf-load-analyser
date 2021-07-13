package module

import (
	_ "embed" // for embed ebpf source
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/load_elf_phdrs.c.k
var loadElfPhdrsSrc string

type loadElfPhdrsEvent struct {
	enhance.TimeEventResult
}

func (a loadElfPhdrsEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("获取文件程序头"))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "load_elf_phdrs",
		Source: loadElfPhdrsSrc,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__load_elf_phdrs", "load_elf_phdrs", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("load_elf_phdrs_events", monitor.RenderHandler(loadElfPhdrsEvent{}, nil))
	factory.Register(m)
}
