package module

import (
	_ "embed" // for embed bcc source
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
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
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "load_elf_phdrs",
		Source:  loadElfPhdrsSrc,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__load_elf_phdrs", "load_elf_phdrs", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("load_elf_phdrs_events", modules.RenderHandler(&loadElfPhdrsEvent{}))
	factory.Register(m)
}
