package module

import (
	_ "embed" // embed for ld_steps
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"strings"
)

//go:embed src/ld_steps.c.k
var ldStepSource string

type bootstrapStepEvent struct {
	enhance.TimeEventResult
}

func (b bootstrapStepEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("ld 自举完成"))
}

type startUserProgEvent struct {
	enhance.TimeEventResult
}

func (s startUserProgEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("将控制权交给用户程序"))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "ld_steps",
		Source:  ldStepSource,
		LazyInit: func(mm *modules.MonitorModule, param bcc.PreParam) bool {
			mm.Events = []*bcc.Event{
				bcc.NewUprobeEvent("bootstrap_finished", "__rtld_malloc_init_stubs", param.Interp, -1),
				bcc.NewUretprobeEvent("start_user_prog", "_dl_start", param.Interp, -1),
			}
			mm.IsEnd = len(param.Interp) != 0 && strings.Contains(param.Interp, "ld-linux")
			return !mm.IsEnd
		},
	})
	m.RegisterOnceTable("bootstrap_finished_events", modules.RenderHandler(&bootstrapStepEvent{}))
	m.RegisterOnceTable("start_user_prog_events", modules.RenderHandler(&startUserProgEvent{}))
	factory.Register(m.Mm())
}
