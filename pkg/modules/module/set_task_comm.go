package module

import (
	_ "embed" // embed for __set_task_comm
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/x__set_task_comm.c.k
var xSetTaskCommSource string

type xSetTaskCommEvent struct {
	enhance.TimeEventResult
	Comm [256]byte
}

func (x xSetTaskCommEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("设置进程名：" + data.TrimBytes2Str(x.Comm[:])))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "__set_task_comm",
		Source:  xSetTaskCommSource,
		Events:  []*bcc.Event{bcc.NewKprobeEvent("kprobe__x__set_task_comm", "__set_task_comm", -1)},
	})
	m.RegisterOnceTable("x__set_task_comm_events", modules.RenderHandler(&xSetTaskCommEvent{}))
	factory.Register(m.Mm())
}
