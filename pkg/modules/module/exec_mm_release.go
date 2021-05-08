package module

import (
	_ "embed" // embed for exec_mm_release
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/exec_mm_release.c.k
var execMmReleaseSource string

type execMmReleaseEvent struct {
	enhance.TimeEventResult
}

func (e execMmReleaseEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("释放进程中旧的虚拟内存"))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor:  "exec_mm_release",
		Source:   execMmReleaseSource,
		Events:   []*bcc.Event{bcc.NewKprobeEvent("kprobe__exec_mm_release", "exec_mm_release", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("exec_mm_release_events", modules.RenderHandler(&execMmReleaseEvent{}))
	factory.Register(m)
}
