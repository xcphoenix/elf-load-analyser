package module

import (
	_ "embed" // embed for zap_other_threads
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/zap_other_threads.c.k
var zapOtherThreadsSource string

type zapOtherThreadEvent struct {
	enhance.TimeEventResult
}

func (z zapOtherThreadEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("开始删除线程组中的其他线程，向除本线程外的其他线程发送 SIGKILL 信号"))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor:  "zap_other_threads",
		Source:   zapOtherThreadsSource,
		Events:   []*bcc.Event{bcc.NewKprobeEvent("kprobe__zap_other_threads", "zap_other_threads", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("zap_other_threads_events", modules.RenderHandler(&zapOtherThreadEvent{}))
	factory.Register(m)
}
