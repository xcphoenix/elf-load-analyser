package module

import (
	_ "embed" // embed for flush_thread
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/flush_thread.c.k
var flushThreadSource string

type flushThreadEvent struct {
	enhance.TimeEventResult
}

func (z flushThreadEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("初始化进程结构体 TLS 元数据"))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "flush_thread",
		Source:  flushThreadSource,
		Events:  []*bcc.Event{bcc.NewKprobeEvent("kprobe__flush_thread", "flush_thread", -1)},
	})
	m.RegisterOnceTable("flush_thread_events", modules.RenderHandler(&flushThreadEvent{}))
	factory.Register(m.Mm())
}
