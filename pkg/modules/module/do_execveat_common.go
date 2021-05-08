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

//go:embed src/do_execveat_common.c.k
var doExecveatCommonSource string

type execveatComEvent struct {
	enhance.TimeEventResult
	Fd       int32
	Flags    int32
	Filename [256]byte
}

func (e execveatComEvent) Render() *data.AnalyseData {
	s := data.TrimBytes2Str(e.Filename[:])
	var msg = form.NewFmtList(form.Fmt{
		{"fd = %d", e.Fd},
		{"flags = %d", e.Flags},
		{"filename = %s", s},
	})
	return data.NewAnalyseData(msg)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "execveat",
		Source:  doExecveatCommonSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__do_execveat_common", "do_execveat_common", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("exec_events", modules.RenderHandler(&execveatComEvent{}))
	factory.Register(m)
}
