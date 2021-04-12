package module

import (
	_ "embed" // for embed bcc source
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/enhance"
)

//go:embed src/begin_new_exec.c.k
var beginNewExecSrc string

type beginNewExecEvent struct {
	enhance.TimeEventResult
}

func (a beginNewExecEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("开始为新程序做准备"))
}

func init() {
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "begin_new_exec",
		Source:  beginNewExecSrc,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__begin_new_exec", "begin_new_exec", -1),
		},
	})
	m.RegisterOnceTable("begin_new_exec_events", func(data []byte) (*data.AnalyseData, error) {
		return modules.Render(data, &beginNewExecEvent{}, true)
	})
	factory.Register(m.Mm())
}
