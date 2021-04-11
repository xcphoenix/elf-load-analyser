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

//go:embed src/bprm_execve.c.k
var bprmExecveSrc string

type bprmExecveEvent struct {
	enhance.TimeEventResult
}

func (a bprmExecveEvent) Render() (*data.AnalyseData, bool) {
	return data.NewAnalyseData(form.NewMarkdown("开始执行新程序...")), true
}

func init() {
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "bprm_execve",
		Source:  bprmExecveSrc,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__bprm_execve", "bprm_execve", -1),
		},
	})
	m.RegisterOnceTable("call_event", func(data []byte) (*data.AnalyseData, bool, error) {
		return modules.Render(data, &bprmExecveEvent{}, true)
	})
	factory.Register(m.Mm())
}
