package module

import (
	_ "embed" // for embed bcc source
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/data"
	"github.com/phoenixxc/elf-load-analyser/pkg/data/content"
	"github.com/phoenixxc/elf-load-analyser/pkg/modules"
	"github.com/phoenixxc/elf-load-analyser/pkg/modules/enhance"
)

// sysExecveEvent
type {{ .EventName }} struct {
	enhance.TimeEventResult
}

func (e {{ .EventName }}) Render() *data.AnalyseData {
	return data.NewAnalyseData(content.NewMarkdown("start call"))
}

//go:embed src/{{ .BccSourceFile }}.k
var {{ .BccSrcVal }} string

type {{ .MonitorName }} struct {
	modules.MonitorModule
}

func init() {
	m := modules.NewPerfResolveMonitorModule(&{{ .MonitorName }}{})
	m.RegisterOnceTable({{ .BccEvent }}, func(d []byte) (*data.AnalyseData, error) {
		return modules.Render(d, &{{ .EventName }}{}, true)
	})
	modules.ModuleInit(m, true)
}

func (e *{{ .MonitorName }}) Monitor() string {
	return "{{ .MonitorName }}"
}

func (e *{{ .MonitorName }}) Source() string {
	return {{ .BccSrcVal }}
}

func (e *{{ .MonitorName }}) Events() []*bcc.Event {
	k := bcc.NewKprobeEvent("{{ .BccFnName }}", fnName, -1)
	return []*bcc.Event{ke, k}
}