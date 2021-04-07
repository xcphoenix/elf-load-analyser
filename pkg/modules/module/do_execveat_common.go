package module

import (
	_ "embed" // for embed bcc source
	"fmt"

	"github.com/phoenixxc/elf-load-analyser/pkg/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/data"
	"github.com/phoenixxc/elf-load-analyser/pkg/data/form"
	"github.com/phoenixxc/elf-load-analyser/pkg/modules"
	"github.com/phoenixxc/elf-load-analyser/pkg/modules/enhance"
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
	var msg = form.NewList(
		fmt.Sprintf("fd = %d", e.Fd),
		fmt.Sprintf("flags = %d", e.Flags),
		fmt.Sprintf("filename = %s", s),
	)
	return data.NewAnalyseData(msg)
}

type doExecveatCommon struct {
	modules.MonitorModule
}

func init() {
	m := modules.NewPerfResolveMm(&doExecveatCommon{}, false)
	m.RegisterOnceTable("call_event", func(data []byte) (*data.AnalyseData, error) {
		return modules.Render(data, &execveatComEvent{}, true)
	})
	modules.ModuleInit(m)
}

func (c *doExecveatCommon) Monitor() string {
	return "execveat"
}

func (c *doExecveatCommon) Source() string {
	return doExecveatCommonSource
}

func (c *doExecveatCommon) Events() []*bcc.Event {
	ke := bcc.NewKprobeEvent("kprobe__do_execveat_common", "do_execveat_common", -1)
	return []*bcc.Event{ke}
}
