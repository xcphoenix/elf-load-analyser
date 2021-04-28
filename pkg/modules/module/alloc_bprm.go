package module

import (
	_ "embed" // for embed bcc source
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

// about stack 512byte limit,
// see: https://stackoverflow.com/questions/53627094/ebpf-track-values-longer-than-stack-size
//go:embed src/alloc_bprm.c.k
var allowBprmSource string

type allocBprmEvent struct {
	enhance.TimeEventResult
	Filename    [256]byte
	Fdpath      [256]byte
	Interp      [256]byte
	CurTopOfMem uint64
	RlimCur     uint64
	RlimMax     uint64
}

func (a allocBprmEvent) Render() *data.AnalyseData {
	s := fmt.Sprintf("分配空间，保存二进制文件参数\n\n"+
		"filename: %q, fdpath: %q, interp: %q, rlimit stack cur: 0x%X, "+
		"rlimit stack max: 0x%X, current of top mem: 0x%X",
		data.TrimBytes2Str(a.Filename[:]), data.TrimBytes2Str(a.Fdpath[:]), data.TrimBytes2Str(a.Interp[:]),
		a.RlimCur, a.RlimMax, a.CurTopOfMem)
	return data.NewAnalyseData(form.NewMarkdown(s))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "alloc_bprm",
		Source:  allowBprmSource,
		Events: []*bcc.Event{
			bcc.NewKretprobeEvent("kretprobe__alloc_bprm", "alloc_bprm", -1),
		},
		IsEnd: false,
	})
	m.RegisterOnceTable("call_event", modules.RenderHandler(&allocBprmEvent{}))
	factory.Register(m.Mm())
}
