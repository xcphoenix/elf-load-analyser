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
	res := data.NewSet(
		form.NewMarkdown("分配空间，保存二进制文件参数"),
		form.NewList(
			fmt.Sprintf("filename: %q", data.TrimBytes2Str(a.Filename[:])),
			fmt.Sprintf("fdpath:   %q", data.TrimBytes2Str(a.Fdpath[:])),
			fmt.Sprintf("interp:   %q", data.TrimBytes2Str(a.Interp[:])),
			fmt.Sprintf("rlimit stack cur:   0x%X", a.RlimCur),
			fmt.Sprintf("rlimit stack max:   0x%X", a.RlimMax),
			fmt.Sprintf("current of top mem: 0x%X", a.CurTopOfMem),
		),
	)
	return data.NewAnalyseData(res)
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
