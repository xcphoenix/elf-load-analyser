package module

import (
	_ "embed" // embed for set_brk
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/set_brk.c.k
var setBrkSource string

type setBrkEvent struct {
	enhance.TimeEventResult

	Start        uint64
	End          uint64
	StartAligned uint64
	EndAligned   uint64
	Prot         int64
	ClearBytes   uint32
	ExecProt     uint32
}

func (s setBrkEvent) Render() *data.AnalyseData {
	result := data.NewSet(
		form.NewMarkdown("可加载段 p_memsz > p_filesz，映射匿名页"),
		form.NewFmtList(form.Fmt{
			{"Start(elf_bss): %x, after alignment: %x", s.Start, s.StartAligned},
			{"End(elf_brk):   %x, after alignment: %x", s.End, s.EndAligned},
			{"Prot: %x", s.Prot},
		}),
	)
	if s.EndAligned > s.StartAligned {
		var prot = "0"
		if s.ExecProt != 0 {
			prot = "VM_EXEC"
		}
		result.Combine(form.NewMarkdown("映射最后的匿名页").AppendCode(
			"c",
			fmt.Sprintf("vm_brk_flags(%x, %x, %s)", s.StartAligned, s.EndAligned-s.StartAligned, prot)),
		)
	}
	result.Combine(form.NewMarkdown(fmt.Sprintf("设置堆(start_brk, brk) = %x", s.EndAligned)))
	if s.ClearBytes > 0 {
		result.Combine(form.NewMarkdown(fmt.Sprintf("清除 bss 未映射的剩下区域 (%x, %x)", s.Start, s.Start+uint64(s.ClearBytes))))
	}

	return data.NewAnalyseData(result).
		PutExtra(virtualm.VmaFlag, virtualm.NewVMIndicatricesEvent(map[string]uint64{
			"StartBrk": s.EndAligned,
			"Brk":      s.EndAligned,
		}))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "set_brk",
		Source:   setBrkSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__set_brk", "set_brk", -1)},
		CanMerge: true,
	})
	m.RegisterTable("set_brk_events", true, monitor.RenderHandler(setBrkEvent{}, nil))
	factory.Register(m)
}
