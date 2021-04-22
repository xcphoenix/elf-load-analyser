package module

import (
	_ "embed" // embed for vm_brk_flags
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/handler/virtualm"
)

//go:embed src/vm_brk_flags.c.k
var vmBrkFlagsSource string

const (
	interpFlag = 0x1000
	vmaMerged  = 0x0100
	mapedFlag  = 0x0010
)

type vmBrkFlagsEvent struct {
	enhance.TimeEventResult

	Type   uint32
	Start  uint64
	Length uint64
	Prot   uint64

	VmaStart uint64
	VmaEnd   uint64
	VmaOff   uint64
	VmaFlags uint64
	VmaProt  uint64
}

func (v vmBrkFlagsEvent) Render() *data.AnalyseData {
	result := data.NewSet(
		form.NewMarkdown(fmt.Sprintf("%s 映射 bss 段", helper.IfElse(v.Type&interpFlag > 0, "解释器", "ELF文件").(string))),
		form.NewList(
			fmt.Sprintf("Start: %x, length: %x", v.Start, v.Length),
			fmt.Sprintf("Prot:  %x", v.Prot),
		),
	)
	aData := data.NewAnalyseData(result)

	if v.Type&mapedFlag != 0 {
		if v.Type&vmaMerged != 0 {
			result.Combine(form.NewMarkdown("合并VMA"))
			// TODO vma合并细节
		} else {
			result.Combine(form.NewMarkdown("匿名映射VMA"))
			aData.PutExtra(virtualm.VmaFlag, virtualm.MapVmaEvent{
				NewVma: virtualm.BuildVma(v.VmaStart, v.VmaEnd, v.VmaFlags, v.VmaOff, virtualm.AnonymousMap),
			})
		}
	}
	return aData
}

func init() {
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "vm_brk_flags",
		Source:  vmBrkFlagsSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__total_mapping_size", "total_mapping_size", -1),
			bcc.NewKprobeEvent("kprobe__vm_brk_flags", "vm_brk_flags", -1),
			bcc.NewKretprobeEvent("kretprobe__vm_brk_flags", "vm_brk_flags", -1),
			bcc.NewKretprobeEvent("kretprobe__vma_merge", "vma_merge", -1),
			bcc.NewKprobeEvent("kprobe__vma_link", "vma_link", -1),
		},
	})
	m.RegisterTable("vm_brk_flags_events", true, modules.RenderHandler(&vmBrkFlagsEvent{}))
	factory.Register(m.Mm())
}
