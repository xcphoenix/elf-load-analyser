package module

import (
	_ "embed" // for embed bcc source
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/handler/virtualm"
	"github.com/xcphoenix/elf-load-analyser/pkg/xsys/xfs"
	"strconv"
	"strings"

	"github.com/xcphoenix/elf-load-analyser/pkg/helper"

	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/enhance"
)

//go:embed src/elf_map.c.k
var elfMapSource string

type elfMapEventType struct {
	enhance.TimeEventResult

	Vaddr       uint64
	ShiftedAddr uint64
	AlignedAddr uint64
	ActualAddr  uint64
	Size        uint64
	Off         uint64
	Prot        int64
	Type        int64

	TotalSize uint64
	INode     uint64
}

func (e elfMapEventType) Render() *data.AnalyseData {
	return data.NewLazyAnalyseData(func(aData *data.AnalyseData) data.Content {
		result := data.NewSet().Combine(
			form.NewMarkdown("文件映射操作\n\n"),
			form.NewList(
				fmt.Sprintf("偏移后的地址: 0X%X", e.ShiftedAddr),
				fmt.Sprintf("ELF文件中的虚拟地址: 0X%X", e.Vaddr),
				fmt.Sprintf("实际的虚拟地址: 0X%X", e.ActualAddr),
			),
			form.NewList(
				fmt.Sprintf("当前段大小：0X%X", e.Size),
				fmt.Sprintf("当前段偏移：0X%X", e.Off),
			),
			form.NewList(
				fmt.Sprintf("VMA权限: 0X%X", e.Prot),
				fmt.Sprintf("VMA类型: 0x%X", e.Type),
			),
		)
		event := virtualm.MapVmaEvent{
			NewVma: virtualm.BuildVma(e.ActualAddr, e.ActualAddr+e.Size, uint(e.Prot), uint(e.Type), e.Off, xfs.INodePath(e.INode)),
		}
		aData.PutExtra(virtualm.VmaFlag, event)
		return result
	})
}

type elfMapPropEventType struct {
	enhance.TimeEventResult

	LoadAddr uint64
	LoadBias uint64

	EEntry    uint64
	StartCode uint64
	StartData uint64
	EndCode   uint64
	EndData   uint64
	ElfBss    uint64
	ElfBrk    uint64

	FirstPaged uint64
	Rnd        uint64
	MaxAlign   uint32
	IsDyn      bool
	WithInterp bool
	IsRnd      bool
}

func (e elfMapPropEventType) Render() *data.AnalyseData {
	e.StartCode += e.LoadAddr
	e.EndCode += e.LoadAddr
	e.StartData += e.LoadAddr
	e.EndData += e.LoadAddr
	e.ElfBss += e.LoadAddr
	e.ElfBrk += e.LoadAddr

	result := data.NewSet().Combine(
		form.NewMarkdown("获取文件映射相关属性\n\n"),
		form.NewList(
			fmt.Sprintf("是否为动态共享对象: %v", e.IsDyn),
			fmt.Sprintf("是否含有解释器: %v", e.WithInterp),
			fmt.Sprintf("ELF入口地址: 0X%X", e.EEntry),
			fmt.Sprintf("可加载段最大对齐值: 0X%X", e.MaxAlign),
			fmt.Sprintf("是否开启数据段、代码段地址随机化: %v", e.IsRnd),
			fmt.Sprintf("地址随机化值: 0X%X", e.Rnd),
		),
		form.NewList(
			fmt.Sprintf("加载地址：0X%X", e.LoadAddr),
			fmt.Sprintf("加载偏移：0X%X", e.LoadBias),
		),
	)
	return data.NewAnalyseData(result)
}

func init() {
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "elf_map",
		Source:  elfMapSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__elf_map", "elf_map", -1),
			bcc.NewKretprobeEvent("kretprobe__elf_map", "elf_map", -1),
			bcc.NewKprobeEvent("kprobe__set_brk", "set_brk", -1),
			bcc.NewKretprobeEvent("kretprobe__arch_mmap_rnd", "arch_mmap_rnd", -1),
			bcc.NewKprobeEvent("kprobe__total_mapping_size", "total_mapping_size", -1),
		},
		LazyInit: func(mm *modules.MonitorModule, param bcc.PreParam) bool {
			mm.Source = strings.ReplaceAll(mm.Source, "_ISDYN_", helper.IfElse(param.IsDyn, "1", "0").(string))
			mm.Source = strings.ReplaceAll(mm.Source, "_ENTRY_", strconv.FormatUint(param.Header.Entry, 10))
			return false
		},
	})
	m.RegisterTable("elf_map_events", true, func(data []byte) (*data.AnalyseData, error) {
		return modules.Render(data, &elfMapEventType{}, true)
	})
	m.RegisterOnceTable("elf_map_prop_events", func(data []byte) (*data.AnalyseData, error) {
		return modules.Render(data, &elfMapPropEventType{}, true)
	})
	factory.Register(m.Mm())
}
