package module

import (
	_ "embed" // for embed bcc source
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
	"strconv"
	"strings"

	"github.com/xcphoenix/elf-load-analyser/pkg/helper"

	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
)

//go:embed src/elf_map.c.k
var elfMapSource string

var elfFilePath string

type elfMapEventType struct {
	enhance.TimeEventResult
	commonElfMapEventType
}

func (e elfMapEventType) Render() *data.AnalyseData {
	var result = e.commonElfMapEventType.Render()
	var event = virtualm.MapVmaEvent{
		// ps: 第一次 elf_map 会先映射整体，所以不能直接用 v.VmaEnd
		NewVma: virtualm.BuildVma(e.VmaStart, e.VmaStart+e.Size, e.VmaFlags, e.Off, elfFilePath),
	}
	return result.PutExtra(virtualm.VmaFlag, event)
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
		form.NewFmtList(form.Fmt{
			{"是否为动态共享对象: %v", e.IsDyn},
			{"是否含有解释器: %v", e.WithInterp},
			{"ELF入口地址: 0X%X", e.EEntry},
			{"可加载段最大对齐值: 0X%X", e.MaxAlign},
			{"是否开启数据段、代码段地址随机化: %v", e.IsRnd},
			{"地址随机化值: 0X%X", e.Rnd},
		}),
		form.NewFmtList(form.Fmt{
			{"加载地址：0X%X", e.LoadAddr},
			{"加载偏移：0X%X", e.LoadBias},
		}),
	)
	return data.NewAnalyseData(result)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Name:   "elf_map",
		Source: elfMapSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__elf_map", "elf_map", -1),
			bcc.NewKretprobeEvent("kretprobe__elf_map", "elf_map", -1),
			bcc.NewKprobeEvent("kprobe__set_brk", "set_brk", -1),
			bcc.NewKretprobeEvent("kretprobe__arch_mmap_rnd", "arch_mmap_rnd", -1),
			bcc.NewKprobeEvent("kprobe__total_mapping_size", "total_mapping_size", -1),
			bcc.NewKprobeEvent("kprobe__vma_link", "vma_link", -1),
		},
		LazyInit: func(mm *modules.MonitorModule, param bcc.PreParam) bool {
			elfFilePath = param.Path
			mm.Source = strings.ReplaceAll(mm.Source, "_ISDYN_", helper.IfElse(param.IsDyn, "1", "0").(string))
			mm.Source = strings.ReplaceAll(mm.Source, "_ENTRY_", strconv.FormatUint(param.Header.Entry, 10))
			return false
		},
	})
	m.RegisterTable("elf_map_events", true, modules.RenderHandler(elfMapEventType{}, nil))
	m.RegisterOnceTable("elf_map_prop_events", modules.RenderHandler(elfMapPropEventType{}, nil))
	factory.Register(m)
}
