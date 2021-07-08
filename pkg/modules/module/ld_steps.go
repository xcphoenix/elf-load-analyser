package module

import (
	_ "embed" // embed for ld_steps
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
	"strings"
)

//go:embed src/ld_steps.c.k
var ldStepSource string

type bootstrapStepEvent struct {
	enhance.TimeEventResult
}

func (b bootstrapStepEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("ld 自举完成"))
}

type startUserProgEvent struct {
	enhance.TimeEventResult
}

func (s startUserProgEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("将控制权交给用户程序"))
}

type protectRelroEvent struct { //nolint:maligned
	enhance.TimeEventResult
	LAddr       uint64
	Name        [256]byte
	Start       uint64
	Prot        int64
	Len         uint32
	IsDoProtect bool
}

func (p protectRelroEvent) Render() *data.AnalyseData {
	objectName := helper.TrimBytes2Str(p.Name[:])
	// NOTE: 目前不确定是否是特例
	if len(objectName) == 0 {
		objectName = "可执行程序"
	}
	res := data.NewSet(
		form.NewMarkdown(fmt.Sprintf("%q 存在 GNU_RELRO 段", objectName)),
		form.NewFmtList(form.Fmt{
			{"对象的加载地址: 0x%x", p.LAddr},
			{"按页向下对其后: 开始地址和结束地址处于%s", helper.IfElse(p.IsDoProtect,
				fmt.Sprintf("不同页, 执行 mprotect 操作, 开始地址: 0x%x, 长度: 0x%x, 设置只读权限", p.Start, p.Len),
				"同一页, 忽略",
			)},
		}),
	)
	var aData = data.NewAnalyseData(res)
	if p.IsDoProtect {
		aData.PutExtra(virtualm.VmaFlag, virtualm.MprotectFixupEvent{
			Start: p.Start,
			End:   p.Start + uint64(p.Len),
			Flags: uint64(p.Prot),
		})
	}
	return aData
}

type normalMprotectEvent struct {
	enhance.TimeEventResult
	Start uint64
	Prot  int64
	Len   uint32
}

func (n normalMprotectEvent) Render() *data.AnalyseData {
	end := n.Start + uint64(n.Len)
	res := data.NewSet(form.NewMarkdown(fmt.Sprintf("修改 [0x%x, 0x%x] 权限为: %x", n.Start, end, n.Prot)))
	return data.NewAnalyseData(res).
		PutExtra(virtualm.VmaFlag, virtualm.MprotectFixupEvent{
			Start: n.Start,
			End:   end,
			Flags: uint64(n.Prot),
		})
}

type mapObjectFromFdEvent struct {
	enhance.TimeEventResult
	RealName [256]byte
	Fd       int32
}

func (m mapObjectFromFdEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("开始映射共享对象: " + helper.TrimBytes2Str(m.RealName[:])))
}

type MmapEvent struct {
	enhance.TimeEventResult
	Addr   uint64
	Len    uint32
	Prot   int64
	Flags  int64
	Fd     int64
	Offset uint64
	Name   [256]byte
}

func (m MmapEvent) Render() *data.AnalyseData {
	var mapName = helper.TrimBytes2Str(m.Name[:])
	if len(mapName) == 0 {
		if m.Fd < 0 {
			mapName = "匿名页"
		} else {
			mapName = fmt.Sprintf("unknown(fd = %d)", m.Fd)
		}
	}

	res := data.NewSet(
		form.NewMarkdown("开始映射: "+mapName),
		form.NewFmtList(form.Fmt{
			{"地址范围: [0x%x, 0x%x]", m.Addr, m.Addr + uint64(m.Len)},
			{"偏移: 0x%x, Prot: 0x%x, Flags: 0x%x", m.Offset, m.Prot, m.Flags},
		}),
	)
	return data.NewAnalyseData(res).
		PutExtra(virtualm.VmaFlag, virtualm.MapVmaEvent{
			NewVma: virtualm.BuildVma(m.Addr, m.Addr+uint64(m.Len), uint64(m.Prot), m.Offset,
				helper.IfElse(m.Fd < 0, virtualm.AnonymousMap, mapName).(string),
			),
		})
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Name:   "ld_steps",
		Source: ldStepSource,
		LazyInit: func(mm *modules.MonitorModule, param bcc.PreParam) bool {
			mm.Events = []*bcc.Event{
				bcc.NewUprobeEvent("bootstrap_finished", "__rtld_malloc_init_stubs", param.Interp, -1),
				bcc.NewUretprobeEvent("start_user_prog", "_dl_start", param.Interp, -1),

				bcc.NewUprobeEvent("dl_protect_relro", "_dl_protect_relro", param.Interp, -1),
				bcc.NewUretprobeEvent("mprotect", "__mprotect", param.Interp, -1),
				bcc.NewUretprobeEvent("mprotect", "mprotect", param.Interp, -1),
				bcc.NewUretprobeEvent("ret_dl_protect_relro", "_dl_protect_relro", param.Interp, -1),

				// bcc.NewUprobeEvent("munmap", "__munmap", param.Interp, -1),
				// bcc.NewKprobeEvent("mmap", bpf.GetSyscallFnName("mmap"), -1),

				bcc.NewUprobeEvent("dl_map_object_from_fd", "_dl_map_object_from_fd", param.Interp, -1),
				bcc.NewUretprobeEvent("ret_dl_map_object_from_fd", "_dl_map_object_from_fd", param.Interp, -1),
			}
			mm.IsEnd = len(param.Interp) != 0 && strings.Contains(param.Interp, "ld-linux")
			return !mm.IsEnd
		},
	})
	m.RegisterOnceTable("bootstrap_finished_events", modules.RenderHandler(bootstrapStepEvent{}, nil))
	m.RegisterOnceTable("start_user_prog_events", modules.RenderHandler(startUserProgEvent{}, nil))
	m.RegisterTable("protect_relro_events", true, modules.RenderHandler(protectRelroEvent{}, nil))

	m.RegisterTable("mprotect_events", true, modules.RenderHandler(normalMprotectEvent{}, nil))

	m.RegisterTable("map_object_events", true, modules.RenderHandler(mapObjectFromFdEvent{}, nil))
	// m.RegisterTable("mmap_events", true, modules.RenderHandler(&MmapEvent{}))

	m.SetMark("start_user_prog_events", perf.EndFlag)
	factory.Register(m)
}
