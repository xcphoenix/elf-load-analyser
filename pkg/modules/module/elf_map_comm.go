package module

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
	"github.com/xcphoenix/elf-load-analyser/pkg/xsys/xfs"
)

type commonElfMapEventType struct {
	Vaddr       uint64
	ShiftedAddr uint64
	AlignedAddr uint64
	ActualAddr  uint64
	Size        uint64
	Off         uint64

	VmaStart uint64
	VmaEnd   uint64
	VmaOff   uint64
	VmaFlags uint64

	TotalSize uint64
	INode     uint64
}

func (e commonElfMapEventType) Render() *data.AnalyseData {
	return data.NewLazyAnalyseData(func(aData *data.AnalyseData) data.Content {
		result := data.NewSet().Combine(
			form.NewMarkdown("ELF解释器映射操作\n\n"),
			form.NewFmtList(form.Fmt{
				{"偏移后的地址: 0X%X", e.ShiftedAddr},
				{"ELF文件中的虚拟地址: 0X%X", e.Vaddr},
				{"实际的虚拟地址: 0X%X", e.ActualAddr},
			}),
			form.NewFmtList(form.Fmt{
				{"当前段大小：0X%X", e.Size},
				{"当前段偏移：0X%X", e.Off},
			}),
			form.NewFmtList(form.Fmt{
				{"VMA地址: [0x%X, 0x%X]", e.VmaStart, e.VmaStart + e.Size},
				{"VMA类型: 0x%X, 在文件中的偏移(若存在): 0x%X", e.VmaFlags, e.Off},
			}),
		)
		event := virtualm.MapVmaEvent{
			// ps: 第一次 elf_map 会先映射整体，所以不能直接用 v.VmaEnd
			NewVma: virtualm.BuildVma(e.VmaStart, e.VmaStart+e.Size, e.VmaFlags, e.Off, xfs.INodePath(e.INode)),
		}
		aData.PutExtra(virtualm.VmaFlag, event)
		return result
	})
}
