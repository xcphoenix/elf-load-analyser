package module

import (
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/handler/virtualm"
	"github.com/xcphoenix/elf-load-analyser/pkg/xsys/xfs"
)

type commonElfMapEventType struct {
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

func (e commonElfMapEventType) Render() *data.AnalyseData {
	return data.NewLazyAnalyseData(func(aData *data.AnalyseData) data.Content {
		result := data.NewSet().Combine(
			form.NewMarkdown("ELF解释器映射操作\n\n"),
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
