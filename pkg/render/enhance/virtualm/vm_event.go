package virtualm

import (
	"github.com/antlabs/deepcopy"
	"sort"
)

// VmEvent 事件
type VMEvent interface {
	doEvent(memory *virtualMemory) // ApplyEvent 应用事件到虚拟内存中
}

// MapVmaEvent 映射事件
type MapVmaEvent struct {
	NewVma Vma
}

// ApplyEvent 添加 VMA
func (m MapVmaEvent) doEvent(memory *virtualMemory) {
	memory.vmaList = append(memory.vmaList, m.NewVma)
}

// MprotectFixupEvent simulate `mprotect_fixup` behavior
type MprotectFixupEvent struct {
	Start uint64 // region start
	End   uint64 // region end
	Flags uint64 // new flags
}

func (m MprotectFixupEvent) doEvent(memory *virtualMemory) {
	if len(memory.vmaList) == 0 {
		return
	}

	var refactorVmas = make([]int, 0)

	// TODO: 优化排序，目前存在很多的冗余操作
	// 地址从高到底排序
	sort.Sort(vmaList(memory.vmaList))

	for i, vma := range memory.vmaList {
		if vma.Start >= m.End {
			continue
		}
		if vma.End <= m.Start {
			break
		}
		i := i
		refactorVmas = append(refactorVmas, i)
	}

	if len(refactorVmas) == 1 {
		var topChangedVma, bottomChangedVma Vma
		_ = deepcopy.Copy(&topChangedVma, &(memory.vmaList[refactorVmas[0]])).Do()
		_ = deepcopy.Copy(&bottomChangedVma, &(memory.vmaList[refactorVmas[len(refactorVmas)-1]])).Do()
		topRegionLen := topChangedVma.End - m.End
		bottomRegionLen := m.Start - bottomChangedVma.Start
		for _, vmaIdx := range refactorVmas {
			memory.vmaList[vmaIdx].Flags = m.Flags
		}
		if topRegionLen > 0 {
			memory.vmaList[refactorVmas[0]].End = m.End
			topChangedVma.Start = m.End
		}
		if bottomRegionLen > 0 {
			memory.vmaList[refactorVmas[len(refactorVmas)-1]].Start = m.Start
			bottomChangedVma.End = m.Start
		}
		if topRegionLen > 0 {
			memory.vmaList = append(memory.vmaList, topChangedVma)
		}
		if bottomRegionLen > 0 {
			memory.vmaList = append(memory.vmaList, bottomChangedVma)
		}
	}
}

// ShiftVmaEvent simulate `shift_arg_pages`, but just change vma region
type ShiftVmaEvent struct {
	TgtVma Vma
	Shift  uint64
}

func (s ShiftVmaEvent) doEvent(memory *virtualMemory) {
	// 暂时忽略 vma 重合等异常情况
	for i := range memory.vmaList {
		if memory.vmaList[i].Start == s.TgtVma.Start {
			memory.vmaList[i].Start -= s.Shift
			memory.vmaList[i].End -= s.Shift
			break
		}
	}
}

// AdjustVmaEvent simulate `__vma_adjust`, but just change vma region, ignore operation about insert and expand
type AdjustVmaEvent struct {
	VmaStart    uint64
	VmaEnd      uint64
	AdjustStart uint64
	AdjustEnd   uint64
	// ignore pgoff
}

func (a AdjustVmaEvent) doEvent(memory *virtualMemory) {
	if len(memory.vmaList) == 0 {
		return
	}
	for i := range memory.vmaList {
		if memory.vmaList[i].Start == a.VmaStart && memory.vmaList[i].End == a.VmaEnd {
			memory.vmaList[i].Start = a.AdjustStart
			memory.vmaList[i].End = a.AdjustEnd
		}
	}
}

type VMIndicatrixEvent struct {
	indicatrix map[string]uint64
}

func NewVMIndicatricesEvent(indicatrices map[string]uint64) *VMIndicatrixEvent {
	return &VMIndicatrixEvent{
		indicatrix: indicatrices,
	}
}

func NewVMIndicatrixEvent(desc string, addr uint64) *VMIndicatrixEvent {
	return &VMIndicatrixEvent{
		indicatrix: map[string]uint64{
			desc: addr,
		},
	}
}

func (v VMIndicatrixEvent) doEvent(memory *virtualMemory) {
	if len(v.indicatrix) == 0 {
		return
	}
	if memory.indicatrix == nil {
		memory.indicatrix = make(map[string]uint64, 0)
	}
	for desc, addr := range v.indicatrix {
		memory.indicatrix[desc] = addr
	}
}
