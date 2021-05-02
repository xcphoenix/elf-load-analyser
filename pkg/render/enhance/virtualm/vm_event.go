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
	TgtVma Vma    // target vma
	Start  uint64 // region start
	End    uint64 // region end
	Flags  uint64 // new flags
}

func (m MprotectFixupEvent) doEvent(memory *virtualMemory) {
	if len(memory.vmaList) == 0 {
		return
	}

	var refactorVmas = make([]int, 0)
	// 仅关注 TgtVma 的区间范围
	startVal := m.TgtVma.Start
	endVal := m.TgtVma.End

	// TODO: 优化排序，目前存在很多的冗余操作
	// 地址从高到底排序
	sort.Sort(vmaList(memory.vmaList))

	for i, vma := range memory.vmaList {
		if vma.Start >= endVal {
			continue
		}
		if vma.End <= startVal {
			break
		}
		i := i
		refactorVmas = append(refactorVmas, i)
	}

	switch len(refactorVmas) {
	case 0:
		// 直接创建 vma
		memory.vmaList = append(memory.vmaList, BuildVma(m.Start, m.End, m.Flags, m.TgtVma.Offset, m.TgtVma.MappedFile))
	default:
		var topChangedVma, bottomChangedVma Vma
		_ = deepcopy.Copy(&topChangedVma, &(memory.vmaList[refactorVmas[0]])).Do()
		_ = deepcopy.Copy(&bottomChangedVma, &(memory.vmaList[refactorVmas[len(refactorVmas)-1]])).Do()

		topRegionLen := topChangedVma.End - endVal
		bottomRegionLen := startVal - bottomChangedVma.Start

		for _, vmaIdx := range refactorVmas {
			memory.vmaList[vmaIdx].Flags = m.Flags
		}

		if topRegionLen > 0 {
			memory.vmaList[refactorVmas[0]].End = endVal
			topChangedVma.Start = endVal
		}
		if bottomRegionLen > 0 {
			memory.vmaList[refactorVmas[len(refactorVmas)-1]].Start = startVal
			bottomChangedVma.End = startVal
		}

		if topRegionLen > 0 {
			memory.vmaList = append(memory.vmaList, topChangedVma)
		}
		if bottomRegionLen > 0 {
			memory.vmaList = append(memory.vmaList, bottomChangedVma)
		}
	}

	// TODO merge same attr vma
}

// ShiftVmaEvent simulate `shift_arg_pages`, but just change vma region
type ShiftVmaEvent struct {
	TgtVma Vma
	Shift  uint64
}

func (s ShiftVmaEvent) doEvent(memory *virtualMemory) {
	// 暂时忽略 vma 重合等异常情况

	for _, vma := range memory.vmaList {
		if vma.Start == s.TgtVma.Start {
			vma.Start -= s.Shift
			vma.End -= s.Shift
			break
		}
	}
}

// TaskSizeVmEvent 设置进程虚拟空间大小事件
type TaskSizeVMEvent struct {
	TaskSize uint64
}

func (t TaskSizeVMEvent) doEvent(memory *virtualMemory) {
	memory.taskSize = t.TaskSize
}

// MMapVMEvent mmap base属性
type MMapVMEvent struct {
	MmapBase uint64
}

func (m MMapVMEvent) doEvent(memory *virtualMemory) {
	memory.mmapBase = m.MmapBase
}

// BrkVMEvent 堆属性
type BrkVMEvent struct {
	StartBrk uint64
	Brk      uint64
}

func (b BrkVMEvent) doEvent(memory *virtualMemory) {
	memory.startBrk = b.StartBrk
	memory.brk = b.Brk
}
