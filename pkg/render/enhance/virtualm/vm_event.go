package virtualm

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
