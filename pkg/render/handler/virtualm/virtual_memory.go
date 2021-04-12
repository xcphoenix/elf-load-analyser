package virtualm

import (
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"hash/fnv"
	"math"
	"sort"

	"github.com/go-echarts/go-echarts/charts"
)

const (
	EmptyMap = ""
	HeapMap  = "[heap]"
	StackMap = "[stack]"
	VvarMap  = "[vvar]"
	Vsyscall = "[vsyscall]"
)

type vmaClass uint8

const (
	mapClass  = vmaClass(iota) // 默认类型
	fillClass                  // 用于渲染时填充空VMA，无实际意义
)

// Vma BuildVma 结构体
type Vma struct {
	Class      vmaClass `json:"kind"`
	Start      uint64   `json:"start"`
	End        uint64   `json:"end"`
	Prot       uint     `json:"prot"`
	Flag       uint     `json:"flag"`
	Offset     uint64   `json:"offset"`
	MappedFile string   `json:"file"`
}

// BuildVma 创建 VMA, mappedFile 可选值：文件名称、EmptyMap、HeapMap、StackMap、VvarMap、Vsyscall
func BuildVma(start uint64, end uint64, prot uint, flag uint, offset uint64, mappedFile string) Vma {
	return Vma{Class: mapClass, Start: start, End: end, Prot: prot, Flag: flag, Offset: offset, MappedFile: mappedFile}
}

// ProtDesc 获取权限
func (v Vma) ProtDesc() string {
	// TODO
	return ""
}

func (v Vma) Show() string {
	// TODO 按照 /proc/<pid>/maps 的方式输出
	return ""
}

// VmaData VMA数据，用于渲染图表
type VmaData []interface{}

// BuildVmaData 创建 VMA 数据集，echarts 数据是多维数组：X轴、Y轴、其他维度
func BuildVmaData(vma Vma) []VmaData {
	// 为了显示效果，保证数据长度尽量不相差太大
	size := math.Log2(math.Log2(float64((vma.End-vma.Start)/0x1000)+1)+1) + 1
	return []VmaData{{0, size, vma}}
}

// virtualMemory 虚拟内存
type virtualMemory struct {
	word    uint
	vmaList []Vma
}

func (vm *virtualMemory) Len() int {
	return len(vm.vmaList)
}

func (vm *virtualMemory) Less(i, j int) bool {
	return vm.vmaList[i].Start > vm.vmaList[j].Start
}

func (vm *virtualMemory) Swap(i, j int) {
	vm.vmaList[i], vm.vmaList[j] = vm.vmaList[j], vm.vmaList[i]
}

// newVirtualMemory 创建新的虚拟空间
func newVirtualMemory() *virtualMemory {
	return &virtualMemory{word: archWord(), vmaList: make([]Vma, 0)}
}

func (vm virtualMemory) ShowVm() string {
	// TODO 按照 /proc/<pid>/maps 的方式输出
	return ""
}

func (vm *virtualMemory) ApplyEvent(event VmaEvent) *virtualMemory {
	event.doEvent(vm)
	return vm
}

func (vm *virtualMemory) vMap(vma Vma) {
	vm.vmaList = append(vm.vmaList, vma)
}

// fillSlot 填充空槽
func (vm *virtualMemory) fillSlot() {
	if len(vm.vmaList) == 0 {
		return
	}
	sort.Sort(vm)
	var fillVma []Vma
	lastStart := vm.vmaList[0].Start
	for _, vma := range vm.vmaList[1:] {
		if lastStart > vma.End {
			fillVma = append(fillVma, Vma{Class: fillClass, Start: vma.End, End: lastStart})
		}
		lastStart = vma.Start
	}
	if lastStart > 0 {
		fillVma = append(fillVma, Vma{Class: fillClass, Start: 0, End: lastStart})
	}

	vm.vmaList = append(vm.vmaList, fillVma...)
	sort.Sort(sort.Reverse(vm))
}

// ChartsRender 渲染数据到 Writer，设置host为js、css文件来源
//nolint:funlen
func (vm *virtualMemory) ChartsRender(host string) *charts.Bar {
	vm.fillSlot()
	addrCnt := 0.0

	const tipsFormatter = `function(params) {
		let dot = '<span style="display:inline-block;margin-right:5px;border-radius:10px;width:10px;' +
				'height:10px;background-color:' + params.color + '"></span>';
		let obj = params.value[2];
		if (obj.kind !== 0) {
			return 'empty';
		}

		let startAddr = obj.start.toString(16);
		let endAddr = obj.end.toString(16);
		let addrItem = dot + '0x' + startAddr + ' - ' + '0x' + endAddr;
		
		let offsetItem = dot + '0X' + obj.offset.toString(16);
		let fileItem = dot + obj.file;
		
		return '<div style="font-family: monospace">' + addrItem + '<br />' + offsetItem + '<br />' + fileItem + '</div>';
	}
`

	const markLineFormatter = `function(params) {
		return params.name;
}
`

	vmBar := charts.NewBar()
	vmBar.SetGlobalOptions(
		charts.InitOpts{Height: "700px", Width: "100%", AssetsHost: host},
		charts.TitleOpts{Title: "用户地址空间", Left: "center"},
		charts.ToolboxOpts{Show: false},
		charts.LegendOpts{Data: []string{}},
		charts.TooltipOpts{Formatter: charts.FuncOpts(tipsFormatter)},
		charts.YAxisOpts{
			AxisLabel: charts.LabelTextOpts{Formatter: " "},
		},
	)

	vmBar.AddXAxis([]string{" "})
	for i := range vm.vmaList {
		vma := vm.vmaList[i]

		vmData := BuildVmaData(vma)
		addrCnt += vmData[0][1].(float64)

		var opts = []charts.SeriesOptser{
			charts.BarOpts{Stack: "stack"},
			charts.LabelTextOpts{
				Formatter: vma.MappedFile,
				Color:     "white",
				Show:      helper.IfElse(len(vma.MappedFile) == 0, false, true).(bool),
			},
			charts.MLNameYAxisItem{Name: fmt.Sprintf("0x%X", vma.End), YAxis: addrCnt},
			charts.MLStyleOpts{
				Symbol:     []string{"pin"},
				SymbolSize: 20,
				Label:      charts.LabelTextOpts{Show: true, Formatter: charts.FuncOpts(markLineFormatter)},
			},
			charts.ItemStyleOpts{Color: vmaColor(vma)},
		}
		vmBar.AddYAxis(vma.MappedFile, vmData, opts...)
	}
	return vmBar
}

// VmaEvent 事件
type VmaEvent interface {
	doEvent(memory *virtualMemory) // ApplyEvent 应用事件到虚拟内存中
}

// MapVmaEvent 映射事件
type MapVmaEvent struct {
	NewVma Vma
}

// ApplyEvent 添加 VMA
func (m MapVmaEvent) doEvent(memory *virtualMemory) {
	memory.vMap(m.NewVma)
}

// archWord 判断是32还是64
func archWord() uint {
	return 32 << (^uint(0) >> 63)
}

func hash(s string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return int(h.Sum32()) + len(s)
}

func vmaColor(vma Vma) string {
	var colors = [...]string{
		"#708090", "#20b2aa", "#778899", "#00a15c", "#00808c", "#6a5acd", "#704214", "#4798b3", "#a0522d", "#a16b47",
	}
	if vma.Class == fillClass {
		return "#eeeeee"
	}
	return colors[hash(vma.MappedFile)%len(colors)]
}
