package virtualm

import (
	"bytes"
	"fmt"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"hash/fnv"
	"math"
	"sort"
	"strings"

	"github.com/go-echarts/go-echarts/charts"
)

const (
	AnonymousMap = ""
	HeapMap      = "[heap]"
	StackMap     = "[stack]"
	VvarMap      = "[vvar]"
	Vsyscall     = "[vsyscall]"
)

const (
	xvmRead  = 0x1
	xvmWrite = 0x2
	xvmExec  = 0x4
	xvmShare = 0x80
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
	Flags      uint64   `json:"flag"`
	Offset     uint64   `json:"offset"`
	MappedFile string   `json:"file"`
	Attr       string   `json:"attr"`
}

// BuildVma 创建 VMA, mappedFile 可选值：文件名称、AnonymousMap、HeapMap、StackMap、VvarMap、Vsyscall
func BuildVma(start uint64, end uint64, flag uint64, offset uint64, mappedFile string) Vma {
	v := Vma{
		Class: mapClass, Start: start, End: end,
		Flags: flag, Offset: offset,
		MappedFile: mappedFile,
	}
	v.Attr = v.AttrSerialize()
	return v
}

// AttrSerialize 获取权限
func (v Vma) AttrSerialize() string {
	var buf bytes.Buffer
	if v.Flags&xvmRead != 0 {
		buf.WriteRune('r')
	} else {
		buf.WriteRune('-')
	}
	if v.Flags&xvmWrite != 0 {
		buf.WriteRune('w')
	} else {
		buf.WriteRune('-')
	}
	if v.Flags&xvmExec != 0 {
		buf.WriteRune('x')
	} else {
		buf.WriteRune('-')
	}
	if v.Flags&xvmShare != 0 {
		buf.WriteRune('s')
	} else {
		buf.WriteRune('p')
	}
	return buf.String()
}

// Show 序列化显示，仿 /proc/xxx/maps
func (v Vma) Show() string {
	return fmt.Sprintf("%x-%x %s %08x %s\n", v.Start, v.End, v.AttrSerialize(), v.Offset, v.MappedFile)
}

type vmaList []Vma

func (vm vmaList) Len() int {
	return len(vm)
}

func (vm vmaList) Less(i, j int) bool {
	return vm[i].Start > vm[j].Start
}

func (vm vmaList) Swap(i, j int) {
	vm[i], vm[j] = vm[j], vm[i]
}

// virtualMemory 虚拟内存
type virtualMemory struct {
	word     uint
	taskSize uint64
	mmapBase uint64
	startBrk uint64
	brk      uint64

	vmaList []Vma
}

// newVirtualMemory 创建新的虚拟空间
func newVirtualMemory() *virtualMemory {
	return &virtualMemory{word: archWord(), vmaList: make([]Vma, 0)}
}

// ShowVM 虚拟空间序列化
func (vm virtualMemory) ShowVM() string {
	var buf bytes.Buffer
	for _, vma := range vm.vmaList {
		if vma.Class == fillClass {
			continue
		}
		buf.WriteString(vma.Show())
	}
	return strings.TrimSpace(buf.String())
}

// ApplyEvent 应用 VMEvent 事件
func (vm *virtualMemory) ApplyEvent(event VMEvent) (diff string) {
	before := vm.ShowVM()
	event.doEvent(vm)
	after := vm.ShowVM()
	unifiedDiff := difflib.UnifiedDiff{
		A:       difflib.SplitLines(before),
		B:       difflib.SplitLines(after),
		Context: 3,
	}
	diff, _ = difflib.GetUnifiedDiffString(unifiedDiff)
	return
}

// fillSlot 填充 vma 空槽
func (vm virtualMemory) fillSlot() []Vma {
	var tmpVmaList []Vma
	tmpVmaList = append(tmpVmaList, vm.vmaList...)
	sort.Sort(vmaList(tmpVmaList))
	var fillVma []Vma

	// 如果设置了 taskSize startBrk Brk 或者 mmapSize，找到其中的最大值
	// 如果这个值超出了当前 vma 最大值的范围（排序后第一个或者如果vma是空的话取0），映射这个区域
	newMaxAddr := maxAddr(vm.taskSize, vm.startBrk, vm.brk, vm.mmapBase)
	var curMaxAddr uint64
	if len(tmpVmaList) != 0 {
		curMaxAddr = tmpVmaList[0].End
	}
	if newMaxAddr > curMaxAddr {
		fillVma = append(fillVma, Vma{Class: fillClass, Start: curMaxAddr, End: newMaxAddr})
	}

	// 填充后面的区间
	if len(tmpVmaList) > 0 {
		lastStart := tmpVmaList[0].Start
		for _, vma := range tmpVmaList[1:] {
			if lastStart > vma.End {
				fillVma = append(fillVma, Vma{Class: fillClass, Start: vma.End, End: lastStart})
			}
			lastStart = vma.Start
		}
		if lastStart > 0 {
			fillVma = append(fillVma, Vma{Class: fillClass, Start: 0, End: lastStart})
		}
	}

	tmpVmaList = append(tmpVmaList, fillVma...)
	sort.Sort(sort.Reverse(vmaList(tmpVmaList)))
	return tmpVmaList
}

// ChartsRender 渲染数据到 Writer，设置host为js、css文件来源
//nolint:funlen
func (vm virtualMemory) ChartsRender(host string) *charts.Bar {
	tmpVmaList := vm.fillSlot()
	addrCnt := 0.0

	const tipsFormatter = `function(params) {
		let dot = '<span style="display:inline-block;margin-right:5px;border-radius:10px;width:10px;' +
				'height:10px;background-color:' + params.color + '"></span>';
		let obj = params.value[2];
		if (typeof(obj.kind) == 'undefined' || obj.kind !== 0) {
			return 'empty';
		}

		let startAddr = obj.start.toString(16);
		let endAddr = obj.end.toString(16);
		let addrItem = dot + '0x' + startAddr + ' - ' + '0x' + endAddr;
		
		let attrItem = dot + obj.attr;
		let offsetItem = dot + '0X' + obj.offset.toString(16);
		let fileItem = dot + obj.file;
		
		return '<div style="font-family: monospace">' + addrItem + '<br />' + attrItem 
			+ '<br />' + offsetItem + '<br />' + fileItem + '</div>';
	}
`

	const markLineFormatter = `function(params) {return params.name;}`

	vmBar := charts.NewBar()
	vmBar.SetGlobalOptions(
		charts.InitOpts{Height: "700px", Width: "80%", AssetsHost: host},
		charts.TitleOpts{Title: "用户地址空间", Left: "center"},
		charts.ToolboxOpts{Show: false},
		charts.LegendOpts{Data: []string{}},
		charts.TooltipOpts{Formatter: charts.FuncOpts(tipsFormatter)},
		charts.YAxisOpts{
			AxisLabel: charts.LabelTextOpts{Formatter: " "},
		},
	)

	var addrMap = make(map[uint64]float64)
	vmBar.AddXAxis([]string{" "})
	for i := range tmpVmaList {
		vma := tmpVmaList[i]

		vmData := [][]interface{}{{0, flatAddr(vma.End - vma.Start), vma}}
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
				Symbol:     []string{"none", "none"},
				SymbolSize: 20,
				Label:      charts.LabelTextOpts{Show: true, Formatter: charts.FuncOpts(markLineFormatter)},
			},
			charts.ItemStyleOpts{Color: vmaColor(vma)},
		}
		addrMap[vma.End] = addrCnt
		vmBar.AddYAxis(vma.MappedFile, vmData, opts...)
	}

	vmBar.Overlap(vm.renderAddr(addrMap))

	fn := fmt.Sprintf(`(function () {
        let targetType = 'scatter';
        let posOffset = [-350, 0];
        let series = option_%[1]s.series;
        series.forEach(function (element) {
          if (element.type === targetType) {
            element.symbolOffset = posOffset;
            element.symbolSize = 20;
            element.symbol = 'pin';
            element.symbolRotate = 40;
          }
        });
        myChart_%[1]s.setOption(option_%[1]s);
      })();`, vmBar.ChartID)
	vmBar.AddJSFuncs(fn)

	return vmBar
}

func (vm virtualMemory) renderAddr(addrMap map[uint64]float64) *charts.Scatter {
	scatter := charts.NewScatter()
	scatter.AddXAxis([]string{""})

	// 重新计算虚拟值
	if vm.taskSize > 0 {
		scatter.AddYAxis("task_size", []interface{}{calAddr(addrMap, vm.taskSize)}, charts.LabelTextOpts{
			Show:      true,
			Position:  "left",
			Formatter: fmt.Sprintf("task_size:\n%x", vm.taskSize),
		})
	}
	if vm.mmapBase > 0 {
		scatter.AddYAxis("mmap_base", []interface{}{calAddr(addrMap, vm.mmapBase)}, charts.LabelTextOpts{
			Show:      true,
			Position:  "left",
			Formatter: fmt.Sprintf("mmap_base:\n%x", vm.mmapBase),
		})
	}
	if vm.startBrk > 0 {
		scatter.AddYAxis("start_brk", []interface{}{calAddr(addrMap, vm.startBrk)}, charts.LabelTextOpts{
			Show:      true,
			Position:  "left",
			Formatter: fmt.Sprintf("start_brk:\n%x", vm.startBrk),
		})
	}
	return scatter
}

func calAddr(addrMap map[uint64]float64, realAddr uint64) float64 {
	var realAddrList = make([]uint64, len(addrMap))
	var cnt = 0
	for addr := range addrMap {
		realAddrList[cnt] = addr
		cnt++
	}
	// 升序排列
	sort.SliceStable(realAddrList, func(i, j int) bool {
		return realAddrList[i] < realAddrList[j]
	})

	const radioLimit = 3

	for i, addr := range realAddrList {
		switch {
		case addr == realAddr:
			return addrMap[addr]
		case addr > realAddr:
			start, vrStart, end, radio := uint64(0), float64(0), addr, float64(0)
			if i != 0 {
				start = realAddrList[i-1]
				vrStart = addrMap[start]
			}
			switch {
			case radioLimit*(end-realAddr) < end-start:
				radio = 1 - float64(1)/radioLimit
			case radioLimit*(end-realAddr) > (radioLimit-1)*(end-start):
				radio = float64(1) / radioLimit
			default:
				radio = (float64(realAddr) - float64(start)) / (float64(end) - float64(start))
			}
			return vrStart + (addrMap[addr]-vrStart)*radio
		}
	}
	return addrMap[realAddrList[cnt-1]]
}

func maxAddr(addrArray ...uint64) uint64 {
	if len(addrArray) == 0 {
		return 0
	}
	var max uint64
	for i := range addrArray {
		if addrArray[i] > max {
			max = addrArray[i]
		}
	}
	return max
}

// flatAddr 地址映射
func flatAddr(addr uint64) float64 {
	return math.Log2(math.Log2(float64(addr/0x1000)+1)+1) + 1
}

// archWord 判断是32还是64
func archWord() uint {
	return 32 << (^uint(0) >> 63)
}

func hash(s string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return int(h.Sum32())
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
