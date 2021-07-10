package progress

import (
	"fmt"
	"time"
)

type Process struct {
	CurVal   uint
	TotalVal uint
	Err      error
	Other    interface{}
}

type Size int

type Formatter interface {
	Format(s Size, pro Process) string
}

type ProcessDefinition struct {
	remainWidth, finishWidth int

	Boundary [2]string
	Remain   func(width int) string
	Finish   func(width int) string
}

func (pd ProcessDefinition) String() string {
	return fmt.Sprintf("%s%s%s%s", pd.Boundary[0], pd.Remain(pd.finishWidth), pd.Finish(pd.remainWidth), pd.Boundary[1])
}

type BarDefinition struct {
	Left    func() string
	Right   func() string
	Process ProcessDefinition
}

// left              process            right
//   len(left)  +  len(process)  +  len(right) + 2 = size
//                      |
// len(Boundary[0]) + len(Boundary[1]) + remainWidth + finishWidth
//
// barLen = size - len(left) - len(right) - len(Boundary[0]) - len(Boundary[1])
// if barLen >= 2  可以计算
// else
//    计算满足 barLen >= 2 前提下，left 和 right 要缩减的字符，必要时将左右边界缩减为1个字符
//    若缩减后，左右边界字符数都小于4，加上左右边界都为1个字符的前提下，仍然无法输出，直接以文本方式输出
//
func (bd BarDefinition) String() string {
	return fmt.Sprintf("%s %s %s", bd.Left(), bd.Process, bd.Right())
}

type DefinitionAdaptor func(definition BarDefinition, size Size) string

type AdaptiveBarFormatter struct {
	Adaptor DefinitionAdaptor

	Success    func() string
	Failure    func(err error) string
	Processing func(pro Process) BarDefinition
}

func NewAdaptiveBarFormatter(adaptor DefinitionAdaptor,
	success func() string,
	failure func(err error) string,
	processing func(pro Process) BarDefinition) *AdaptiveBarFormatter {
	return &AdaptiveBarFormatter{Adaptor: adaptor, Success: success, Failure: failure, Processing: processing}
}

func (formatter AdaptiveBarFormatter) Format(s Size, pro Process) string {
	if pro.Err != nil {
		return formatter.Failure(pro.Err) + "\n"
	}

	if pro.CurVal >= pro.TotalVal {
		return formatter.Success() + "\n"
	}
	var definition = formatter.Processing(pro)
	// 假设
	definition.Process.finishWidth, definition.Process.remainWidth = int(pro.CurVal), int(pro.TotalVal-pro.CurVal)
	return formatter.Adaptor(definition, s)
}

func DrawBar(formatter Formatter, interval time.Duration, fun func() Process) {
	for {
		var process = fun()
		var size = Size(100)

		_ = CarriageRetEcho(formatter.Format(size, process))
		if process.CurVal >= process.TotalVal {
			return
		}
		time.Sleep(interval)
	}
}

func CarriageRetEcho(str string) (err error) {
	str = "\r\033[K" + str
	fmt.Print(str)
	return
}
