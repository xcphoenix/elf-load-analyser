package progress

import (
	"fmt"
	"testing"
	"time"
)

func TestDrawBar(t *testing.T) {
	var cnt, total = 0, 100
	DrawBar(
		NewAdaptiveBarFormatter(func(definition BarDefinition, size Size) string {
			return definition.String()
		}, func() string {
			return "DOWNLOAD OK!"
		}, func(err error) string {
			return "DOWNLOAD ERROR: " + err.Error()
		}, func(pro Process) BarDefinition {
			return BarDefinition{
				Left: func() string {
					return "xxx.zip"
				},
				Right: func() string {
					return fmt.Sprintf("%d / %d", pro.CurVal, pro.TotalVal)
				},
				Process: ProcessDefinition{
					Boundary: [2]string{"[", "]"},
					Remain: func(width int) (str string) {
						if width == 0 {
							return
						}
						var idx = 0
						for idx < width-1 {
							str += "="
							idx++
						}
						return str + ">"
					},
					Finish: func(width int) string {
						var str = ""
						var idx = 0
						for idx < width {
							str += "-"
							idx++
						}
						return str
					},
				},
			}
		}),
		50*time.Millisecond,
		func() Process {
			var process = Process{
				CurVal:   uint(cnt),
				TotalVal: uint(total),
			}
			cnt++
			return process
		})
}
