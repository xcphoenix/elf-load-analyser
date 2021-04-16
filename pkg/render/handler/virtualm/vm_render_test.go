package virtualm

import (
	"os"
	"testing"
)

func TestVirtualMemory_Render(t *testing.T) {
	virtualMemory := newVirtualMemory()
	catPath := "/usr/bin/cat"
	virtualMemory.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0x55c03db9d000, 0x55c03db9e000, 1, 0x1, 0x0, catPath),
	})
	virtualMemory.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0x55e913f21000, 0x55e913f25000, 5, 0x1, 0x1000, catPath),
	})
	virtualMemory.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0x55e913f25000, 0x55e913f28000, 1, 0x1, 0x5000, catPath),
	})
	virtualMemory.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0x55e913f3f000, 0x55e913f60000, 5, 0x1, 0x0, HeapMap),
	})
	virtualMemory.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0x7f5d19ba1000, 0x7f5d19ba2000, 5, 0x1, 0x6000, "/usr/lib/ld-2.33.so"),
	})
	virtualMemory.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0x7ffe328d3000, 0x7ffe328f4000, 5, 0x1, 0x0, StackMap),
	})

	f, err := os.Create("testdata/test.html")
	if err != nil {
		return
	}
	bar := virtualMemory.ChartsRender("http://127.0.0.1:8080/assets/")
	_ = bar.Render(f)
}
