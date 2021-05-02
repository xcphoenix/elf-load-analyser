package virtualm

import (
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

func TestMprotectFixupEvent(t *testing.T) {
	mem := newVirtualMemory()
	mem.ApplyEvent(MapVmaEvent{
		NewVma: BuildVma(0xf3000, 0xff000, 0x12, 0, ""),
	})
	mem.ApplyEvent(MprotectFixupEvent{
		Start: 0xf3000,
		End:   0xf4000,
		Flags: 0x24,
	})
	sort.Sort(sort.Reverse(vmaList(mem.vmaList)))
	assert.Equal(t, 2, len(mem.vmaList))
	assert.Equal(t, uint64(0x24), mem.vmaList[0].Flags)
	assert.Equal(t, uint64(0xf3000), mem.vmaList[0].Start)
	assert.Equal(t, uint64(0xf4000), mem.vmaList[0].End)

	mem.ApplyEvent(MprotectFixupEvent{
		Start: 0xf4000,
		End:   0xff000,
		Flags: 0x20,
	})
	sort.Sort(sort.Reverse(vmaList(mem.vmaList)))
	assert.Equal(t, 2, len(mem.vmaList))
	assert.Equal(t, uint64(0x20), mem.vmaList[1].Flags)
	assert.Equal(t, uint64(0xf4000), mem.vmaList[1].Start)
	assert.Equal(t, uint64(0xff000), mem.vmaList[1].End)

	mem.ApplyEvent(MprotectFixupEvent{
		Start: 0xf5000,
		End:   0xf6000,
		Flags: 0x10,
	})
	// 3-4 4-5 5-6 6-f
	sort.Sort(sort.Reverse(vmaList(mem.vmaList)))
	assert.Equal(t, 4, len(mem.vmaList))
	assert.Equal(t, uint64(0x10), mem.vmaList[2].Flags)
	assert.Equal(t, uint64(0xf5000), mem.vmaList[2].Start)
	assert.Equal(t, uint64(0xf6000), mem.vmaList[2].End)
}
