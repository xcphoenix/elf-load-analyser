package enhance

import (
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
	"sort"
	"strconv"
	"time"
)

const (
	StartMark       = "_START_"
	kernelBootNsKey = "_ns_"
)

// Ps: 只有手动使用了 TimeEventResult 才会执行这个 init
func init() {
	plugin.RegisterPlugin(&timeCorrectPlugin{}, 0x10)
}

// TimeEventResult EventResult with env boot ns, coordinate with enhance.timeCorrectPlugin
type TimeEventResult struct {
	TS uint64 `enhance:"_ns_"`
}

type nsMap struct {
	kernelBootNs uint64
	grabTime     time.Time
}

func newNsMap(kernelBootNs uint64, grabTime time.Time) *nsMap {
	return &nsMap{kernelBootNs: kernelBootNs, grabTime: grabTime}
}

func amendTime(ts uint64, timeAmend *nsMap) time.Time {
	// correct time
	afterNs := ts - timeAmend.kernelBootNs
	realTm := timeAmend.grabTime
	return realTm.Add(time.Duration(afterNs) * time.Nanosecond)
}

type timeCorrectPlugin struct{}

func (t timeCorrectPlugin) Handle(dataCollection []*data.AnalyseData) ([]*data.AnalyseData, []plugin.ReqHandler) {
	var timeAmend *nsMap
	var startIdx = -1

	for i, aData := range dataCollection {
		if exist, ns, err := parseDataNsKey(aData, kernelBootNsKey); exist {
			if err != nil {
				log.Warn(err)
				break
			}
			if _, ok := aData.ExtraByKey(StartMark); ok {
				startIdx = i
				timeAmend = newNsMap(ns, time.Time(aData.XTime))
				break
			}
		}
	}

	if startIdx < 0 {
		log.Warnf("Time correct mark not found, ignore!")
		return dataCollection, nil
	}

	for i, aData := range dataCollection {
		if i == startIdx {
			continue
		}
		if exist, ns, err := parseDataNsKey(aData, kernelBootNsKey); exist {
			if err != nil {
				log.Warn(err)
				continue
			}
			aData.XTime = data.JSONTime(amendTime(ns, timeAmend))
		}
	}

	sort.Slice(dataCollection, func(i, j int) bool {
		return time.Time(dataCollection[i].XTime).Before(time.Time(dataCollection[j].XTime))
	})
	return dataCollection, nil
}

func parseDataNsKey(d *data.AnalyseData, nsKey string) (bool, uint64, error) {
	v, ok := d.ExtraByKey(nsKey)
	if !ok {
		return false, 0, nil
	}

	d.RmExtra(nsKey)

	if v, ok := v.(string); ok {
		ns, e := strconv.ParseUint(v, 10, 64)
		if e != nil {
			return true, 0, fmt.Errorf("convert ns data to int error, %w", e)
		}
		return true, ns, nil
	}

	return true, 0, fmt.Errorf("ns data is not string type")
}
