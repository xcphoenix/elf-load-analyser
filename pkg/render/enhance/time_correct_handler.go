package enhance

import (
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
	"sort"
	"time"
)

const kernelBootNsKey = "_ns_"

func init() {
	plugin.RegisterPlugin(&timeCorrectPlugin{}, 0x10)
}

// TimeEventResult 包含内核启动时间以修正相对时间
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
	if ts <= timeAmend.kernelBootNs {
		log.Warnf("time that need be amend before start time")
		ts = timeAmend.kernelBootNs + 1
	}

	afterNs := ts - timeAmend.kernelBootNs
	baseTime := timeAmend.grabTime
	return baseTime.Add(time.Duration(afterNs) * time.Nanosecond)
}

type timeCorrectPlugin struct{}

func (t timeCorrectPlugin) Handle(dataCollection []*data.AnalyseData) ([]*data.AnalyseData, []plugin.ReqHandler) {
	type NsDataPair struct {
		nsData *data.AnalyseData
		ns     uint64
	}

	var timeAmend *nsMap
	var noNsDataList []*data.AnalyseData
	var withNsDataList []NsDataPair

	// split
	for i := range dataCollection {
		var ns uint64
		v, ok := dataCollection[i].ExtraByKey(kernelBootNsKey)
		if ok {
			ns, ok = v.(uint64)
		}
		if ok && ns != 0 {
			withNsDataList = append(withNsDataList, NsDataPair{dataCollection[i], ns})
		} else {
			noNsDataList = append(noNsDataList, dataCollection[i])
		}
	}

	dataCollection = noNsDataList

	if len(withNsDataList) > 0 {
		// sort
		sort.Slice(withNsDataList, func(i, j int) bool {
			return withNsDataList[i].ns < withNsDataList[j].ns
		})

		// amend
		for i := range withNsDataList {
			aData, ns := withNsDataList[i].nsData, withNsDataList[i].ns
			dataCollection = append(dataCollection, aData)
			if i == 0 {
				timeAmend = newNsMap(ns, time.Time(aData.XTime))
				continue
			}
			aData.XTime = data.JSONTime(amendTime(ns, timeAmend))
		}
	}

	// sort
	sort.Slice(dataCollection, func(i, j int) bool {
		return time.Time(dataCollection[i].XTime).Before(time.Time(dataCollection[j].XTime))
	})
	return dataCollection, nil
}
