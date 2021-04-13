package enhance

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"strconv"
)

const (
	StartMark        = "_START_"
	kernelBootNsKey  = "_ns_"
	timeEnhancerName = "TimeAmend"
)

func init() {
	modules.RegisteredEnhancer(timeEnhancerName, &timeEnhancer{})
}

type TimeEvent interface {
	Ns() uint64
}

// TimeEventResult EventResult with env boot ns, coordinate with enhance.timeEnhancer
type TimeEventResult struct {
	TS uint64 `enhance:"_ns_"`
}

func (t *TimeEventResult) Ns() uint64 {
	return t.TS
}

// timeEnhancer 时间修正处理器
type timeEnhancer struct{}

func (t timeEnhancer) PreHandle(tCtx *modules.TableCtx) {
	if !tCtx.IsMark(StartMark) {
		WaitNs()
	}
}

func (t timeEnhancer) AfterHandle(tCtx *modules.TableCtx,
	aData *data.AnalyseData, err error) (*data.AnalyseData, error) {
	if err != nil {
		return aData, err
	}

	if v, ok := aData.ExtraByKey(kernelBootNsKey); ok {
		ns, e := strconv.ParseUint(v.(string), 10, 64)
		if e != nil {
			log.Warnf("%s ==> can not convert %q data, %v", timeEnhancerName, kernelBootNsKey, e)
			return aData, err
		}
		var sendOk bool
		if tCtx.IsMark(StartMark) {
			log.Debugf("%s ==> %s notify other coordinate", timeEnhancerName, tCtx.Name)
			sendOk = SendNs(NewNsMap(ns))
		}
		// NOTE: 如果标记为开始事件的 table 被多次触发，可能会造成乱序
		if !tCtx.IsMark(StartMark) || !sendOk {
			log.Debugf("%s ==> %s amend timestamp", timeEnhancerName, tCtx.Name)
			aData.XTime = data.JSONTime(AmendTime(ns))
		}
		aData.RmExtra(kernelBootNsKey)
	}
	return aData, err
}
