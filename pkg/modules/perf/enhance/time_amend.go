package enhance

import (
	"sync"
	"time"
)

// 由于协程执行的随机性，事件解析的顺序不一定符合事件实际发生的顺序，且bcc无法调用外部函数，
// 故标记开始事件，以其为基准，校对时间

var timeAmend *nsMap
var timeMutex sync.Mutex
var startChain = make(chan *nsMap)

type nsMap struct {
	kernelBootNs uint64
	grabTime     time.Time
}

func newNsMap(kernelBootNs uint64, grabTime time.Time) *nsMap {
	if grabTime.IsZero() {
		grabTime = time.Now()
	}
	return &nsMap{kernelBootNs: kernelBootNs, grabTime: grabTime}
}

// sendNs 发送开始事件信号
func sendNs(nsMap *nsMap) bool {
	if timeAmend != nil {
		return false
	}
	timeMutex.Lock()
	defer timeMutex.Unlock()
	if timeAmend == nil {
		timeAmend = newNsMap(nsMap.kernelBootNs, nsMap.grabTime)
		close(startChain)
	} else {
		return false
	}
	return true
}

// waitNs 等待开始信号
func waitNs() {
	<-startChain
}

// amendTime 纠正时间
func amendTime(ts uint64) time.Time {
	waitNs()
	afterNs := ts - timeAmend.kernelBootNs
	realTm := timeAmend.grabTime
	return realTm.Add(time.Duration(afterNs) * time.Nanosecond)
}
