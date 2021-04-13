package enhance

import (
	"sync"
	"time"
)

// 由于协程执行的随机性，事件解析的顺序不一定符合事件实际发生的顺序，且bcc无法调用外部函数，
// 故标记开始事件，以其为基准，校对时间

var timeAmend *NsMap
var timeMutex sync.Mutex
var startChain = make(chan *NsMap)

type NsMap struct {
	kernelBootNs uint64
	grabTime     time.Time
}

func NewNsMap(kernelBootNs uint64) *NsMap {
	return &NsMap{kernelBootNs: kernelBootNs, grabTime: time.Now()}
}

// SendNs 发送开始事件信号
func SendNs(nsMap *NsMap) bool {
	if timeAmend != nil {
		return false
	}
	timeMutex.Lock()
	defer timeMutex.Unlock()
	if timeAmend == nil {
		timeAmend = &NsMap{
			kernelBootNs: nsMap.kernelBootNs,
			grabTime:     nsMap.grabTime,
		}
		close(startChain)
	} else {
		return false
	}
	return true
}

// WaitNs 等待开始信号
func WaitNs() {
	<-startChain
}

// AmendTime 纠正时间
func AmendTime(ts uint64) time.Time {
	WaitNs()
	afterNs := ts - timeAmend.kernelBootNs
	realTm := timeAmend.grabTime
	return realTm.Add(time.Duration(afterNs) * time.Nanosecond)
}
