package data

// Pool 数据池
type Pool struct {
	ch       chan *AnalyseData
	finish   chan struct{} // 数据收集完成
	ready    chan struct{} // 数据开始收集
	dataList []*AnalyseData
}

// NewDataPool 创建数据池
func NewDataPool() *Pool {
	return &Pool{
		ch:       make(chan *AnalyseData),
		finish:   make(chan struct{}),
		dataList: make([]*AnalyseData, 0),
		ready:    make(chan struct{}),
	}
}

// Chan 获取数据池发送的通道
func (p *Pool) Chan() chan<- *AnalyseData {
	return p.ch
}

// WaitReady 阻塞等待操作就绪
func (p *Pool) WaitReady() {
	<-p.ready
}

// Data 获取池中的数据，若数据未收集完成，阻塞操作
func (p *Pool) Data() []*AnalyseData {
	<-p.finish
	return p.dataList
}

// InitPool 初始化数据池
//  done: 被关闭时，停止接收数据
//  waitCnt: 表示数据接收前要等待的次数
func (p *Pool) InitPool(done <-chan struct{}, waitCnt int) {
	go func() {
		for {
			select {
			case d, ok := <-p.ch:
				// 若已停止接受数据，退出
				if !ok {
					return
				}

				// 如果还未等待完成，丢弃数据，计数器减一
				if waitCnt > 0 {
					waitCnt--
					if waitCnt == 0 {
						// 开始接收数据
						close(p.ready)
					}
					continue
				}

				// 接收数据
				p.dataList = append(p.dataList, d)
			case <-done:
				// 停止接收数据
				close(p.ch)
				// 数据接收完毕
				close(p.finish)
				return
			}
		}
	}()
}
