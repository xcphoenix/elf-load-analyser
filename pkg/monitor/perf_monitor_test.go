package monitor

import (
	"github.com/stretchr/testify/assert"
	"log"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

//nolint:funlen
func TestLogical(t *testing.T) {
	var senderNum = 50
	var sendRecordCnt = senderNum
	var senders = make([]chan int, senderNum)
	for i := range senders {
		senders[i] = make(chan int)
	}

	var ready = make(chan interface{})
	var finish = make(chan interface{})
	var finishAndNoData = make(chan interface{})
	var end = make(chan struct{})

	var cases = make([]reflect.SelectCase, len(senders))
	for i, sender := range senders {
		cases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(sender),
		}
	}
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectSend,
		Chan: reflect.ValueOf(ready),
		Send: reflect.ValueOf("Ready!"),
	})
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(finish),
	})

	var random = rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec

	var msg string
	go func() {
		var data = <-ready
		msg = data.(string)
	}()

	// 模拟发送数据
	go func() {
		// 模拟模块就绪的时间
		time.Sleep(time.Duration(random.Intn(100)+100) * time.Microsecond)

		for i, sender := range senders {
			// 模拟 finish 事件提前被处理
			if i == len(senders)/2 && time.Now().Nanosecond()%2 == 0 {
				log.Println("finish event")
				close(finish)
			}

			var sender, i = sender, i
			go func() {
				sender <- i
				log.Println("sender send data", i)
			}()
		}
	}()

	// 模拟接收数据
	go func() {
	LOOP:
		for {
			// 索引，如果是 Receive，对应接收到的值以及是否匹配，若 chan 关闭，那么 ok 为 false
			var chosen, value, ok = reflect.Select(cases)

			switch chosen {
			// 对应 ready
			case senderNum:
				log.Println("--- received ready event")
			// 对应 finish
			case senderNum + 1:
				log.Println("--- received finish event")

				// assert.False(t, value.IsValid())
				assert.False(t, ok)

				// 应当保证当前再没有要被接收的数据了
				// 设置为空，防止持续触发
				cases[chosen].Chan = reflect.ValueOf(nil)
				cases = append(cases, reflect.SelectCase{
					Dir:  reflect.SelectRecv,
					Chan: reflect.ValueOf(finishAndNoData),
				})
				// 添加 default，当无其他事件时会被触发
				cases = append(cases, reflect.SelectCase{
					Dir: reflect.SelectDefault,
				})
			// 对应无未处理事件
			case senderNum + 2:
				log.Println("--- received end event, end!!!")
				break LOOP
			//	对应已收到 finish 信号，且没有未处理的数据
			case senderNum + 3:
				log.Println("--- no other data, start end!")
				close(finishAndNoData)
			// 对应发送
			default:
				log.Printf("--- received data: %v\n", value)

				assert.True(t, value.IsValid(), "received data is invalid")
				assert.True(t, ok, "received chan is closed")

				// 模拟延时操作
				time.Sleep(500 * time.Microsecond)
				// 删除元素，表示已被消费
				sendRecordCnt--

				// 元素都处理完毕，直接退出
				if sendRecordCnt == 0 {
					break LOOP
				}
			}
		}
		close(end)
	}()

	<-end
	assert.NotEqual(t, "", msg, "cannot receive msg from ready")

	assert.Equal(t, 0, sendRecordCnt, "there are some data be ignored")
}
