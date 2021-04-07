package log

import (
	"bytes"
	"strings"
)

const clear = "\033[0m"

// Em warp string with bolder in terminal
func Em(message string) string {
	return wrap("\033[1m", message)
}

func italic(message string) string {
	return wrap("\033[3m", message)
}

func warn(message string) string {
	return wrap("\033[1;33m", message)
}

func minor(message string) string {
	return wrap("\033[0;37m", message)
}

func success(message string) string {
	return wrap("\033[1;32m", message)
}

func err(message string) string {
	return wrap("\033[1;31m", message)
}

func wrap(before string, message string) string {
	var buff bytes.Buffer
	buff.Grow(len(message) + len(before) + len(clear))
	// TODO 如果 message 存在 clear，那么从最后一个位置后开始添加
	startIdx := strings.LastIndex(message, clear)
	if startIdx >= 0 {
		idx := startIdx + len(clear)
		buff.WriteString(message[:idx])
		message = message[idx:]
	}

	buff.WriteString(before)
	buff.WriteString(message)
	buff.WriteString(clear)
	return buff.String()
}
