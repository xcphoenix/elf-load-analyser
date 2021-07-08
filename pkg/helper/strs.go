package helper

import (
	"bytes"
	"unsafe"
)

// Bytes2Str 字节数组转字符串
func Bytes2Str(arr []byte) string {
	return *(*string)(unsafe.Pointer(&arr))
}

// TrimBytes2Str 去除空字符后转字符串
func TrimBytes2Str(arr []byte) string {
	l := bytes.IndexByte(arr, 0)
	arr = arr[:l]
	return *(*string)(unsafe.Pointer(&arr))
}
