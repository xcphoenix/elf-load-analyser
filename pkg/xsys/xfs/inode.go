package xfs

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

const findCmdPrefix = "find / -type f -xdev -inum "

var cache = map[uint64]string{}

// INodePath 传入 inode，获取文件路径名
func INodePath(inode uint64) string {
	if inode <= 0 {
		return ""
	}
	if path, ok := cache[inode]; !ok {
		// FIXME 效率太慢
		cmd := exec.Command("sh", "-c", findCmdPrefix+strconv.FormatUint(inode, 10), " 2>& /dev/null") //nolint:gosec
		var out bytes.Buffer
		var err bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &err

		_ = cmd.Run()
		path := strings.TrimSpace(out.String())
		cache[inode] = path
		return path
	} else {
		return path
	}
}
