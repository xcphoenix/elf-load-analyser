package xfs

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

const findCmdPrefix = "find / -type f -xdev -inum "

var cache sync.Map

// INodePath 传入 inode，获取文件路径名
func INodePath(inode uint64) string {
	if inode <= 0 {
		return ""
	}
	path, _ := cache.LoadOrStore(inode, func() string {
		cmd := exec.Command("sh", "-c", findCmdPrefix+strconv.FormatUint(inode, 10), " 2>& /dev/null") //nolint:gosec
		var out bytes.Buffer
		var err bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &err

		_ = cmd.Run()
		return strings.TrimSpace(out.String())
	}())
	return path.(string)
}
