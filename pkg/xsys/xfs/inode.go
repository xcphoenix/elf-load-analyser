package xfs

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// FileINode 获取文件 Inode，如果文件不存在等返回错误
func FileINode(f string) (uint64, error) {
	fileInfo, err := os.Stat(f)
	if err != nil {
		return 0, err
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("not a syscall.Stat_t")
	}

	cache.Store(f, stat.Ino)
	return stat.Ino, nil
}
