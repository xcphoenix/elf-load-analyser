package xfs

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

const findCmdPrefix = "find / -type f -xdev -inum "

// FindPath 传入 inode，获取文件路径名
func FindPath(inode uint64) (string, error) {
	if inode <= 0 {
		return "", nil
	}
	// FIXME 效率太慢
	cmd := exec.Command("sh", "-c", findCmdPrefix+strconv.FormatUint(inode, 10), " 2>& /dev/null") //nolint:gosec
	var out bytes.Buffer
	var err bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &err

	e := cmd.Run()
	return strings.TrimSpace(out.String()), e
}
