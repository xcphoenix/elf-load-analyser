package xfs

import (
	"fmt"
	"testing"
)

func TestFindPath(t *testing.T) {
	path := INodePath(3015077)
	fmt.Println(path)
}
